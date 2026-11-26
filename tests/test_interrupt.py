"""Interruption tests: Ctrl+C (SIGINT), SIGTERM/SIGHUP and failures in the middle of a write.

Put this file in tests/ and run from the project root:

    pytest tests/test_interrupt.py -v

Every test uses a temporary HOME, so the real ~/.sfm is never touched.
"""

import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sfm import auth, cli, storage, vault

SRC = Path(__file__).resolve().parents[1] / "src"

pytestmark = pytest.mark.skipif(
    not hasattr(signal, "SIGHUP"), reason="POSIX signals only"
)


# ------------------------------------------------------------------ fixtures
@pytest.fixture(autouse=True)
def restore_signal_handlers():
    """cli.main() installs SIGTERM/SIGHUP handlers: undo that after each test."""
    saved = {s: signal.getsignal(s)
             for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    yield
    for sig, handler in saved.items():
        if handler is not None:
            signal.signal(sig, handler)


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Temporary HOME and a cheap Argon2id (the tests are about interruptions, not KDF cost)."""
    home = tmp_path / "home"
    work = tmp_path / "work"
    home.mkdir()
    work.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(auth, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(auth, "ARGON2_MEMORY_COST", 1024)
    monkeypatch.setattr(auth, "ARGON2_PARALLELISM", 1)
    return SimpleNamespace(root=tmp_path, home=home, work=work)


PASSWORD = "alice-password-1"


@pytest.fixture
def alice(env):
    auth.register("alice", PASSWORD)
    return "alice", auth.login("alice", PASSWORD)


# ------------------------------------------------------------------- helpers
def make_file(env, name="a.txt", data=b"some secret content"):
    path = env.work / name
    path.write_bytes(data)
    return path


def tmp_leftovers(env):
    """Any temporary file left anywhere (index.tmp or .sfm-*.tmp)."""
    return sorted(str(p) for p in env.root.rglob("*") if p.name.endswith(".tmp"))


def blobs(user):
    return sorted(p.name for p in storage.get_blobs_dir(user).iterdir())


def raise_interrupt():
    raise KeyboardInterrupt


def send_signal(signum):
    """Deliver a REAL signal to this process; the Python handler fires inside sleep()."""
    def action():
        os.kill(os.getpid(), signum)
        time.sleep(5)
        raise AssertionError("signal was not delivered")
    return action


class Trap:
    """Fire `action` once, on the nth matching call of os.<func>; later calls pass through."""

    def __init__(self, monkeypatch, func, action, when=None, nth=1):
        real = getattr(os, func)
        self.count = 0

        def wrapper(*args, **kwargs):
            if when is None or when(*args):
                self.count += 1
                if self.count == nth:
                    action()
            return real(*args, **kwargs)

        monkeypatch.setattr(os, func, wrapper)


def is_index(*args):
    return str(args[1]).endswith("index.enc")     # os.replace(src, dst)


# --------------------------------------------------- index (storage.py)
def test_interrupt_before_index_replace_keeps_old_index(env, alice, monkeypatch):
    user, kek = alice
    vault.encrypt_file(user, kek, str(make_file(env)))
    before = storage.get_index_path(user).read_bytes()

    Trap(monkeypatch, "replace", raise_interrupt, when=is_index)
    with pytest.raises(KeyboardInterrupt):
        storage.write_index_blob(user, b"new content")

    assert storage.get_index_path(user).read_bytes() == before   # old index intact
    assert tmp_leftovers(env) == []                              # no index.tmp left
    assert vault.list_files(user, kek) == [(1, "a.txt")]         # vault still opens


def test_stale_tmp_from_a_killed_run_is_harmless(env, alice):
    """kill -9 cannot be caught: it can only leave an index.tmp, which must not matter."""
    user, kek = alice
    tmp = storage.get_index_path(user).with_suffix(".tmp")
    os.close(os.open(tmp, os.O_WRONLY | os.O_CREAT, 0o600))
    tmp.write_bytes(b"junk from a killed run")

    assert vault.encrypt_file(user, kek, str(make_file(env))) == 1
    assert vault.list_files(user, kek) == [(1, "a.txt")]
    assert not tmp.exists()


# ------------------------------------------------- encrypt (vault.py)
def test_interrupt_while_writing_blob_removes_it(env, alice, monkeypatch):
    user, kek = alice
    src = make_file(env)
    Trap(monkeypatch, "fsync", raise_interrupt)               # first fsync = blob write

    with pytest.raises(KeyboardInterrupt):
        vault.encrypt_file(user, kek, str(src))

    assert blobs(user) == []                                  # partial blob removed
    assert vault.list_files(user, kek) == []                  # nothing was committed
    assert vault.encrypt_file(user, kek, str(src)) == 1       # and the vault still works


# ------------------------------------------------- decrypt (vault.py)
def test_interrupt_while_decrypting_leaves_no_partial_output(env, alice, monkeypatch):
    user, kek = alice
    fid = vault.encrypt_file(user, kek, str(make_file(env)))
    dest = env.work / "out.txt"
    Trap(monkeypatch, "fsync", raise_interrupt)

    with pytest.raises(KeyboardInterrupt):
        vault.decrypt_file(user, kek, fid, str(dest))

    assert not dest.exists()                                  # no truncated plaintext
    assert tmp_leftovers(env) == []


def test_interrupt_during_forced_decrypt_keeps_the_original(env, alice, monkeypatch):
    user, kek = alice
    fid = vault.encrypt_file(user, kek, str(make_file(env)))
    dest = env.work / "out.txt"
    dest.write_bytes(b"original")
    Trap(monkeypatch, "replace", raise_interrupt,
         when=lambda s, d, *a: str(d).endswith("out.txt"))

    with pytest.raises(KeyboardInterrupt):
        vault.decrypt_file(user, kek, fid, str(dest), force=True)

    assert dest.read_bytes() == b"original"                   # not truncated
    assert tmp_leftovers(env) == []
    assert not [p for p in env.work.iterdir() if p.name.startswith(".sfm-")]


# -------------------------------------------------- delete (vault.py)
def test_interrupt_before_delete_commit_keeps_the_file(env, alice, monkeypatch):
    user, kek = alice
    fid = vault.encrypt_file(user, kek, str(make_file(env, data=b"keep me")))
    Trap(monkeypatch, "fsync", raise_interrupt, nth=1)        # while writing the new index

    with pytest.raises(KeyboardInterrupt):
        vault.delete_file(user, kek, fid)

    assert vault.list_files(user, kek) == [(1, "a.txt")]      # still there
    out = env.work / "out.txt"
    vault.decrypt_file(user, kek, fid, str(out))
    assert out.read_bytes() == b"keep me"                     # and still readable
    assert tmp_leftovers(env) == []


def test_interrupt_during_overwrite_leaves_file_already_unreadable(env, alice, monkeypatch):
    user, kek = alice
    fid = vault.encrypt_file(user, kek, str(make_file(env)))
    Trap(monkeypatch, "fsync", raise_interrupt, nth=2)        # 1st = index, 2nd = overwrite

    with pytest.raises(KeyboardInterrupt):
        vault.delete_file(user, kek, fid)

    assert vault.list_files(user, kek) == []                  # key already destroyed
    with pytest.raises(vault.VaultError):
        vault.decrypt_file(user, kek, fid, str(env.work / "out.txt"))
    assert tmp_leftovers(env) == []                           # (an unreadable blob may remain)


# ------------------------------------------------ real signals via cli.main
@pytest.fixture
def cli_encrypt(env, alice, monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": PASSWORD)
    src = make_file(env)
    return lambda: cli.main(["--user", "alice", "encrypt", str(src)])


def test_cli_sigint_during_encrypt_exits_130(env, alice, cli_encrypt, monkeypatch, capsys):
    user, kek = alice
    Trap(monkeypatch, "replace", send_signal(signal.SIGINT), when=is_index)

    try:
        code = cli_encrypt()
    except KeyboardInterrupt:      # without this, pytest itself would abort
        pytest.fail("cli.main() let KeyboardInterrupt escape")
    assert code == 130

    captured = capsys.readouterr()
    assert "Aborted" in captured.err
    assert "Traceback" not in captured.err
    assert tmp_leftovers(env) == []
    assert vault.list_files(user, kek) == []                  # nothing committed
    # Known limit: the interrupt hit after the blob was written, so one unreferenced,
    # encrypted blob may remain. It is unreadable without a record: harmless.
    assert len(blobs(user)) <= 1


def test_cli_sigterm_during_encrypt_exits_143_and_cleans_up(env, alice, cli_encrypt, monkeypatch):
    user, kek = alice
    Trap(monkeypatch, "replace", send_signal(signal.SIGTERM), when=is_index)

    def sentinel(signum, frame):   # without this, a missing handler would kill pytest itself
        pytest.fail("cli.main() did not install a SIGTERM handler")
    signal.signal(signal.SIGTERM, sentinel)    # cli.main() must replace it with its own

    with pytest.raises(SystemExit) as exc:
        cli_encrypt()

    assert exc.value.code == 128 + signal.SIGTERM
    assert tmp_leftovers(env) == []
    assert vault.list_files(user, kek) == []


# ------------------------------------------- a real process, a real signal
def wait_for(stream, needle: bytes, timeout=10.0) -> bytes:
    buf, end = b"", time.time() + timeout
    while needle not in buf and time.time() < end:
        ready, _, _ = select.select([stream], [], [], 0.2)
        if ready:
            chunk = os.read(stream.fileno(), 1024)
            if not chunk:
                break
            buf += chunk
    return buf


@pytest.mark.parametrize("sig, code", [
    (signal.SIGINT, 130),     # Ctrl+C
    (signal.SIGTERM, 143),    # kill
    (signal.SIGHUP, 129),     # terminal closed
])
def test_real_process_stops_cleanly_at_password_prompt(env, sig, code):
    child_env = dict(os.environ, HOME=str(env.home), PYTHONPATH=str(SRC))
    proc = subprocess.Popen(
        [sys.executable, "-m", "sfm", "--user", "alice", "list"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=child_env,
        start_new_session=True,     # no controlling terminal: getpass reads stdin, not your keyboard
    )
    try:
        seen = wait_for(proc.stderr, b"Password")
        assert b"Password" in seen, "the prompt never appeared"
        proc.send_signal(sig)
        _, err = proc.communicate(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()

    assert proc.returncode == code
    assert b"Traceback" not in seen + err
