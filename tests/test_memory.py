"""Memory-handling tests: wiping, no-echo password input, process hardening.

Run from the project root:  pytest tests/test_memory.py -v
"""

import os
import pty
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sfm import auth, cli, secmem, validation, vault

SRC = Path(__file__).resolve().parents[1] / "src"
PASSWORD = "S3cret-Pass-123"


# ------------------------------------------------------------------ wipe
def test_wipe_zeroes_in_place():
    buf = bytearray(b"super-secret-key")
    same = buf
    secmem.wipe(buf)
    assert same is buf and buf == bytearray(16)


def test_wipe_ignores_other_types_and_empty():
    secmem.wipe(b"immutable")
    secmem.wipe("text")
    secmem.wipe(None)
    secmem.wipe(bytearray())


def test_wiped_buffer_can_still_be_resized():
    buf = bytearray(b"abc")
    secmem.wipe(buf)
    buf += b"d"                                  # fails if a ctypes export were left open
    assert buf == bytearray(b"\x00\x00\x00d")


def test_secret_context_wipes_even_on_error():
    buf = bytearray(b"key")
    with pytest.raises(RuntimeError):
        with secmem.secret(buf):
            raise RuntimeError
    assert buf == bytearray(3)


# ------------------------------------------------------------------ validation of bytearray passwords
def test_validate_password_accepts_bytearray_and_counts_characters():
    pw = bytearray("pässwörd1".encode())          # 9 characters, 11 bytes
    assert validation.validate_password(pw, check_strength=True) is pw
    with pytest.raises(validation.ValidationError):
        validation.validate_password(bytearray("ääää".encode()), check_strength=True)  # 4 chars, 8 bytes


@pytest.mark.parametrize("bad", [bytearray(), b"", "", None, 123, bytearray(b"a" * 600)])
def test_validate_password_rejects_bad_input(bad):
    with pytest.raises(validation.ValidationError):
        validation.validate_password(bad)


# ------------------------------------------------------------------ session wipes password and key
@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    work = tmp_path / "work"
    home.mkdir()
    work.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(auth, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(auth, "ARGON2_MEMORY_COST", 1024)
    monkeypatch.setattr(auth, "ARGON2_PARALLELISM", 1)
    return SimpleNamespace(home=home, work=work)


def _capture_buffers(monkeypatch):
    """Record every password buffer handed out and every key returned by login."""
    seen = SimpleNamespace(passwords=[], keks=[])
    real_read, real_login = secmem.read_password, auth.login

    def read(prompt="Password: "):
        buf = real_read(prompt)
        seen.passwords.append(buf)
        return buf

    def login(user, password):
        kek = real_login(user, password)
        seen.keks.append(kek)
        return kek

    monkeypatch.setattr(secmem, "read_password", read)
    monkeypatch.setattr(auth, "login", login)
    return seen


def test_password_and_kek_are_wiped_after_a_command(env, monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": PASSWORD)
    assert cli.main(["register", "alice"]) == 0
    seen = _capture_buffers(monkeypatch)
    assert cli.main(["--user", "alice", "list"]) == 0
    assert seen.passwords and seen.keks
    for buf in seen.passwords:
        assert buf == bytearray(len(buf))
    for kek in seen.keks:
        assert isinstance(kek, bytearray) and kek == bytearray(len(kek))


def test_registration_passwords_are_wiped_even_when_they_do_not_match(env, monkeypatch):
    answers = iter([PASSWORD, "different-pass-9"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    seen = _capture_buffers(monkeypatch)
    assert cli.main(["register", "alice"]) == 1
    assert len(seen.passwords) == 2
    for buf in seen.passwords:
        assert buf == bytearray(len(buf))


def test_kek_is_wiped_when_a_command_fails(env, monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": PASSWORD)
    cli.main(["register", "alice"])
    seen = _capture_buffers(monkeypatch)
    assert cli.main(["--user", "alice", "delete", "42"]) == 1       # file not found
    assert seen.keks and all(k == bytearray(len(k)) for k in seen.keks)


def test_kek_is_wiped_on_interrupt(env, monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": PASSWORD)
    cli.main(["register", "alice"])
    seen = _capture_buffers(monkeypatch)

    def interrupted(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(vault, "list_files", interrupted)
    assert cli.main(["--user", "alice", "list"]) == 130
    assert seen.keks and all(k == bytearray(len(k)) for k in seen.keks)


def test_file_plaintext_and_dek_are_wiped_after_encrypt(env, monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": PASSWORD)
    cli.main(["register", "alice"])
    kek = auth.login("alice", PASSWORD)
    src = env.work / "f.txt"
    src.write_bytes(b"PLAINTEXT-1234567890")

    plains, deks = [], []
    real_read, real_gen = vault._read_source, vault.crypto.generate_key

    def read(path):
        buf = real_read(path)
        plains.append(buf)
        return buf

    def gen():
        k = real_gen()
        return k
    monkeypatch.setattr(vault, "_read_source", read)
    real_enc = vault.crypto.encrypt_bytes

    def enc(key, data, aad=b""):
        if len(key) == 32 and isinstance(key, bytearray):
            deks.append(key)
        return real_enc(key, data, aad)
    monkeypatch.setattr(vault.crypto, "encrypt_bytes", enc)

    vault.encrypt_file("alice", kek, str(src))
    assert plains and all(b == bytearray(len(b)) for b in plains)
    assert deks and all(d == bytearray(len(d)) for d in deks if d is not kek)


def test_read_source_returns_exact_bytes_and_handles_empty(env):
    f = env.work / "a.bin"
    data = os.urandom(100_000)
    f.write_bytes(data)
    assert vault._read_source(f) == bytearray(data)
    e = env.work / "empty"
    e.write_bytes(b"")
    assert vault._read_source(e) == bytearray()


def test_roundtrip_still_works_with_wipeable_keys(env, monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": PASSWORD)
    cli.main(["register", "alice"])
    src = env.work / "f.txt"
    src.write_bytes(b"hello world")
    assert cli.main(["--user", "alice", "encrypt", str(src)]) == 0
    out = env.work / "out.txt"
    assert cli.main(["--user", "alice", "decrypt", "1", "-o", str(out)]) == 0
    assert out.read_bytes() == b"hello world"


# ------------------------------------------------------------------ process hardening
def test_harden_process_disables_core_dumps_and_dumpable():
    code = (
        "import resource, ctypes\n"
        "from sfm import secmem\n"
        "secmem.harden_process()\n"
        "print(resource.getrlimit(resource.RLIMIT_CORE))\n"
        "print(ctypes.CDLL(None).prctl(3, 0, 0, 0, 0))\n"      # PR_GET_DUMPABLE
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env={**os.environ, "PYTHONPATH": str(SRC)}, timeout=30)
    lines = out.stdout.split()
    assert out.returncode == 0, out.stderr
    assert "(0, 0)" in out.stdout.replace("  ", " ")
    assert lines[-1] == "0"


# ------------------------------------------------------------------ real terminal (pty) input
def _run_reader(keys: bytes, tmp_path):
    """Run secmem.read_password on a pseudo-terminal; return (password bytes, terminal output)."""
    result = tmp_path / "result.txt"
    code = (
        "import sys\n"
        "from sfm import secmem\n"
        f"pw = secmem.read_password('Pass: ')\n"
        f"open({str(result)!r}, 'w').write(repr(bytes(pw)))\n"
    )
    master, slave = pty.openpty()
    proc = subprocess.Popen([sys.executable, "-c", code], stdin=slave, stdout=slave,
                            stderr=slave, env={**os.environ, "PYTHONPATH": str(SRC)},
                            close_fds=True)
    os.close(slave)
    time.sleep(0.6)                                 # let the child reach the prompt
    os.write(master, keys)
    out = b""
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            chunk = os.read(master, 1024)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
        if proc.poll() is not None:
            break
    proc.wait(timeout=10)
    os.close(master)
    return (result.read_text() if result.exists() else None), out


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pty test is Linux only")
def test_terminal_password_is_not_echoed(tmp_path):
    got, out = _run_reader(b"hunter2-hunter2\n", tmp_path)
    assert got == repr(b"hunter2-hunter2")
    assert b"hunter2" not in out
    assert b"Pass:" in out


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pty test is Linux only")
def test_terminal_backspace_and_utf8(tmp_path):
    got, _ = _run_reader("abcX\x7fdé\x7fe\n".encode(), tmp_path)   # abcX<BS>dé<BS>e
    assert got == repr(b"abcde")                                        # é removed as one character


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pty test is Linux only")
def test_terminal_ctrl_u_clears_the_line(tmp_path):
    got, _ = _run_reader(b"wrong\x15right-one\n", tmp_path)
    assert got == repr(b"right-one")
