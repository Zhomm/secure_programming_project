"""Structured logging tests: format, permissions, no secrets, never breaks a command.

Run from the project root:  pytest tests/test_logging.py -v
"""

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from sfm import auth, cli, log, storage

PASSWORD = "S3cret-Pass-123"
FILENAME = "my-private-tax-return.txt"
CONTENT = b"TOP-SECRET-CONTENT-12345"


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
    monkeypatch.setattr("getpass.getpass", lambda prompt="": PASSWORD)
    return SimpleNamespace(home=home, work=work, log=home / ".sfm" / "sfm.log")


def run(*argv):
    return cli.main(list(argv))


def events(env):
    return [json.loads(line) for line in env.log.read_text().splitlines()]


def names(env):
    return [e["event"] for e in events(env)]


def test_log_file_is_private_and_json_lines(env):
    assert run("register", "alice") == 0
    mode = stat.S_IMODE(env.log.stat().st_mode)
    assert mode == 0o600
    assert stat.S_IMODE(env.log.parent.stat().st_mode) == 0o700
    for e in events(env):
        assert {"ts", "level", "event", "pid"} <= e.keys()


def test_full_flow_is_logged_with_ids_only(env):
    src = env.work / FILENAME
    src.write_bytes(CONTENT)
    assert run("register", "alice") == 0
    assert run("--user", "alice", "encrypt", str(src)) == 0
    assert run("--user", "alice", "list") == 0
    assert run("--user", "alice", "decrypt", "1", "-o", str(env.work / "out.txt")) == 0
    assert run("--user", "alice", "delete", "1") == 0
    n = names(env)
    for expected in ("register_ok", "login_ok", "encrypt_ok", "list_ok",
                     "decrypt_ok", "delete_ok"):
        assert expected in n
    enc = next(e for e in events(env) if e["event"] == "encrypt_ok")
    assert enc["file_id"] == 1 and enc["size"] == len(CONTENT) and enc["user"] == "alice"


def test_log_never_contains_secrets(env):
    src = env.work / FILENAME
    src.write_bytes(CONTENT)
    run("register", "alice")
    run("--user", "alice", "encrypt", str(src))
    run("--user", "alice", "decrypt", "1", "-o", str(env.work / "restored-name.txt"))
    run("--user", "alice", "decrypt", "99", "-o", str(env.work / "x.txt"))
    run("--user", "alice", "encrypt", str(env.work / "missing-file-name.txt"))
    text = env.log.read_text()
    for secret in (PASSWORD, FILENAME, CONTENT.decode(), "restored-name",
                   "missing-file-name", str(env.work), str(env.home)):
        assert secret not in text, f"leaked: {secret}"


def test_failed_login_logged_without_password(env, monkeypatch):
    run("register", "alice")
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "wrong-password-9")
    assert run("--user", "alice", "list") == 1
    assert run("--user", "ghost", "list") == 1
    text = env.log.read_text()
    assert "wrong-password-9" not in text
    reasons = [e.get("reason") for e in events(env) if e["event"] == "login_failed"]
    assert reasons == ["bad_password", "unknown_user"]


def test_user_facing_error_stays_generic(env, monkeypatch, capsys):
    run("register", "alice")
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "wrong-password-9")
    run("--user", "alice", "list")
    err = capsys.readouterr().err
    assert err.strip() == "Error: invalid username or password"
    assert "unknown_user" not in err and "bad_password" not in err


def test_command_failed_event(env):
    run("register", "alice")
    assert run("--user", "alice", "delete", "42") == 1
    e = [x for x in events(env) if x["event"] == "command_failed"][-1]
    assert e["command"] == "delete" and e["error"] == "VaultError"


def test_ctrl_c_and_sigterm_are_logged(env, monkeypatch):
    def interrupted(prompt=""):
        raise KeyboardInterrupt
    monkeypatch.setattr("getpass.getpass", interrupted)
    assert run("--user", "alice", "list") == 130
    assert "aborted" in names(env)

    def terminated(prompt=""):
        raise SystemExit(143)
    monkeypatch.setattr("getpass.getpass", terminated)
    with pytest.raises(SystemExit):
        run("--user", "alice", "list")
    e = [x for x in events(env) if x["event"] == "terminated"][-1]
    assert e["code"] == 143


def test_internal_error_logs_type_only(env, monkeypatch):
    def boom(args):
        raise RuntimeError("path /home/x/secret.txt password hunter2")
    monkeypatch.setattr(cli, "cmd_list", boom)
    parser_func = cli.build_parser
    monkeypatch.setattr(cli, "build_parser", lambda: _with_list(parser_func(), boom))
    assert run("--user", "alice", "list") == 2
    text = env.log.read_text()
    assert "RuntimeError" in text
    assert "hunter2" not in text and "secret.txt" not in text


def _with_list(parser, func):
    parser.set_defaults()
    for action in parser._actions:
        if hasattr(action, "choices") and action.choices and "list" in action.choices:
            action.choices["list"].set_defaults(func=func)
    return parser


def test_unknown_fields_are_dropped(env):
    log.event("probe", password="hunter2", key=b"\x00", path="/etc/passwd", file_id=7)
    e = events(env)[-1]
    assert e["file_id"] == 7
    assert "password" not in e and "key" not in e and "path" not in e
    assert "hunter2" not in env.log.read_text()


def test_values_cannot_forge_log_lines(env):
    log.event("probe", reason='x"}\n{"event":"login_ok","user":"root"}')
    lines = env.log.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event"] == "probe"


def test_invalid_user_field_is_masked(env):
    log.event("probe", user="a\nb; rm -rf /")
    assert events(env)[-1]["user"] == "<invalid>"


def test_long_strings_are_truncated(env):
    log.event("probe", reason="A" * 10_000)
    assert len(events(env)[-1]["reason"]) == log.MAX_STR_LEN


def test_logging_failure_never_breaks_a_command(env, monkeypatch):
    run("register", "alice")
    src = env.work / "f.txt"
    src.write_bytes(b"data")

    def broken(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(log, "_attach", broken)
    log.event("probe")                                  # must not raise
    assert run("--user", "alice", "encrypt", str(src)) == 0


def test_symlinked_log_is_not_followed(env, tmp_path):
    env.log.parent.mkdir(mode=0o700, exist_ok=True)
    target = tmp_path / "victim.txt"
    target.write_text("original")
    env.log.symlink_to(target)
    log.event("probe")
    assert target.read_text() == "original"


def test_existing_loose_log_gets_tightened(env):
    env.log.parent.mkdir(mode=0o700, exist_ok=True)
    env.log.write_text("")
    os.chmod(env.log, 0o644)
    log.event("probe")
    assert stat.S_IMODE(env.log.stat().st_mode) == 0o600


def test_rotation_keeps_private_permissions(env, monkeypatch):
    monkeypatch.setattr(log, "MAX_BYTES", 400)
    log._current_path = None                            # force a new handler with new limit
    for i in range(30):
        log.event("probe", file_id=i)
    files = sorted(env.log.parent.glob("sfm.log*"))
    assert len(files) > 1
    for f in files:
        assert stat.S_IMODE(f.stat().st_mode) == 0o600
