"""Authentication tests: registration, login, failure paths, what the user database contains.

Run from the project root:  pytest tests/test_auth.py -v
"""

import sqlite3
import stat
from types import SimpleNamespace

import pytest

from sfm import auth, cli, validation

PASSWORD = "S3cret-Pass-123"


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(auth, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(auth, "ARGON2_MEMORY_COST", 1024)
    monkeypatch.setattr(auth, "ARGON2_PARALLELISM", 1)
    return SimpleNamespace(home=home, db=home / ".sfm" / "users.db")


def rows(env):
    conn = sqlite3.connect(env.db)
    try:
        return conn.execute("SELECT username, salt, verifier FROM users ORDER BY username").fetchall()
    finally:
        conn.close()


def test_register_then_login_returns_a_32_byte_key(env):
    auth.register("alice", PASSWORD)
    kek = auth.login("alice", PASSWORD)
    assert isinstance(kek, bytearray) and len(kek) == 32


def test_the_same_password_always_gives_the_same_key(env):
    auth.register("alice", PASSWORD)
    assert auth.login("alice", PASSWORD) == auth.login("alice", PASSWORD)


@pytest.mark.parametrize("wrong", ["wrong-password-1", PASSWORD + " ", PASSWORD.lower(), PASSWORD[:-1]])
def test_wrong_passwords_are_rejected(env, wrong):
    auth.register("alice", PASSWORD)
    with pytest.raises(auth.AuthError, match="invalid username or password"):
        auth.login("alice", wrong)


def test_unknown_user_gets_the_same_error_as_a_wrong_password(env):
    auth.register("alice", PASSWORD)
    messages = []
    for user in ("alice", "nobody"):
        with pytest.raises(auth.AuthError) as e:
            auth.login(user, "wrong-password-1")
        messages.append(str(e.value))
    assert messages[0] == messages[1]


def test_registering_twice_fails_and_keeps_the_first_password(env):
    auth.register("alice", PASSWORD)
    with pytest.raises(auth.AuthError, match="registration failed"):
        auth.register("alice", "another-password-9")
    assert auth.login("alice", PASSWORD)
    with pytest.raises(auth.AuthError):
        auth.login("alice", "another-password-9")


def test_usernames_are_case_sensitive(env):
    auth.register("alice", PASSWORD)
    with pytest.raises(auth.AuthError):
        auth.login("Alice", PASSWORD)


def test_login_before_any_registration_does_not_crash(env):
    with pytest.raises(auth.AuthError, match="invalid username or password"):
        auth.login("alice", PASSWORD)


def test_each_user_gets_a_unique_salt_verifier_and_key(env):
    auth.register("alice", PASSWORD)
    auth.register("bob", PASSWORD)                                # same password on purpose
    (_, salt_a, ver_a), (_, salt_b, ver_b) = rows(env)
    assert salt_a != salt_b and ver_a != ver_b
    assert len(salt_a) == 16 and len(ver_a) == 32
    assert auth.login("alice", PASSWORD) != auth.login("bob", PASSWORD)


def test_database_never_contains_the_password_or_the_key(env):
    auth.register("alice", PASSWORD)
    kek = bytes(auth.login("alice", PASSWORD))
    raw = env.db.read_bytes()
    assert PASSWORD.encode() not in raw
    assert kek not in raw


def test_stored_verifier_is_not_the_encryption_key(env):
    """The verifier (in the database) and the KEK (RAM only) come from different HKDF labels."""
    auth.register("alice", PASSWORD)
    (_, _, verifier), = rows(env)
    assert verifier != bytes(auth.login("alice", PASSWORD))


def test_database_permissions_are_private(env):
    auth.register("alice", PASSWORD)
    assert stat.S_IMODE(env.db.stat().st_mode) == 0o600
    assert stat.S_IMODE(env.db.parent.stat().st_mode) == 0o700


def test_passwords_with_unicode_and_spaces_work(env):
    pw = "pässwörd with spaces 日本語"
    auth.register("alice", pw)
    assert auth.login("alice", pw)
    with pytest.raises(auth.AuthError):
        auth.login("alice", "passwörd with spaces 日本語")


def test_bytearray_passwords_give_the_same_key_as_str(env):
    auth.register("alice", PASSWORD)
    assert auth.login("alice", PASSWORD) == auth.login("alice", bytearray(PASSWORD.encode()))


def test_sql_injection_in_the_username_is_harmless(env):
    auth.register("alice", PASSWORD)
    with pytest.raises(auth.AuthError):
        auth.login("alice' OR '1'='1", "x")
    with pytest.raises(auth.AuthError):
        auth.login("x'; DROP TABLE users; --", "x")
    assert len(rows(env)) == 1


# ------------------------------------------------------------------ through the command line
@pytest.fixture
def ask(monkeypatch):
    def set_password(*answers):
        it = iter(answers)
        monkeypatch.setattr("getpass.getpass", lambda prompt="": next(it))
    return set_password


def test_cli_register_rejects_short_and_empty_passwords(env, ask, capsys):
    for pw in ("short", ""):
        ask(pw, pw)
        assert cli.main(["register", "alice"]) == 1
    assert not env.db.exists() or rows(env) == []
    assert "Error:" in capsys.readouterr().err


def test_cli_register_rejects_mismatching_confirmation(env, ask, capsys):
    ask(PASSWORD, PASSWORD + "x")
    assert cli.main(["register", "alice"]) == 1
    assert "passwords do not match" in capsys.readouterr().err


def test_cli_login_with_empty_password_never_succeeds(env, ask):
    ask(PASSWORD, PASSWORD)
    cli.main(["register", "alice"])
    ask("")
    assert cli.main(["--user", "alice", "list"]) == 1


def test_cli_rejects_invalid_usernames_before_touching_anything(env, ask):
    ask(PASSWORD, PASSWORD)
    for bad in ("ab", "../x", "a b", "x" * 33):
        assert cli.main(["register", bad]) == 1
    assert not env.db.exists() or rows(env) == []


def test_cli_wrong_password_message_is_generic_and_exit_code_is_1(env, ask, capsys):
    ask(PASSWORD, PASSWORD)
    cli.main(["register", "alice"])
    ask("wrong-password-1")
    capsys.readouterr()
    assert cli.main(["--user", "alice", "list"]) == 1
    err = capsys.readouterr().err
    assert err.strip() == "Error: invalid username or password"
    assert "Traceback" not in err


def test_cli_requires_a_user_for_every_command_but_register(env, ask):
    with pytest.raises(SystemExit) as e:
        cli.main(["list"])
    assert e.value.code == 2
