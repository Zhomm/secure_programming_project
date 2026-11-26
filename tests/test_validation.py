"""Input-validation tests: usernames, passwords, paths, symlinks, control characters, sizes.

Run from the project root:  pytest tests/test_validation.py -v
"""

import ast
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sfm import auth, cli, validation, vault

SRC = Path(__file__).resolve().parents[1] / "src" / "sfm"
V = validation


# ------------------------------------------------------------------ usernames
@pytest.mark.parametrize("name", ["alice", "Bob_1", "a-b-c", "abc", "x" * 32])
def test_valid_usernames(name):
    assert V.validate_username(name) == name


@pytest.mark.parametrize("name", [
    "", "ab", "x" * 33, "../alice", "a/b", "a b", "alice\n", "al\x00ice", "alice;rm",
    "àlice", "a.b", None, 123, b"alice",
])
def test_invalid_usernames(name):
    with pytest.raises(V.ValidationError):
        V.validate_username(name)


# ------------------------------------------------------------------ passwords
def test_password_length_limits():
    assert V.validate_password("x" * 128)
    with pytest.raises(V.ValidationError):
        V.validate_password("x" * 129)
    with pytest.raises(V.ValidationError):
        V.validate_password("")


def test_password_strength_only_checked_when_asked():
    assert V.validate_password("short")                       # login: any non-empty password
    with pytest.raises(V.ValidationError):
        V.validate_password("short", check_strength=True)     # registration: minimum length
    assert V.validate_password("long-enough", check_strength=True)


# ------------------------------------------------------------------ raw path checks
@pytest.mark.parametrize("raw", [
    "", "a\x00b", "safe.txt\x00../../etc/passwd", "a\nb", "a\rb", "a\x1b[31mred",
    "a\x07bell", "a\x7fdel", "x" * 5000, None, 42, b"bytes",
])
def test_bad_raw_paths_are_rejected(raw, tmp_path):
    with pytest.raises(V.ValidationError):
        V.validate_source_path(raw)
    with pytest.raises(V.ValidationError):
        V.validate_dest_path(raw)


def test_very_long_names_fail_cleanly_not_with_an_os_error(tmp_path):
    for raw in ("x" * 4096, str(tmp_path / ("y" * 300))):           # within MAX_PATH_LEN, too long for the OS
        with pytest.raises(V.ValidationError, match="invalid path"):
            V.validate_source_path(raw)
        with pytest.raises(V.ValidationError, match="invalid path"):
            V.validate_dest_path(raw)


# ------------------------------------------------------------------ source files
def test_regular_file_is_accepted(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hi")
    assert V.validate_source_path(str(f)) == f.resolve()


def test_missing_file_directory_and_special_files_are_rejected(tmp_path):
    with pytest.raises(V.ValidationError):
        V.validate_source_path(str(tmp_path / "missing"))
    with pytest.raises(V.ValidationError, match="not a regular file"):
        V.validate_source_path(str(tmp_path))
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(V.ValidationError, match="not a regular file"):
        V.validate_source_path(str(fifo))
    with pytest.raises(V.ValidationError):
        V.validate_source_path("/dev/null")


def test_symlink_source_is_rejected(tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("secret")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    with pytest.raises(V.ValidationError, match="symbolic links"):
        V.validate_source_path(str(link))


def test_dangling_symlink_source_is_rejected(tmp_path):
    link = tmp_path / "dangling"
    link.symlink_to(tmp_path / "nowhere")
    with pytest.raises(V.ValidationError):
        V.validate_source_path(str(link))


def test_file_inside_a_symlinked_directory_is_still_accepted(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "a.txt").write_text("x")
    (tmp_path / "dirlink").symlink_to(real)
    assert V.validate_source_path(str(tmp_path / "dirlink" / "a.txt")).name == "a.txt"


def test_dot_dot_components_are_resolved(tmp_path):
    (tmp_path / "sub").mkdir()
    f = tmp_path / "a.txt"
    f.write_text("x")
    assert V.validate_source_path(str(tmp_path / "sub" / ".." / "a.txt")) == f.resolve()


def test_file_too_large_is_rejected(tmp_path, monkeypatch):
    f = tmp_path / "big.bin"
    f.write_bytes(b"x" * 100)
    monkeypatch.setattr(V, "MAX_FILE_SIZE", 99)
    with pytest.raises(V.ValidationError, match="too large"):
        V.validate_source_path(str(f))
    monkeypatch.setattr(V, "MAX_FILE_SIZE", 100)
    assert V.validate_source_path(str(f))


def test_empty_file_is_accepted(tmp_path):
    f = tmp_path / "empty"
    f.write_bytes(b"")
    assert V.validate_source_path(str(f))


# ------------------------------------------------------------------ destinations
def test_new_destination_is_accepted(tmp_path):
    dest = V.validate_dest_path(str(tmp_path / "out.txt"))
    assert dest == tmp_path.resolve() / "out.txt"


@pytest.mark.parametrize("raw", [".", "..", "dir/.", "dir/.."])
def test_destination_names_that_are_not_files(raw, tmp_path):
    (tmp_path / "dir").mkdir()
    with pytest.raises(V.ValidationError):
        V.validate_dest_path(str(tmp_path / raw))


def test_destination_in_missing_directory_is_rejected(tmp_path):
    with pytest.raises(V.ValidationError):
        V.validate_dest_path(str(tmp_path / "nodir" / "out.txt"))


def test_destination_parent_must_be_a_directory(tmp_path):
    f = tmp_path / "file"
    f.write_text("x")
    with pytest.raises(V.ValidationError):
        V.validate_dest_path(str(f / "out.txt"))


def test_existing_destination_needs_force(tmp_path):
    f = tmp_path / "out.txt"
    f.write_text("old")
    with pytest.raises(V.ValidationError, match="--force"):
        V.validate_dest_path(str(f))
    assert V.validate_dest_path(str(f), force=True) == f.resolve()


def test_dangling_symlink_destination_needs_force(tmp_path):
    link = tmp_path / "out.txt"
    link.symlink_to(tmp_path / "nowhere")
    with pytest.raises(V.ValidationError, match="--force"):
        V.validate_dest_path(str(link))


# ------------------------------------------------------------------ login timing and listing
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
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "S3cret-Pass-123")
    return SimpleNamespace(home=home, work=work)


def test_unknown_user_costs_the_same_argon2_work_as_a_wrong_password(env, monkeypatch):
    auth.register("alice", "S3cret-Pass-123")
    calls = []
    real = auth._derive_root_key
    monkeypatch.setattr(auth, "_derive_root_key", lambda pw, salt: calls.append(1) or real(pw, salt))
    for user, pw in (("alice", "wrong-password-1"), ("ghost", "wrong-password-1")):
        calls.clear()
        with pytest.raises(auth.AuthError, match="invalid username or password"):
            auth.login(user, pw)
        assert calls == [1], user


def test_unknown_user_and_wrong_password_give_the_same_error(env):
    auth.register("alice", "S3cret-Pass-123")
    errors = []
    for user in ("alice", "ghost"):
        with pytest.raises(auth.AuthError) as e:
            auth.login(user, "wrong-password-1")
        errors.append(str(e.value))
    assert errors[0] == errors[1]


def test_file_name_with_control_characters_cannot_be_encrypted(env):
    auth.register("alice", "S3cret-Pass-123")
    kek = auth.login("alice", "S3cret-Pass-123")
    evil = env.work / "evil\x1b[2Jname.txt"
    evil.write_text("x")
    with pytest.raises(V.ValidationError):
        vault.encrypt_file("alice", kek, str(evil))


def test_list_escapes_control_characters_in_stored_names(env, capsys):
    """A name stored by an older version (or planted in the index) must not reach the terminal raw."""
    assert cli.main(["register", "alice"]) == 0
    kek = auth.login("alice", "S3cret-Pass-123")
    vault._save_index("alice", kek, [{"id": 1, "name": "bad\x1b[2Jname\n", "blob": "0" * 32 + ".bin", "dek": ""}])
    capsys.readouterr()
    assert cli.main(["--user", "alice", "list"]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\\x1b" in out and "\\x0a" in out


# ------------------------------------------------------------------ no shell / dynamic execution
FORBIDDEN_IMPORTS = {"subprocess", "pickle", "marshal", "shelve", "commands"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}


def _py_files():
    return sorted(SRC.glob("*.py"))


def test_source_never_spawns_shells_or_executes_dynamic_code():
    offenders = []
    for path in _py_files():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                offenders += [f"{path.name}: import {a.name}" for a in node.names
                              if a.name.split(".")[0] in FORBIDDEN_IMPORTS]
            elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in FORBIDDEN_IMPORTS:
                offenders.append(f"{path.name}: from {node.module}")
            elif isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Name) and f.id in FORBIDDEN_CALLS:
                    offenders.append(f"{path.name}: {f.id}()")
                if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                    if f.value.id == "os" and f.attr in {"system", "popen", "execv", "execl", "spawnl"}:
                        offenders.append(f"{path.name}: os.{f.attr}()")
                for kw in node.keywords:
                    if kw.arg == "shell":
                        offenders.append(f"{path.name}: shell=")
    assert not offenders, offenders


def test_sqlite_queries_are_parameterised():
    """No f-string / % / + / .format() building of SQL passed to execute()."""
    offenders = []
    for path in _py_files():
        for node in ast.walk(ast.parse(path.read_text())):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"execute", "executemany", "executescript"} and node.args):
                if not (isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                    offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, offenders
