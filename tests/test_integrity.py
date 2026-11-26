"""Integrity tests: what happens when someone edits, truncates or deletes the stored files.

Run from the project root:  pytest tests/test_integrity.py -v
"""

import json
import os
import sqlite3
from types import SimpleNamespace

import pytest

from sfm import auth, cli, vault

PASSWORD = "S3cret-Pass-123"


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
    sfm = home / ".sfm"
    return SimpleNamespace(home=home, work=work, db=sfm / "users.db", log=sfm / "sfm.log",
                           user_dir=sfm / "vault" / "alice")


def run(*argv):
    return cli.main(list(argv))


def log_events(env):
    return [json.loads(l)["event"] + ":" + json.loads(l).get("reason", "")
            for l in env.log.read_text().splitlines()]


def make_vault(env, content=b"important data"):
    assert run("register", "alice") == 0
    src = env.work / "f.txt"
    src.write_bytes(content)
    assert run("--user", "alice", "encrypt", str(src)) == 0
    return src


def blob_of(env):
    return next((env.user_dir / "blobs").iterdir())


# ------------------------------------------------------------------ users.db
def test_appending_a_byte_to_the_database_changes_no_data(env):
    """SQLite ignores trailing bytes, so the stored rows are intact and everything still works."""
    make_vault(env)
    with open(env.db, "ab") as f:
        f.write(b"1")
    assert run("--user", "alice", "list") == 0


def test_garbage_database_is_reported_cleanly(env, capsys):
    make_vault(env)
    env.db.write_bytes(os.urandom(5000))
    capsys.readouterr()
    assert run("--user", "alice", "list") == 1
    assert capsys.readouterr().err.strip() == "Error: user database is damaged"
    assert run("register", "bob") == 1
    assert any(e.startswith("integrity_error") for e in log_events(env))


def test_truncated_database_is_reported_cleanly(env, capsys):
    make_vault(env)
    size = env.db.stat().st_size
    with open(env.db, "r+b") as f:
        f.truncate(size // 2)
    capsys.readouterr()
    assert run("--user", "alice", "list") == 1
    assert "damaged" in capsys.readouterr().err


def test_deleted_database_means_unknown_user_not_a_crash(env, capsys):
    make_vault(env)
    env.db.unlink()
    capsys.readouterr()
    assert run("--user", "alice", "list") == 1
    assert capsys.readouterr().err.strip() == "Error: invalid username or password"


def test_changed_verifier_only_locks_the_user_out(env):
    make_vault(env)
    conn = sqlite3.connect(env.db)
    conn.execute("UPDATE users SET verifier = ?", (bytes(32),))
    conn.commit()
    conn.close()
    assert run("--user", "alice", "list") == 1


def test_changed_salt_cannot_open_the_vault(env):
    make_vault(env)
    conn = sqlite3.connect(env.db)
    conn.execute("UPDATE users SET salt = ?", (bytes(16),))
    conn.commit()
    conn.close()
    assert run("--user", "alice", "list") == 1


def test_forged_verifier_logs_in_but_cannot_read_any_data(env, capsys):
    """An attacker who rewrites users.db with his own password passes the login check,
    but the key derived from his password cannot open the real index."""
    make_vault(env)
    attacker_pw = "attacker-password-9"
    salt = os.urandom(16)
    root = auth._derive_root_key(attacker_pw, salt)
    verifier = auth._derive(root, info=b"sfm-auth-verifier")
    conn = sqlite3.connect(env.db)
    conn.execute("UPDATE users SET salt = ?, verifier = ?", (salt, verifier))
    conn.commit()
    conn.close()
    kek = auth.login("alice", attacker_pw)                     # login "works"...
    with pytest.raises(vault.VaultError, match="cannot open vault"):   # ...data does not
        vault.list_files("alice", kek)
    assert any(e.startswith("integrity_error") for e in log_events(env))


# ------------------------------------------------------------------ index.enc
def test_new_user_gets_an_authenticated_empty_index(env):
    assert run("register", "alice") == 0
    assert (env.user_dir / "index.enc").exists()
    assert run("--user", "alice", "list") == 0


def test_deleted_index_with_files_present_is_an_error_not_an_empty_vault(env, capsys):
    make_vault(env)
    (env.user_dir / "index.enc").unlink()
    blobs_before = sorted(p.name for p in (env.user_dir / "blobs").iterdir())
    capsys.readouterr()
    for cmd in (["list"], ["delete", "1"], ["decrypt", "1", "-o", str(env.work / "o.txt")],
                ["encrypt", str(env.work / "f.txt")]):
        assert run("--user", "alice", *cmd) == 1
        assert capsys.readouterr().err.strip() == "Error: vault index is missing or damaged"
    assert not (env.user_dir / "index.enc").exists()           # no new index was created
    assert sorted(p.name for p in (env.user_dir / "blobs").iterdir()) == blobs_before
    assert "integrity_error:index missing" in log_events(env)


def test_deleted_index_and_no_files_is_just_an_empty_vault(env):
    """Nothing is lost, so there is nothing to protect (and nothing to detect)."""
    assert run("register", "alice") == 0
    (env.user_dir / "index.enc").unlink()
    assert run("--user", "alice", "list") == 0


@pytest.mark.parametrize("damage", ["append", "flip", "truncate", "empty"])
def test_modified_index_is_detected(env, capsys, damage):
    make_vault(env)
    idx = env.user_dir / "index.enc"
    data = bytearray(idx.read_bytes())
    if damage == "append":
        data += b"1"
    elif damage == "flip":
        data[len(data) // 2] ^= 0x01
    elif damage == "truncate":
        data = data[:-5]
    else:
        data = bytearray()
    idx.write_bytes(bytes(data))
    capsys.readouterr()
    assert run("--user", "alice", "list") == 1
    assert capsys.readouterr().err.strip() == "Error: cannot open vault"
    assert "integrity_error:index authentication failed" in log_events(env)


def test_old_index_copy_is_not_detected_rollback_is_a_documented_limit(env):
    """Replacing the index with an older valid copy still authenticates (no version counter)."""
    src = make_vault(env)
    old = (env.user_dir / "index.enc").read_bytes()
    assert run("--user", "alice", "encrypt", str(src)) == 0     # now 2 files
    (env.user_dir / "index.enc").write_bytes(old)               # back to 1 file
    assert run("--user", "alice", "list") == 0                  # accepted: known limitation


# ------------------------------------------------------------------ blobs
@pytest.mark.parametrize("damage", ["append", "flip", "truncate"])
def test_modified_encrypted_file_is_detected_and_nothing_is_written(env, capsys, damage):
    make_vault(env)
    blob = blob_of(env)
    data = bytearray(blob.read_bytes())
    if damage == "append":
        data += b"1"
    elif damage == "flip":
        data[len(data) // 2] ^= 0x01
    else:
        data = data[: len(data) // 2]
    blob.write_bytes(bytes(data))
    out = env.work / "out.txt"
    capsys.readouterr()
    assert run("--user", "alice", "decrypt", "1", "-o", str(out)) == 1
    assert capsys.readouterr().err.strip() == "Error: file is corrupted or has been modified"
    assert not out.exists()
    assert "integrity_error:file authentication failed" in log_events(env)


def test_deleted_encrypted_file_is_reported(env, capsys):
    make_vault(env)
    blob_of(env).unlink()
    out = env.work / "out.txt"
    capsys.readouterr()
    assert run("--user", "alice", "decrypt", "1", "-o", str(out)) == 1
    assert "Error: cannot decrypt file" in capsys.readouterr().err
    assert not out.exists()
    assert "integrity_error:blob unreadable" in log_events(env)


def test_two_encrypted_files_cannot_be_swapped(env):
    """Swapping two blobs is caught: each blob is bound to its file id by the AAD."""
    src = make_vault(env, b"first")
    src.write_bytes(b"second")
    assert run("--user", "alice", "encrypt", str(src)) == 0
    index = vault._load_index("alice", auth.login("alice", PASSWORD))
    p1 = env.user_dir / "blobs" / index[0]["blob"]
    p2 = env.user_dir / "blobs" / index[1]["blob"]
    a, b = p1.read_bytes(), p2.read_bytes()
    p1.write_bytes(b)
    p2.write_bytes(a)
    assert run("--user", "alice", "decrypt", "1", "-o", str(env.work / "o1.txt")) == 1
    assert run("--user", "alice", "decrypt", "2", "-o", str(env.work / "o2.txt")) == 1
    assert not (env.work / "o1.txt").exists() and not (env.work / "o2.txt").exists()
