"""Access-control tests: users are isolated, and a vault that is not private is refused.

Run from the project root:  pytest tests/test_access.py -v
"""

import json
import os
import shutil
from types import SimpleNamespace

import pytest

from sfm import auth, cli, log, storage, validation, vault

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
    return SimpleNamespace(home=home, work=work, vault=home / ".sfm" / "vault",
                           log=home / ".sfm" / "sfm.log")


def make_user(env, name, content=b"data"):
    auth.register(name, PASSWORD)
    kek = auth.login(name, PASSWORD)
    src = env.work / f"{name}.txt"
    src.write_bytes(content)
    file_id = vault.encrypt_file(name, kek, str(src))
    return kek, file_id


def log_events(env):
    return [json.loads(l) for l in env.log.read_text().splitlines()]


def test_users_cannot_see_each_others_files(env):
    kek_a, id_a = make_user(env, "alice", b"alice-data")
    kek_b, id_b = make_user(env, "bob", b"bob-data")
    assert [i for i, _ in vault.list_files("alice", kek_a)] == [id_a]
    assert [i for i, _ in vault.list_files("bob", kek_b)] == [id_b]


def test_wrong_key_for_a_vault_is_refused(env):
    kek_a, _ = make_user(env, "alice")
    make_user(env, "bob")
    with pytest.raises(vault.VaultError):
        vault.list_files("alice", auth.login("bob", PASSWORD))   # bob's key, alice's vault
    with pytest.raises(vault.VaultError):
        vault.delete_file("alice", auth.login("bob", PASSWORD), 1)


def test_copied_index_does_not_open_in_another_vault(env):
    """Copy alice's index.enc into bob's directory: bob's key must not open it (AAD + key)."""
    make_user(env, "alice")
    kek_b, _ = make_user(env, "bob")
    shutil.copy(env.vault / "alice" / "index.enc", env.vault / "bob" / "index.enc")
    with pytest.raises(vault.VaultError):
        vault.list_files("bob", kek_b)


def test_copied_blob_does_not_decrypt_for_another_user(env):
    """Put alice's blob and record in bob's vault, re-encrypting the index with bob's own key:
    the blob/DEK are still bound to alice via AAD, so decryption fails."""
    kek_a, id_a = make_user(env, "alice", b"alice-secret")
    kek_b, _ = make_user(env, "bob")
    rec = vault._load_index("alice", kek_a)[0]
    shutil.copy(env.vault / "alice" / "blobs" / rec["blob"],
                env.vault / "bob" / "blobs" / rec["blob"])
    records = vault._load_index("bob", kek_b) + [dict(rec, id=99)]
    vault._save_index("bob", kek_b, records)
    with pytest.raises(vault.VaultError):
        vault.decrypt_file("bob", kek_b, 99, str(env.work / "stolen.txt"))
    assert not (env.work / "stolen.txt").exists()


def test_open_user_directory_is_refused_not_repaired(env):
    kek, _ = make_user(env, "alice")
    d = env.vault / "alice"
    os.chmod(d, 0o755)
    with pytest.raises(vault.VaultError, match="access denied"):
        vault.list_files("alice", kek)
    assert (d.stat().st_mode & 0o777) == 0o755          # still not silently fixed
    assert any(e["event"] == "access_denied" for e in log_events(env))


def test_open_index_is_refused(env):
    kek, _ = make_user(env, "alice")
    os.chmod(env.vault / "alice" / "index.enc", 0o644)
    with pytest.raises(vault.VaultError, match="access denied"):
        vault.list_files("alice", kek)


def test_symlinked_user_dir_is_refused(env, tmp_path):
    kek, _ = make_user(env, "alice")
    real = env.vault / "alice"
    moved = tmp_path / "elsewhere"
    real.rename(moved)
    real.symlink_to(moved)
    with pytest.raises(vault.VaultError, match="access denied"):
        vault.list_files("alice", kek)


def test_blob_replaced_by_symlink_is_refused(env, tmp_path):
    kek, file_id = make_user(env, "alice")
    blob = next((env.vault / "alice" / "blobs").iterdir())
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"x" * 64)
    blob.unlink()
    blob.symlink_to(outside)
    with pytest.raises(vault.VaultError):
        vault.delete_file("alice", kek, file_id)
    assert outside.read_bytes() == b"x" * 64             # target untouched


def test_traversal_in_blob_name_is_refused(env):
    kek, _ = make_user(env, "alice")
    records = vault._load_index("alice", kek)
    records[0]["blob"] = "../../../../etc/passwd"
    vault._save_index("alice", kek, records)
    with pytest.raises(vault.VaultError):
        vault.delete_file("alice", kek, records[0]["id"])


@pytest.mark.parametrize("bad", ["../alice", "a/b", "", "ab", "x" * 40, "al ice", "a\nb"])
def test_bad_username_never_reaches_the_filesystem(env, bad):
    kek, _ = make_user(env, "alice")
    for call in (lambda: vault.list_files(bad, kek),
                 lambda: vault.delete_file(bad, kek, 1),
                 lambda: vault.decrypt_file(bad, kek, 1, str(env.work / "o.txt")),
                 lambda: vault.encrypt_file(bad, kek, str(env.work / "alice.txt"))):
        with pytest.raises(validation.ValidationError):
            call()
    assert sorted(p.name for p in env.vault.iterdir()) == ["alice"]


def test_cli_reports_access_denied_generically(env, monkeypatch, capsys):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": PASSWORD)
    assert cli.main(["register", "alice"]) == 0
    os.chmod(env.vault / "alice", 0o755)
    assert cli.main(["--user", "alice", "list"]) == 1
    err = capsys.readouterr().err
    assert err.strip() == "Error: access denied"
    assert "permissions" not in err and str(env.home) not in err
