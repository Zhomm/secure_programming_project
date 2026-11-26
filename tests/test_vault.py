"""Vault tests: encrypt/decrypt correctness, what is stored on disk, secure deletion.

Run from the project root:  pytest tests/test_vault.py -v
"""

import os
import stat
from types import SimpleNamespace

import pytest

from sfm import auth, cli, storage, vault

PASSWORD = "S3cret-Pass-123"
SECRET = b"TOP-SECRET-CONTENT-0123456789"


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
    auth.register("alice", PASSWORD)
    kek = auth.login("alice", PASSWORD)
    return SimpleNamespace(home=home, work=work, kek=kek, vault=home / ".sfm" / "vault" / "alice")


def put(env, name, data):
    f = env.work / name
    f.write_bytes(data)
    return vault.encrypt_file("alice", env.kek, str(f))


def get(env, file_id, name="out.bin", force=False):
    out = env.work / name
    vault.decrypt_file("alice", env.kek, file_id, str(out), force)
    return out


def all_vault_bytes(env):
    return b"".join(p.read_bytes() for p in env.vault.rglob("*") if p.is_file())


# ------------------------------------------------------------------ correctness
@pytest.mark.parametrize("size", [0, 1, 16, 4095, 1024 * 1024 + 7])
def test_round_trip_is_byte_exact(env, size):
    data = os.urandom(size)
    file_id = put(env, "in.bin", data)
    assert get(env, file_id).read_bytes() == data


def test_binary_and_unicode_names_round_trip(env):
    data = bytes(range(256)) * 10
    file_id = put(env, "résumé-日本語.bin", data)
    assert vault.list_files("alice", env.kek) == [(file_id, "résumé-日本語.bin")]
    assert get(env, file_id).read_bytes() == data


def test_ids_increase_and_list_matches(env):
    ids = [put(env, f"f{i}.txt", b"x%d" % i) for i in range(3)]
    assert ids == [1, 2, 3]
    assert vault.list_files("alice", env.kek) == [(1, "f0.txt"), (2, "f1.txt"), (3, "f2.txt")]


def test_same_file_encrypted_twice_gives_two_independent_entries(env):
    a = put(env, "same.txt", SECRET)
    b = put(env, "same.txt", SECRET)
    blobs = sorted((env.vault / "blobs").iterdir())
    assert a != b and len(blobs) == 2
    assert blobs[0].read_bytes() != blobs[1].read_bytes()


def test_original_file_is_left_untouched(env):
    put(env, "orig.txt", SECRET)
    assert (env.work / "orig.txt").read_bytes() == SECRET


def test_unknown_ids_are_rejected(env):
    put(env, "a.txt", b"x")
    for bad in (0, 2, -1, 10**9):
        with pytest.raises(vault.VaultError, match="file not found"):
            vault.decrypt_file("alice", env.kek, bad, str(env.work / "o.bin"))
        with pytest.raises(vault.VaultError, match="file not found"):
            vault.delete_file("alice", env.kek, bad)


def test_decrypt_never_overwrites_without_force(env):
    file_id = put(env, "a.txt", b"new content")
    target = env.work / "existing.txt"
    target.write_bytes(b"precious old data")
    with pytest.raises(Exception, match="--force"):
        get(env, file_id, "existing.txt")
    assert target.read_bytes() == b"precious old data"
    get(env, file_id, "existing.txt", force=True)
    assert target.read_bytes() == b"new content"


def test_decrypted_file_is_private(env):
    file_id = put(env, "a.txt", b"x")
    assert stat.S_IMODE(get(env, file_id).stat().st_mode) == 0o600


def test_wrong_key_cannot_use_the_vault(env):
    put(env, "a.txt", SECRET)
    with pytest.raises(vault.VaultError):
        vault.list_files("alice", bytearray(32))


# ------------------------------------------------------------------ what is on disk
def test_nothing_readable_is_stored(env):
    put(env, "my-secret-name.txt", SECRET)
    disk = all_vault_bytes(env)
    assert SECRET not in disk
    assert b"my-secret-name" not in disk
    assert b"alice.txt" not in disk
    names = [p.name for p in env.vault.rglob("*")]
    assert not any("my-secret-name" in n for n in names)


def test_blob_names_are_random_and_permissions_are_private(env):
    put(env, "a.txt", b"1")
    put(env, "b.txt", b"2")
    blobs = list((env.vault / "blobs").iterdir())
    assert all(vault.BLOB_NAME_RE.fullmatch(b.name) for b in blobs)
    assert len({b.name for b in blobs}) == 2
    for p in env.vault.rglob("*"):
        mode = stat.S_IMODE(p.stat().st_mode)
        assert mode == (0o700 if p.is_dir() else 0o600), p


def test_no_temporary_files_are_left_behind(env):
    file_id = put(env, "a.txt", b"x")
    get(env, file_id)
    get(env, file_id, force=True)
    vault.delete_file("alice", env.kek, file_id)
    leftovers = [p for p in env.home.rglob("*") if p.suffix == ".tmp" or p.name.startswith(".sfm-")]
    assert leftovers == []


# ------------------------------------------------------------------ secure deletion
def test_delete_removes_record_and_blob(env):
    keep = put(env, "keep.txt", b"keep me")
    gone = put(env, "gone.txt", SECRET)
    vault.delete_file("alice", env.kek, gone)
    assert vault.list_files("alice", env.kek) == [(keep, "keep.txt")]
    assert len(list((env.vault / "blobs").iterdir())) == 1
    assert get(env, keep).read_bytes() == b"keep me"            # the other file is untouched


def test_deleted_file_cannot_be_recovered_even_with_the_old_blob(env):
    """Crypto-erase: the wrapped key lived only in the index, so a copy of the blob is useless."""
    file_id = put(env, "a.txt", SECRET)
    blob = next((env.vault / "blobs").iterdir())
    saved_blob = blob.read_bytes()
    vault.delete_file("alice", env.kek, file_id)
    assert not blob.exists()
    assert SECRET not in saved_blob
    with pytest.raises(vault.VaultError, match="file not found"):
        vault.decrypt_file("alice", env.kek, file_id, str(env.work / "o.bin"))


def test_deleting_twice_fails_cleanly(env):
    file_id = put(env, "a.txt", b"x")
    vault.delete_file("alice", env.kek, file_id)
    with pytest.raises(vault.VaultError, match="file not found"):
        vault.delete_file("alice", env.kek, file_id)


def test_delete_with_cli_prints_a_generic_message(env, monkeypatch, capsys):
    put(env, "a.txt", b"x")
    monkeypatch.setattr("getpass.getpass", lambda prompt="": PASSWORD)
    assert cli.main(["--user", "alice", "delete", "1"]) == 0
    assert capsys.readouterr().out.strip() == "Deleted."


def test_secure_delete_overwrites_the_data_before_unlinking(tmp_path, monkeypatch):
    f = tmp_path / "victim.bin"
    original = os.urandom(300_000)
    f.write_bytes(original)
    seen = {}
    real_unlink = os.unlink

    def spy(path, *a, **k):
        seen["content"] = open(path, "rb").read()                # what is on disk right before removal
        return real_unlink(path, *a, **k)
    monkeypatch.setattr(os, "unlink", spy)
    storage.secure_delete(f)
    assert not f.exists()
    assert len(seen["content"]) == len(original)
    assert seen["content"] != original
    assert sum(a == b for a, b in zip(seen["content"], original)) < len(original) * 0.02


def test_secure_delete_handles_multiple_chunks_and_empty_files(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "CHUNK_SIZE", 4096)
    big = tmp_path / "big.bin"
    big.write_bytes(b"A" * 20_000)
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    storage.secure_delete(big)
    storage.secure_delete(empty)
    assert not big.exists() and not empty.exists()


def test_secure_delete_syncs_file_and_directory(tmp_path, monkeypatch):
    f = tmp_path / "x.bin"
    f.write_bytes(b"x" * 100)
    synced = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd), real(fd))[1])
    storage.secure_delete(f)
    assert len(synced) == 2                                      # the file, then its directory


def test_secure_delete_refuses_symlinks_and_directories(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("must survive")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        storage.secure_delete(link)
    assert target.read_text() == "must survive"
    with pytest.raises(OSError):
        storage.secure_delete(tmp_path)


def test_secure_delete_of_a_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        storage.secure_delete(tmp_path / "nothing")
