"""Vault operations: encrypt a file into the vault, decrypt it back."""

import base64
import json
import os
import secrets
import stat
import re

from . import crypto, storage, validation

BLOB_NAME_RE = re.compile(r"[0-9a-f]{32}\.bin")

class VaultError(Exception):
    """Generic vault failure (no internal details in the message)."""


def _index_aad(username: str) -> bytes:
    return f"sfm-index|{username}".encode()


def _blob_aad(username: str, file_id: int) -> bytes:
    return f"sfm-blob|{username}|{file_id}".encode()


def _dek_aad(username: str, file_id: int) -> bytes:
    return f"sfm-dek|{username}|{file_id}".encode()

def _blob_path(username: str, record: dict):
    name = record.get("blob", "")
    if not BLOB_NAME_RE.fullmatch(name):
        raise VaultError("cannot read vault")
    return storage.get_blobs_dir(username) / name

def _load_index(username: str, kek: bytes) -> list[dict]:
    blob = storage.read_index_blob(username)
    if blob is None:
        return []
    try:
        plain = crypto.decrypt_bytes(kek, blob, _index_aad(username))
    except crypto.DecryptionError:
        raise VaultError("cannot open vault")
    return json.loads(plain)


def _save_index(username: str, kek: bytes, records: list[dict]) -> None:
    plain = json.dumps(records).encode()
    blob = crypto.encrypt_bytes(kek, plain, _index_aad(username))
    storage.write_index_blob(username, blob)


def _read_source(path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > validation.MAX_FILE_SIZE:
            raise VaultError("invalid file")
        return f.read()


def encrypt_file(username: str, kek: bytes, raw_path: str) -> int:
    src = validation.validate_source_path(raw_path)
    try:
        plaintext = _read_source(src)
    except OSError:
        raise VaultError("cannot read file")

    records = _load_index(username, kek)
    file_id = max((r["id"] for r in records), default=0) + 1

    dek = crypto.generate_key()
    blob = crypto.encrypt_bytes(dek, plaintext, _blob_aad(username, file_id))
    wrapped_dek = crypto.encrypt_bytes(kek, dek, _dek_aad(username, file_id))

    blob_name = secrets.token_hex(16) + ".bin"
    blob_path = storage.get_blobs_dir(username) / blob_name
    
    try:
        fd = os.open(blob_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            _write_fd(fd, blob)
        except BaseException:
            blob_path.unlink(missing_ok=True)  
            raise
    except OSError:
        raise VaultError("cannot write to vault")

    records.append({
        "id": file_id,
        "name": src.name,
        "blob": blob_name,
        "dek": base64.b64encode(wrapped_dek).decode(),
    })
    _save_index(username, kek, records)
    return file_id


def list_files(username: str, kek: bytes) -> list[tuple[int, str]]:
    return [(r["id"], r["name"]) for r in _load_index(username, kek)]

def _write_fd(fd: int, data: bytes) -> None:
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _write_output(dest, data: bytes, force: bool) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not force:
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
        try:
            _write_fd(fd, data)
        except BaseException:
            dest.unlink(missing_ok=True)
            raise
        return

    if os.path.lexists(dest):
        os.close(os.open(dest, os.O_WRONLY | nofollow))
    tmp = dest.with_name(f".sfm-{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
    try:
        _write_fd(fd, data)
        os.replace(tmp, dest)              
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

def decrypt_file(username: str, kek: bytes, file_id: int,
                 raw_dest: str, force: bool = False) -> None:
    dest = validation.validate_dest_path(raw_dest, force)

    record = next((r for r in _load_index(username, kek)
                   if r["id"] == file_id), None)
    if record is None:
        raise VaultError("file not found")
    
    blob_path = _blob_path(username, record)
    try:
        wrapped_dek = base64.b64decode(record["dek"])
        dek = crypto.decrypt_bytes(kek, wrapped_dek, _dek_aad(username, file_id))
        blob = blob_path.read_bytes()
        plaintext = crypto.decrypt_bytes(dek, blob, _blob_aad(username, file_id))
    except (crypto.DecryptionError, OSError):
        raise VaultError("cannot decrypt file")
    
    try:
        _write_output(dest, plaintext, force)
    except OSError:
        raise VaultError("cannot write destination")

def delete_file(username: str, kek: bytes, file_id: int) -> None:
    records = _load_index(username, kek)
    record = next((r for r in records if r["id"] == file_id), None)
    if record is None:
        raise VaultError("file not found")
    blob_path = _blob_path(username, record)

    _save_index(username, kek, [r for r in records if r["id"] != file_id])

    try:
        storage.secure_delete(blob_path)
    except FileNotFoundError:
        pass                                  
    except OSError:
        raise VaultError("cannot erase file data")
