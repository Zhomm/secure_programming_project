import os
import sqlite3
import stat
from pathlib import Path

APP_DIR_NAME = ".sfm"

def get_base_dir() -> Path:
    return Path.home() / APP_DIR_NAME

#create a directory if missing and ensure its permission
def _ensure_dir(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)

def ensure_base_dir() -> Path:
    base = get_base_dir()
    _ensure_dir(base)
    return base

def get_users_db_path() -> Path:
    return ensure_base_dir() / "users.db"

#Create the users table if it does not exist yet.
def init_users_db() -> None:
    db_path = get_users_db_path()
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username   TEXT PRIMARY KEY,
                salt       BLOB NOT NULL,
                verifier   BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.commit()
    finally:
        conn.close()
    os.chmod(db_path, 0o600)

#return/create a directory in ~/.sfm/vault/<username> with 700 permission
def get_user_dir(username: str) -> Path:
    base = ensure_base_dir()
    vault_root = base / "vault"
    _ensure_dir(vault_root) 
    user_dir = vault_root / username
    _ensure_dir(user_dir)
    return user_dir

def get_blobs_dir(username: str) -> Path:
    blobs_dir = get_user_dir(username) / "blobs"
    _ensure_dir(blobs_dir)
    return blobs_dir

def get_index_path(username: str) -> Path:
    return get_user_dir(username) / "index.enc"

#return the encrypted raw index.enc
def read_index_blob(username: str) -> bytes | None:
    index_path = get_index_path(username)
    if not index_path.exists():
        return None
    return index_path.read_bytes()

#atomic write of index.enc
def write_index_blob(username: str, data: bytes) -> None:
    index_path = get_index_path(username)
    tmp_path = index_path.with_suffix(".tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, index_path)

CHUNK_SIZE = 1024 * 1024

#overwrite regular file with random bytes, flush it and unlink it
def secure_delete(path: Path) -> None:
    fd = os.open(path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)                     
        if not stat.S_ISREG(st.st_mode):
            raise OSError("not a regular file")

        remaining = st.st_size
        while remaining > 0:
            view = memoryview(os.urandom(min(remaining, CHUNK_SIZE)))
            remaining -= len(view)
            while view:                      
                view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)

    os.unlink(path)

    dir_fd = os.open(path.parent, os.O_RDONLY)  
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
