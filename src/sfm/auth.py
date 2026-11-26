""" auth.py handles the user authentication (login and register) using argon2id with salt for a secure password storage """

import sqlite3
import hmac
import os
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from . import log, secmem, storage, vault

SALT_SIZE = 16    
ROOT_KEY_SIZE = 32
_DUMMY_SALT = bytes(SALT_SIZE)   # used only to spend the same time for unknown users

# Argon2id cost parameters 
ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 262144   # 256 MiB
ARGON2_PARALLELISM = 4
#with these parameters I achieve around 0.3s 

class AuthError(Exception):
    """Raised on registration or login failure (generic)."""

def _secret_bytes(password) -> bytes:
    if isinstance(password, str):
        return password.encode("utf-8")
    return bytes(password)

#used to derive the root key, using a salt
def _derive_root_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=_secret_bytes(password),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ROOT_KEY_SIZE,
        type=Type.ID,  # Argon2id
    )

#split the root key into 2 subkeys
def _derive(root_key: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(root_key)

def _open_db() -> sqlite3.Connection:
    try:
        return storage.open_users_db()
    except storage.StorageError:
        log.event("integrity_error", level="error", reason="users database damaged")
        raise AuthError("user database is damaged")

#create root_key and the relative verifier (used for login) and save into database
#if successfull create also the user vault dir
def register(username: str, password) -> None:
    conn = _open_db()
    try:
        salt = os.urandom(SALT_SIZE)
        root_key = _derive_root_key(password, salt)
        verifier = _derive(root_key, info=b"sfm-auth-verifier")
        try:
            conn.execute(
                "INSERT INTO users (username, salt, verifier) VALUES (?, ?, ?)",
                (username, salt, verifier),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            log.event("register_failed", level="warning", user=username, reason="exists")
            raise AuthError("registration failed")  # generic
        except sqlite3.Error:
            log.event("integrity_error", level="error", reason="users database damaged")
            raise AuthError("user database is damaged")
    finally:
        conn.close()

    # The index exists from day one, so a missing index.enc is always an anomaly
    storage.get_user_dir(username)
    kek = bytearray(_derive(root_key, info=b"sfm-index-kek"))
    try:
        vault.init_index(username, kek)
    finally:
        secmem.wipe(kek)
    log.event("register_ok", user=username)

#retrieve verifier (if user exists)
def login(username: str, password) -> bytearray:
    conn = _open_db()
    try:
        row = conn.execute(
            "SELECT salt, verifier FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    except sqlite3.Error:
        log.event("integrity_error", level="error", reason="users database damaged")
        raise AuthError("user database is damaged")
    finally:
        conn.close()

    if row is None:
        dummy_root = _derive_root_key(password, _DUMMY_SALT)
        hmac.compare_digest(_derive(dummy_root, info=b"sfm-auth-verifier"), bytes(32))
        log.event("login_failed", level="warning", user=username, reason="unknown_user")
        raise AuthError("invalid username or password")

    salt, stored_verifier = row
    root_key = _derive_root_key(password, salt)
    computed_verifier = _derive(root_key, info=b"sfm-auth-verifier")

    if not hmac.compare_digest(computed_verifier, stored_verifier):
        log.event("login_failed", level="warning", user=username, reason="bad_password")
        raise AuthError("invalid username or password")
    
    kek = bytearray(_derive(root_key, info=b"sfm-index-kek"))
    log.event("login_ok", user=username)
    return kek
