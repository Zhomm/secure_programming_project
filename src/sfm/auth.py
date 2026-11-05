""" auth.py handles tha user authentication (login and register) using argon2id with salt for a secure password storage """

import sqlite3
import hmac

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from . import storage

SALT_SIZE = 16    
ROOT_KEY_SIZE = 32

# Argon2id cost parameters 
ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 262144   # 256 MiB
ARGON2_PARALLELISM = 4
#with this parameters I achieve around 0.3s 

class AuthError(Exception):
    """Raised on registration or login failure (generic)."""

#used to derive the root key, using a salt
def _derive_root_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
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

#create root_key and the relative verifier (used for login) and save into database
#if successfull create also the user vault dir
def register(username: str, password: str) -> None:
    storage.init_users_db()
    db_path = storage.get_users_db_path()

    salt = storage.os.urandom(SALT_SIZE)
    root_key = _derive_root_key(password, salt)
    verifier = _derive(root_key, info=b"sfm-auth-verifier")

    conn = sqlite3.connect(db_path)
    try:
        try:
            conn.execute(
                "INSERT INTO users (username, salt, verifier) VALUES (?, ?, ?)",
                (username, salt, verifier),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise AuthError("registration failed")  # generic
    finally:
        conn.close()

    storage.get_user_dir(username)

#retrieve verifier (if user exists)
def login(username: str, password: str) -> bytes:
    storage.init_users_db()
    db_path = storage.get_users_db_path()
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT salt, verifier FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise AuthError("invalid username or password") 

    salt, stored_verifier = row
    root_key = _derive_root_key(password, salt)
    computed_verifier = _derive(root_key, info=b"sfm-auth-verifier")

    if not hmac.compare_digest(computed_verifier, stored_verifier):
        raise AuthError("invalid username or password")

    kek = _derive(root_key, info=b"sfm-index-kek")
    return kek
