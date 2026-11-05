"""Encryption and decryption with AES-256-GCM """

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12   # 96 bit, standard for GCM
KEY_SIZE = 32     # 256 bit


class DecryptionError(Exception):
    """Raised when ciphertext fails authentication (tampered data/wrong key)."""


#generate random 256 bit string
def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)

#encrypt with AES-256-GCM, return nonce(12 bytes) + ciphertext
def encrypt_bytes(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError("key must be 32 bytes (256 bits)")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def decrypt_bytes(key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError("key must be 32 bytes (256 bits)")
    if len(data) < NONCE_SIZE:
        raise DecryptionError("ciphertext too short")

    nonce, ciphertext = data[:NONCE_SIZE], data[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise DecryptionError("authentication failed: wrong key or tampered data")
