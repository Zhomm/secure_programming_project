"""Encryption/decryption correctness tests for crypto.py (AES-256-GCM).

Run from the project root:  pytest tests/test_crypto.py -v
"""

import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sfm import crypto

KEY = bytes(range(32))


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 255, 4096, 1024 * 1024 + 3])
def test_round_trip_for_many_sizes(size):
    data = os.urandom(size)
    assert crypto.decrypt_bytes(KEY, crypto.encrypt_bytes(KEY, data)) == data


def test_output_layout_is_nonce_then_ciphertext_and_tag():
    data = b"hello world"
    blob = crypto.encrypt_bytes(KEY, data, b"aad")
    assert len(blob) == crypto.NONCE_SIZE + len(data) + 16          # 12-byte nonce + data + 16-byte tag
    nonce, rest = blob[:12], blob[12:]
    assert AESGCM(KEY).decrypt(nonce, rest, b"aad") == data         # standard AES-GCM, nothing custom


def test_plaintext_does_not_appear_in_the_ciphertext():
    data = b"TOP-SECRET-MARKER-" * 10
    assert b"TOP-SECRET-MARKER" not in crypto.encrypt_bytes(KEY, data)


def test_every_encryption_uses_a_fresh_nonce():
    nonces = {crypto.encrypt_bytes(KEY, b"same")[:12] for _ in range(2000)}
    assert len(nonces) == 2000


def test_same_plaintext_gives_different_ciphertexts():
    assert crypto.encrypt_bytes(KEY, b"same") != crypto.encrypt_bytes(KEY, b"same")


def test_wrong_key_is_rejected():
    blob = crypto.encrypt_bytes(KEY, b"data")
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_bytes(bytes(32), blob)


def test_round_trip_with_the_right_associated_data():
    aad = b"sfm-blob|alice|1"
    blob = crypto.encrypt_bytes(KEY, b"data", aad)
    assert crypto.decrypt_bytes(KEY, blob, aad) == b"data"


def test_wrong_associated_data_is_rejected():
    blob = crypto.encrypt_bytes(KEY, b"data", b"sfm-blob|alice|1")
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_bytes(KEY, blob, b"sfm-blob|bob|1")
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_bytes(KEY, blob, b"sfm-blob|alice|2")
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_bytes(KEY, blob)                             # AAD missing


@pytest.mark.parametrize("where", ["nonce", "body", "tag"])
def test_any_flipped_bit_is_detected(where):
    blob = bytearray(crypto.encrypt_bytes(KEY, b"some data to protect"))
    index = {"nonce": 0, "body": 12, "tag": len(blob) - 1}[where]
    blob[index] ^= 0x01
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_bytes(KEY, bytes(blob))


def test_every_single_byte_change_is_detected():
    blob = crypto.encrypt_bytes(KEY, b"0123456789")
    for i in range(len(blob)):
        damaged = bytearray(blob)
        damaged[i] ^= 0xFF
        with pytest.raises(crypto.DecryptionError):
            crypto.decrypt_bytes(KEY, bytes(damaged))


def test_truncation_and_extension_are_detected():
    blob = crypto.encrypt_bytes(KEY, b"data to protect")
    for damaged in (blob[:-1], blob[:-16], blob + b"\x00"):
        with pytest.raises(crypto.DecryptionError):
            crypto.decrypt_bytes(KEY, damaged)


@pytest.mark.parametrize("short", [b"", b"x", b"x" * 11])
def test_input_shorter_than_a_nonce_is_rejected(short):
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_bytes(KEY, short)


@pytest.mark.parametrize("bad_key", [b"", b"short", bytes(16), bytes(24), bytes(33)])
def test_only_256_bit_keys_are_accepted(bad_key):
    with pytest.raises(ValueError):
        crypto.encrypt_bytes(bad_key, b"x")
    with pytest.raises(ValueError):
        crypto.decrypt_bytes(bad_key, bytes(40))


def test_generated_keys_are_32_random_bytes():
    keys = {crypto.generate_key() for _ in range(100)}
    assert len(keys) == 100
    assert all(len(k) == 32 for k in keys)


def test_a_wipeable_bytearray_key_works():
    key = bytearray(KEY)
    assert crypto.decrypt_bytes(key, crypto.encrypt_bytes(key, b"x")) == b"x"
