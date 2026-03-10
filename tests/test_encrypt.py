"""Tests for deadpgp.encrypt"""

import pytest
from cryptography.exceptions import InvalidTag

from deadpgp.keys import generate_keypair
from deadpgp.encrypt import encrypt, decrypt


@pytest.fixture(scope="module")
def keypair():
    return generate_keypair(key_size=2048)


class TestEncryptDecrypt:
    def test_roundtrip_short_message(self, keypair):
        priv, pub = keypair
        plaintext = b"Hello, deadpgp!"
        ciphertext = encrypt(plaintext, pub)
        assert decrypt(ciphertext, priv) == plaintext

    def test_roundtrip_empty_message(self, keypair):
        priv, pub = keypair
        plaintext = b""
        ciphertext = encrypt(plaintext, pub)
        assert decrypt(ciphertext, priv) == plaintext

    def test_roundtrip_binary_data(self, keypair):
        priv, pub = keypair
        plaintext = bytes(range(256)) * 100
        ciphertext = encrypt(plaintext, pub)
        assert decrypt(ciphertext, priv) == plaintext

    def test_ciphertext_differs_from_plaintext(self, keypair):
        _, pub = keypair
        plaintext = b"secret"
        ciphertext = encrypt(plaintext, pub)
        assert ciphertext != plaintext

    def test_two_encryptions_of_same_plaintext_differ(self, keypair):
        _, pub = keypair
        plaintext = b"same plaintext"
        ct1 = encrypt(plaintext, pub)
        ct2 = encrypt(plaintext, pub)
        assert ct1 != ct2

    def test_decrypt_with_wrong_key_raises(self):
        _, pub1 = generate_keypair(2048)
        priv2, _ = generate_keypair(2048)
        ciphertext = encrypt(b"secret", pub1)
        with pytest.raises(Exception):
            decrypt(ciphertext, priv2)

    def test_decrypt_truncated_blob_raises(self, keypair):
        priv, pub = keypair
        ciphertext = encrypt(b"data", pub)
        with pytest.raises(ValueError):
            decrypt(ciphertext[:2], priv)

    def test_decrypt_tampered_ciphertext_raises(self, keypair):
        priv, pub = keypair
        ciphertext = bytearray(encrypt(b"data", pub))
        ciphertext[-1] ^= 0xFF
        with pytest.raises(Exception):
            decrypt(bytes(ciphertext), priv)
