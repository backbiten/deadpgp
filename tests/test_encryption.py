"""Tests for deadpgp.encryption – hybrid encrypt/decrypt."""

import pytest

from deadpgp.keys import (
    generate_rsa_keypair,
    generate_ec_keypair,
    generate_x25519_keypair,
)
from deadpgp.encryption import encrypt, decrypt

PLAINTEXT = b"Hello from the 21st century!"


class TestRSAEncryption:
    @pytest.fixture(scope="class")
    def keypair(self):
        return generate_rsa_keypair(2048)

    def test_roundtrip(self, keypair):
        priv, pub = keypair
        ct = encrypt(PLAINTEXT, pub)
        assert decrypt(ct, priv) == PLAINTEXT

    def test_different_ciphertexts(self, keypair):
        _, pub = keypair
        ct1 = encrypt(PLAINTEXT, pub)
        ct2 = encrypt(PLAINTEXT, pub)
        assert ct1 != ct2  # Nonce and/or session key differ

    def test_empty_plaintext(self, keypair):
        priv, pub = keypair
        ct = encrypt(b"", pub)
        assert decrypt(ct, priv) == b""

    def test_large_plaintext(self, keypair):
        priv, pub = keypair
        large = b"x" * (1024 * 1024)  # 1 MiB
        ct = encrypt(large, pub)
        assert decrypt(ct, priv) == large

    def test_wrong_key_fails(self, keypair):
        _, pub = keypair
        other_priv, _ = generate_rsa_keypair(2048)
        ct = encrypt(PLAINTEXT, pub)
        with pytest.raises((ValueError, Exception)):
            decrypt(ct, other_priv)

    def test_tampered_ciphertext_fails(self, keypair):
        priv, pub = keypair
        ct = bytearray(encrypt(PLAINTEXT, pub))
        ct[-1] ^= 0xFF
        with pytest.raises((ValueError, Exception)):
            decrypt(bytes(ct), priv)


class TestECEncryption:
    @pytest.mark.parametrize("curve", ["secp256r1", "secp384r1", "secp521r1"])
    def test_roundtrip(self, curve):
        priv, pub = generate_ec_keypair(curve)
        ct = encrypt(PLAINTEXT, pub)
        assert decrypt(ct, priv) == PLAINTEXT

    def test_wrong_key_fails(self):
        priv, pub = generate_ec_keypair()
        other_priv, _ = generate_ec_keypair()
        ct = encrypt(PLAINTEXT, pub)
        with pytest.raises((ValueError, Exception)):
            decrypt(ct, other_priv)


class TestX25519Encryption:
    @pytest.fixture(scope="class")
    def keypair(self):
        return generate_x25519_keypair()

    def test_roundtrip(self, keypair):
        priv, pub = keypair
        ct = encrypt(PLAINTEXT, pub)
        assert decrypt(ct, priv) == PLAINTEXT

    def test_wrong_key_fails(self, keypair):
        _, pub = keypair
        other_priv, _ = generate_x25519_keypair()
        ct = encrypt(PLAINTEXT, pub)
        with pytest.raises((ValueError, Exception)):
            decrypt(ct, other_priv)


class TestTypeErrors:
    def test_encrypt_unsupported_key(self):
        with pytest.raises(TypeError, match="Unsupported public key type"):
            encrypt(b"data", object())

    def test_decrypt_unsupported_key(self):
        with pytest.raises(TypeError, match="Unsupported private key type"):
            decrypt(b"data", object())
