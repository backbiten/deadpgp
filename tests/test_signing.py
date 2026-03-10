"""Tests for deadpgp.signing – digital signatures."""

import pytest

from deadpgp.keys import (
    generate_rsa_keypair,
    generate_ec_keypair,
    generate_ed25519_keypair,
)
from deadpgp.signing import sign, verify

MESSAGE = b"Sign me with modern crypto!"


class TestRSASigning:
    @pytest.fixture(scope="class")
    def keypair(self):
        return generate_rsa_keypair(2048)

    def test_sign_and_verify(self, keypair):
        priv, pub = keypair
        sig = sign(MESSAGE, priv)
        assert verify(MESSAGE, sig, pub) is True

    def test_tampered_message_fails(self, keypair):
        priv, pub = keypair
        sig = sign(MESSAGE, priv)
        assert verify(MESSAGE + b"!", sig, pub) is False

    def test_tampered_signature_fails(self, keypair):
        priv, pub = keypair
        sig = bytearray(sign(MESSAGE, priv))
        sig[0] ^= 0xFF
        assert verify(MESSAGE, bytes(sig), pub) is False

    def test_wrong_key_fails(self, keypair):
        priv, _ = keypair
        _, other_pub = generate_rsa_keypair(2048)
        sig = sign(MESSAGE, priv)
        assert verify(MESSAGE, sig, other_pub) is False


class TestECSigning:
    @pytest.mark.parametrize("curve", ["secp256r1", "secp384r1", "secp521r1"])
    def test_sign_and_verify(self, curve):
        priv, pub = generate_ec_keypair(curve)
        sig = sign(MESSAGE, priv)
        assert verify(MESSAGE, sig, pub) is True

    def test_tampered_message_fails(self):
        priv, pub = generate_ec_keypair()
        sig = sign(MESSAGE, priv)
        assert verify(b"different message", sig, pub) is False


class TestEd25519Signing:
    @pytest.fixture(scope="class")
    def keypair(self):
        return generate_ed25519_keypair()

    def test_sign_and_verify(self, keypair):
        priv, pub = keypair
        sig = sign(MESSAGE, priv)
        assert verify(MESSAGE, sig, pub) is True

    def test_tampered_message_fails(self, keypair):
        priv, pub = keypair
        sig = sign(MESSAGE, priv)
        assert verify(MESSAGE + b"x", sig, pub) is False

    def test_empty_message(self, keypair):
        priv, pub = keypair
        sig = sign(b"", priv)
        assert verify(b"", sig, pub) is True


class TestTypeErrors:
    def test_sign_unsupported_key(self):
        with pytest.raises(TypeError, match="Unsupported private key type"):
            sign(b"data", object())

    def test_verify_unsupported_key(self):
        with pytest.raises(TypeError, match="Unsupported public key type"):
            verify(b"data", b"sig", object())
