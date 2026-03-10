"""Tests for deadpgp.sign"""

import pytest
from cryptography.exceptions import InvalidSignature

from deadpgp.keys import generate_keypair
from deadpgp.sign import sign, verify


@pytest.fixture(scope="module")
def keypair():
    return generate_keypair(key_size=2048)


class TestSignVerify:
    def test_valid_signature_does_not_raise(self, keypair):
        priv, pub = keypair
        message = b"I, Alice, certify this message."
        sig = sign(message, priv)
        verify(message, sig, pub)  # must not raise

    def test_empty_message(self, keypair):
        priv, pub = keypair
        sig = sign(b"", priv)
        verify(b"", sig, pub)

    def test_large_message(self, keypair):
        priv, pub = keypair
        message = b"x" * 100_000
        sig = sign(message, priv)
        verify(message, sig, pub)

    def test_tampered_message_raises(self, keypair):
        priv, pub = keypair
        message = b"original"
        sig = sign(message, priv)
        with pytest.raises(InvalidSignature):
            verify(b"tampered", sig, pub)

    def test_tampered_signature_raises(self, keypair):
        priv, pub = keypair
        message = b"data"
        sig = bytearray(sign(message, priv))
        sig[-1] ^= 0xFF
        with pytest.raises(Exception):
            verify(message, bytes(sig), pub)

    def test_wrong_key_raises(self, keypair):
        priv, _ = keypair
        _, pub2 = generate_keypair(2048)
        message = b"data"
        sig = sign(message, priv)
        with pytest.raises(InvalidSignature):
            verify(message, sig, pub2)

    def test_truncated_signature_raises(self, keypair):
        priv, pub = keypair
        sig = sign(b"data", priv)
        with pytest.raises(ValueError):
            verify(b"data", sig[:1], pub)

    def test_signature_is_deterministic_length(self, keypair):
        priv, _ = keypair
        sig1 = sign(b"hello", priv)
        sig2 = sign(b"hello", priv)
        assert len(sig1) == len(sig2)
