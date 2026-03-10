"""Tests for deadpgp.keys"""

import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from deadpgp.keys import (
    generate_keypair,
    export_private_key,
    export_public_key,
    load_private_key,
    load_public_key,
)


class TestGenerateKeypair:
    def test_returns_private_and_public_key(self):
        priv, pub = generate_keypair(key_size=2048)
        assert isinstance(priv, RSAPrivateKey)
        assert isinstance(pub, RSAPublicKey)

    def test_default_key_size_is_4096(self):
        priv, _ = generate_keypair()
        assert priv.key_size == 4096

    def test_custom_key_size(self):
        priv, _ = generate_keypair(key_size=2048)
        assert priv.key_size == 2048

    def test_rejects_key_size_below_2048(self):
        with pytest.raises(ValueError, match="2048"):
            generate_keypair(key_size=1024)

    def test_each_call_produces_unique_keys(self):
        _, pub1 = generate_keypair(2048)
        _, pub2 = generate_keypair(2048)
        assert export_public_key(pub1) != export_public_key(pub2)


class TestExportLoadRoundtrip:
    def setup_method(self):
        self.priv, self.pub = generate_keypair(key_size=2048)

    def test_public_key_roundtrip(self):
        pem = export_public_key(self.pub)
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
        reloaded = load_public_key(pem)
        assert export_public_key(reloaded) == pem

    def test_private_key_roundtrip_no_password(self):
        pem = export_private_key(self.priv)
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        reloaded = load_private_key(pem)
        assert export_private_key(reloaded) == pem

    def test_private_key_roundtrip_with_password(self):
        password = b"super-secret"
        pem = export_private_key(self.priv, password=password)
        assert b"ENCRYPTED" in pem
        reloaded = load_private_key(pem, password=password)
        assert export_public_key(reloaded.public_key()) == export_public_key(self.pub)

    def test_private_key_wrong_password_raises(self):
        pem = export_private_key(self.priv, password=b"correct")
        with pytest.raises(Exception):
            load_private_key(pem, password=b"wrong")
