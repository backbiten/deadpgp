"""Tests for deadpgp.keys – key generation and serialisation."""

import pytest

from deadpgp.keys import (
    generate_rsa_keypair,
    generate_ec_keypair,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    serialize_private_key,
    serialize_public_key,
    load_private_key,
    load_public_key,
)


class TestRSAKeypair:
    def test_default_size(self):
        priv, pub = generate_rsa_keypair()
        assert priv.key_size == 4096

    def test_custom_size(self):
        priv, pub = generate_rsa_keypair(2048)
        assert priv.key_size == 2048

    def test_minimum_size_enforced(self):
        with pytest.raises(ValueError, match="2048"):
            generate_rsa_keypair(1024)

    def test_public_key_matches(self):
        priv, pub = generate_rsa_keypair(2048)
        assert priv.public_key().public_numbers() == pub.public_numbers()


class TestECKeypair:
    @pytest.mark.parametrize("curve", ["secp256r1", "secp384r1", "secp521r1"])
    def test_supported_curves(self, curve):
        priv, pub = generate_ec_keypair(curve)
        assert priv.curve.name == curve

    def test_unsupported_curve(self):
        with pytest.raises(ValueError, match="Unsupported curve"):
            generate_ec_keypair("secp192r1")

    def test_default_curve(self):
        priv, pub = generate_ec_keypair()
        assert priv.curve.name == "secp256r1"


class TestEd25519Keypair:
    def test_generation(self):
        priv, pub = generate_ed25519_keypair()
        # Round-trip serialisation confirms correct type
        pem = serialize_private_key(priv)
        loaded = load_private_key(pem)
        assert serialize_private_key(loaded) == pem


class TestX25519Keypair:
    def test_generation(self):
        priv, pub = generate_x25519_keypair()
        pem = serialize_private_key(priv)
        loaded = load_private_key(pem)
        assert serialize_private_key(loaded) == pem


class TestSerialisation:
    def test_rsa_roundtrip_no_password(self):
        priv, pub = generate_rsa_keypair(2048)
        priv_pem = serialize_private_key(priv)
        pub_pem = serialize_public_key(pub)

        loaded_priv = load_private_key(priv_pem)
        loaded_pub = load_public_key(pub_pem)

        assert loaded_priv.private_numbers() == priv.private_numbers()
        assert loaded_pub.public_numbers() == pub.public_numbers()

    def test_rsa_roundtrip_with_password(self):
        priv, _ = generate_rsa_keypair(2048)
        password = b"s3cr3t!"
        priv_pem = serialize_private_key(priv, password=password)

        # Should fail without password
        with pytest.raises(ValueError):
            load_private_key(priv_pem, password=None)

        # Should succeed with correct password
        loaded = load_private_key(priv_pem, password=password)
        assert loaded.private_numbers() == priv.private_numbers()

    def test_private_pem_header(self):
        priv, _ = generate_rsa_keypair(2048)
        pem = serialize_private_key(priv)
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_public_pem_header(self):
        _, pub = generate_rsa_keypair(2048)
        pem = serialize_public_key(pub)
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_load_invalid_data(self):
        with pytest.raises(ValueError):
            load_private_key(b"not a pem")

    def test_load_invalid_public_data(self):
        with pytest.raises(ValueError):
            load_public_key(b"garbage")
