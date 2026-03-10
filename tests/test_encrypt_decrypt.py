"""Tests for public-key and password encryption/decryption roundtrips."""

import pytest

from deadpgp import keys as _keys
from deadpgp import crypto_box, crypto_pwd
from deadpgp.armor import decode as armor_decode


PLAINTEXT = b"The quick brown fox jumps over the lazy dog."
PASSWORD = "correct horse battery staple"


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def alice_key():
    return _keys.generate_keypair()


@pytest.fixture(scope="module")
def bob_key():
    return _keys.generate_keypair()


# ---------------------------------------------------------------------------
# Public-key mode
# ---------------------------------------------------------------------------


class TestPublicKeyMode:
    def test_encrypt_decrypt_roundtrip(self, alice_key):
        armored = crypto_box.encrypt(PLAINTEXT, alice_key)
        recovered = crypto_box.decrypt(armored, alice_key)
        assert recovered == PLAINTEXT

    def test_armored_output_is_string(self, alice_key):
        armored = crypto_box.encrypt(PLAINTEXT, alice_key)
        assert isinstance(armored, str)

    def test_armored_output_contains_begin_end(self, alice_key):
        armored = crypto_box.encrypt(PLAINTEXT, alice_key)
        assert "-----BEGIN DEADPGP MESSAGE-----" in armored
        assert "-----END DEADPGP MESSAGE-----" in armored

    def test_armored_headers(self, alice_key):
        armored = crypto_box.encrypt(PLAINTEXT, alice_key)
        _, headers, _ = armor_decode(armored)
        assert headers.get("Version") == "1"
        assert headers.get("Mode") == "pubkey"
        assert "EphemeralKey" in headers
        assert "Nonce" in headers

    def test_to_header_matches_recipient_fingerprint(self, alice_key):
        armored = crypto_box.encrypt(PLAINTEXT, alice_key)
        _, headers, _ = armor_decode(armored)
        assert headers.get("To") == alice_key["fingerprint"]

    def test_wrong_key_fails(self, alice_key, bob_key):
        armored = crypto_box.encrypt(PLAINTEXT, alice_key)
        with pytest.raises(ValueError, match="[Dd]ecryption failed"):
            crypto_box.decrypt(armored, bob_key)

    def test_different_ciphertexts_per_call(self, alice_key):
        """Ensure nonce randomness: two encryptions should differ."""
        a1 = crypto_box.encrypt(PLAINTEXT, alice_key)
        a2 = crypto_box.encrypt(PLAINTEXT, alice_key)
        assert a1 != a2

    def test_decrypt_pubkey_msg_with_password_decrypt_raises(self, alice_key):
        armored = crypto_box.encrypt(PLAINTEXT, alice_key)
        with pytest.raises(ValueError):
            crypto_pwd.decrypt(armored, PASSWORD)

    def test_empty_plaintext(self, alice_key):
        armored = crypto_box.encrypt(b"", alice_key)
        assert crypto_box.decrypt(armored, alice_key) == b""

    def test_binary_plaintext(self, alice_key):
        binary = bytes(range(256))
        armored = crypto_box.encrypt(binary, alice_key)
        assert crypto_box.decrypt(armored, alice_key) == binary


# ---------------------------------------------------------------------------
# Password mode
# ---------------------------------------------------------------------------


class TestPasswordMode:
    def test_encrypt_decrypt_roundtrip(self):
        armored = crypto_pwd.encrypt(PLAINTEXT, PASSWORD)
        recovered = crypto_pwd.decrypt(armored, PASSWORD)
        assert recovered == PLAINTEXT

    def test_armored_output_is_string(self):
        armored = crypto_pwd.encrypt(PLAINTEXT, PASSWORD)
        assert isinstance(armored, str)

    def test_armored_output_contains_begin_end(self):
        armored = crypto_pwd.encrypt(PLAINTEXT, PASSWORD)
        assert "-----BEGIN DEADPGP MESSAGE-----" in armored
        assert "-----END DEADPGP MESSAGE-----" in armored

    def test_armored_headers(self):
        armored = crypto_pwd.encrypt(PLAINTEXT, PASSWORD)
        _, headers, _ = armor_decode(armored)
        assert headers.get("Version") == "1"
        mode = headers.get("Mode", "")
        assert mode.startswith("password-")
        assert "Salt" in headers
        assert "Params" in headers
        assert "Nonce" in headers

    def test_wrong_password_fails(self):
        armored = crypto_pwd.encrypt(PLAINTEXT, PASSWORD)
        with pytest.raises(ValueError, match="[Dd]ecryption failed"):
            crypto_pwd.decrypt(armored, "wrong password")

    def test_different_ciphertexts_per_call(self):
        a1 = crypto_pwd.encrypt(PLAINTEXT, PASSWORD)
        a2 = crypto_pwd.encrypt(PLAINTEXT, PASSWORD)
        assert a1 != a2

    def test_decrypt_password_msg_with_pubkey_decrypt_raises(self, alice_key):
        armored = crypto_pwd.encrypt(PLAINTEXT, PASSWORD)
        with pytest.raises(ValueError):
            crypto_box.decrypt(armored, alice_key)

    def test_empty_plaintext(self):
        armored = crypto_pwd.encrypt(b"", PASSWORD)
        assert crypto_pwd.decrypt(armored, PASSWORD) == b""

    def test_binary_plaintext(self):
        binary = bytes(range(256))
        armored = crypto_pwd.encrypt(binary, PASSWORD)
        assert crypto_pwd.decrypt(armored, PASSWORD) == binary

    def test_unicode_password(self):
        pw = "pässwörд 🔐"
        armored = crypto_pwd.encrypt(PLAINTEXT, pw)
        assert crypto_pwd.decrypt(armored, pw) == PLAINTEXT


# ---------------------------------------------------------------------------
# Keys module
# ---------------------------------------------------------------------------


class TestKeys:
    def test_generate_keypair_fields(self):
        kp = _keys.generate_keypair()
        assert "version" in kp
        assert "type" in kp
        assert "fingerprint" in kp
        assert "public_key" in kp
        assert "private_key" in kp

    def test_fingerprint_is_64_hex_chars(self):
        kp = _keys.generate_keypair()
        fp = kp["fingerprint"]
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_two_keypairs_different(self):
        kp1 = _keys.generate_keypair()
        kp2 = _keys.generate_keypair()
        assert kp1["fingerprint"] != kp2["fingerprint"]
        assert kp1["public_key"] != kp2["public_key"]

    def test_save_and_load_private_key(self, tmp_path):
        kp = _keys.generate_keypair()
        path = tmp_path / "test.key"
        _keys.save_private_key(kp, path)
        loaded = _keys.load_key_file(path)
        assert loaded["fingerprint"] == kp["fingerprint"]
        assert loaded["private_key"] == kp["private_key"]

    def test_save_and_load_public_key(self, tmp_path):
        kp = _keys.generate_keypair()
        path = tmp_path / "test.pub"
        _keys.save_public_key(kp, path)
        loaded = _keys.load_key_file(path)
        assert loaded["fingerprint"] == kp["fingerprint"]
        assert "private_key" not in loaded

    def test_load_key_missing_field_raises(self, tmp_path):
        import json
        bad_key = {"version": 1, "type": "x25519"}  # missing fingerprint and public_key
        path = tmp_path / "bad.key"
        path.write_text(json.dumps(bad_key))
        with pytest.raises(_keys.KeyFileError, match="missing field"):
            _keys.load_key_file(path)

    def test_private_key_from_data_no_private_key_raises(self):
        kp = _keys.generate_keypair()
        pub_only = {k: v for k, v in kp.items() if k != "private_key"}
        with pytest.raises(_keys.KeyFileError, match="private key"):
            _keys.private_key_from_data(pub_only)
