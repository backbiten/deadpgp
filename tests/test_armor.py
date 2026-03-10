"""Tests for deadpgp.armor"""

import pytest

from deadpgp.armor import armor, dearmor, _crc24


class TestCRC24:
    def test_known_value(self):
        # CRC-24 of the empty string must equal the init value
        assert _crc24(b"") == 0xB704CE

    def test_consistent(self):
        data = b"Hello, world!"
        assert _crc24(data) == _crc24(data)

    def test_different_data_different_crc(self):
        assert _crc24(b"abc") != _crc24(b"abd")


class TestArmorDearmor:
    def test_roundtrip_message(self):
        data = b"\x00\x01\x02" * 100
        armored = armor(data, "MESSAGE")
        recovered, armor_type = dearmor(armored)
        assert recovered == data
        assert armor_type == "MESSAGE"

    def test_roundtrip_signature(self):
        data = b"sig bytes"
        armored = armor(data, "SIGNATURE")
        recovered, armor_type = dearmor(armored)
        assert recovered == data
        assert armor_type == "SIGNATURE"

    def test_roundtrip_public_key(self):
        data = b"-----BEGIN PUBLIC KEY-----\nfakedata\n-----END PUBLIC KEY-----\n"
        armored = armor(data, "PUBLIC KEY")
        recovered, armor_type = dearmor(armored)
        assert recovered == data
        assert armor_type == "PUBLIC KEY"

    def test_header_format(self):
        armored = armor(b"data", "MESSAGE")
        assert armored.startswith("-----BEGIN DEADPGP MESSAGE-----")
        assert "-----END DEADPGP MESSAGE-----" in armored

    def test_body_line_length(self):
        # Lines in the base64 body must be at most 76 chars
        armored = armor(bytes(range(256)), "MESSAGE")
        lines = armored.splitlines()
        body_lines = [
            l for l in lines
            if l and not l.startswith("-----") and not l.startswith("=")
        ]
        for line in body_lines:
            assert len(line) <= 76, f"Line too long: {line!r}"

    def test_default_type_is_message(self):
        armored = armor(b"x")
        _, t = dearmor(armored)
        assert t == "MESSAGE"

    def test_empty_data_roundtrip(self):
        armored = armor(b"", "MESSAGE")
        recovered, _ = dearmor(armored)
        assert recovered == b""

    def test_dearmor_crc_mismatch_raises(self):
        data = b"hello"
        armored = armor(data, "MESSAGE")
        lines = armored.splitlines()
        # Corrupt the CRC line
        corrupted = "\n".join(
            ("=AAAA" if l.startswith("=") else l) for l in lines
        ) + "\n"
        with pytest.raises(ValueError, match="CRC"):
            dearmor(corrupted)

    def test_dearmor_missing_header_raises(self):
        with pytest.raises(ValueError, match="header"):
            dearmor("no armor here")

    def test_dearmor_missing_footer_raises(self):
        with pytest.raises(ValueError, match="footer"):
            dearmor("-----BEGIN DEADPGP MESSAGE-----\nYWJj\n")

    def test_dearmor_type_mismatch_raises(self):
        armored = armor(b"x", "MESSAGE")
        corrupted = armored.replace(
            "-----END DEADPGP MESSAGE-----",
            "-----END DEADPGP SIGNATURE-----",
        )
        with pytest.raises(ValueError, match="mismatch"):
            dearmor(corrupted)
