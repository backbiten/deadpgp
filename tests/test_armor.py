"""Tests for deadpgp.armor – ASCII-armor encode/decode."""

import pytest

from deadpgp.armor import (
    armor,
    dearmor,
    ARMOR_MESSAGE,
    ARMOR_PUBLIC_KEY,
    ARMOR_PRIVATE_KEY,
    ARMOR_SIGNATURE,
)


SAMPLE_DATA = b"\x00\x01\x02\x03" + b"Hello, armor!" + bytes(range(200))


class TestArmor:
    @pytest.mark.parametrize(
        "armor_type",
        [ARMOR_MESSAGE, ARMOR_PUBLIC_KEY, ARMOR_PRIVATE_KEY, ARMOR_SIGNATURE],
    )
    def test_roundtrip(self, armor_type):
        armored = armor(SAMPLE_DATA, armor_type)
        data, typ = dearmor(armored)
        assert data == SAMPLE_DATA
        assert typ == armor_type

    def test_header_present(self):
        armored = armor(SAMPLE_DATA, ARMOR_MESSAGE)
        assert "-----BEGIN DEADPGP MESSAGE-----" in armored

    def test_footer_present(self):
        armored = armor(SAMPLE_DATA, ARMOR_MESSAGE)
        assert "-----END DEADPGP MESSAGE-----" in armored

    def test_checksum_line_present(self):
        armored = armor(SAMPLE_DATA, ARMOR_MESSAGE)
        lines = armored.splitlines()
        assert any(line.startswith("=") for line in lines)

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError, match="Unknown armor type"):
            armor(SAMPLE_DATA, "UNKNOWN")

    def test_empty_data(self):
        armored = armor(b"", ARMOR_MESSAGE)
        data, _ = dearmor(armored)
        assert data == b""

    def test_large_data(self):
        large = bytes(range(256)) * 400  # ~100 KiB
        armored = armor(large, ARMOR_MESSAGE)
        data, _ = dearmor(armored)
        assert data == large


class TestDearmor:
    def test_missing_header_raises(self):
        with pytest.raises(ValueError, match="Missing or malformed armor header"):
            dearmor("garbage\n=AAAA\n-----END DEADPGP MESSAGE-----")

    def test_missing_footer_raises(self):
        armored = armor(SAMPLE_DATA, ARMOR_MESSAGE)
        lines = armored.splitlines()
        truncated = "\n".join(lines[:-1])
        with pytest.raises(ValueError):
            dearmor(truncated)

    def test_corrupted_checksum_raises(self):
        armored = armor(SAMPLE_DATA, ARMOR_MESSAGE)
        # Find and replace the checksum line (starts with "=", not part of base64 padding)
        lines = armored.splitlines()
        corrupted_lines = []
        for line in lines:
            # The checksum line is a standalone line starting with "=" followed by 4 chars
            if line.startswith("=") and len(line) == 5:
                corrupted_lines.append("=ZZZZ")
            else:
                corrupted_lines.append(line)
        corrupted = "\n".join(corrupted_lines)
        with pytest.raises(ValueError, match="CRC-24 mismatch"):
            dearmor(corrupted)

    def test_corrupted_body_raises(self):
        armored = armor(SAMPLE_DATA, ARMOR_MESSAGE)
        lines = armored.splitlines()
        # Flip a character in the body (line 1)
        body_line = lines[1]
        flipped = body_line[:-1] + ("A" if body_line[-1] != "A" else "B")
        lines[1] = flipped
        corrupted = "\n".join(lines)
        with pytest.raises(ValueError):
            dearmor(corrupted)
