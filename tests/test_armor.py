"""Tests for armor encoding / decoding."""

import pytest

from deadpgp.armor import (
    ArmorError,
    b64,
    b64d,
    decode,
    encode,
    find_blocks,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_LABEL = "DEADPGP MESSAGE"
SAMPLE_HEADERS = {
    "Version": "1",
    "Mode": "pubkey",
    "To": "abcdef1234567890",
    "Nonce": b64(b"\x00" * 12),
}
SAMPLE_PAYLOAD = b"hello deadpgp"


# ---------------------------------------------------------------------------
# encode / decode roundtrip
# ---------------------------------------------------------------------------


class TestEncodeDecode:
    def test_roundtrip_with_payload(self):
        armored = encode(SAMPLE_LABEL, SAMPLE_HEADERS, SAMPLE_PAYLOAD)
        label, headers, payload = decode(armored)

        assert label == SAMPLE_LABEL
        assert headers == SAMPLE_HEADERS
        assert payload == SAMPLE_PAYLOAD

    def test_roundtrip_no_payload(self):
        armored = encode(SAMPLE_LABEL, SAMPLE_HEADERS, b"")
        label, headers, payload = decode(armored)

        assert label == SAMPLE_LABEL
        assert headers == SAMPLE_HEADERS
        assert payload == b""

    def test_begin_end_lines_present(self):
        armored = encode(SAMPLE_LABEL, SAMPLE_HEADERS, SAMPLE_PAYLOAD)
        assert armored.startswith(f"-----BEGIN {SAMPLE_LABEL}-----")
        assert f"-----END {SAMPLE_LABEL}-----" in armored

    def test_headers_in_output(self):
        armored = encode(SAMPLE_LABEL, SAMPLE_HEADERS, SAMPLE_PAYLOAD)
        assert "Version: 1" in armored
        assert "Mode: pubkey" in armored

    def test_extra_whitespace_lines_before_block(self):
        """decode should find the block even with leading text."""
        armored = encode(SAMPLE_LABEL, SAMPLE_HEADERS, SAMPLE_PAYLOAD)
        text = "Some email preamble\n\n" + armored + "\nSome footer text"
        label, headers, payload = decode(text)
        assert label == SAMPLE_LABEL
        assert payload == SAMPLE_PAYLOAD


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestDecodeErrors:
    def test_no_begin_line(self):
        with pytest.raises(ArmorError, match="No '-----BEGIN"):
            decode("random text without armor")

    def test_mismatched_labels(self):
        armored = encode(SAMPLE_LABEL, SAMPLE_HEADERS, SAMPLE_PAYLOAD)
        bad = armored.replace(
            f"-----END {SAMPLE_LABEL}-----",
            "-----END DEADPGP WRONG LABEL-----",
        )
        with pytest.raises(ArmorError, match="does not match"):
            decode(bad)

    def test_no_end_line(self):
        armored = encode(SAMPLE_LABEL, SAMPLE_HEADERS, SAMPLE_PAYLOAD)
        # Remove the END line
        lines = armored.splitlines()
        truncated = "\n".join(line for line in lines if "END" not in line)
        with pytest.raises(ArmorError, match="No '-----END"):
            decode(truncated)


# ---------------------------------------------------------------------------
# find_blocks
# ---------------------------------------------------------------------------


class TestFindBlocks:
    def test_single_block(self):
        armored = encode(SAMPLE_LABEL, SAMPLE_HEADERS, SAMPLE_PAYLOAD)
        blocks = find_blocks(armored)
        assert len(blocks) == 1

    def test_multiple_blocks(self):
        block1 = encode(SAMPLE_LABEL, SAMPLE_HEADERS, b"msg1")
        block2 = encode(SAMPLE_LABEL, SAMPLE_HEADERS, b"msg2")
        combined = block1 + "\nSome text in between\n" + block2
        blocks = find_blocks(combined)
        assert len(blocks) == 2

    def test_no_blocks(self):
        assert find_blocks("no armor here") == []

    def test_block_content_parses(self):
        armored = encode(SAMPLE_LABEL, SAMPLE_HEADERS, SAMPLE_PAYLOAD)
        blocks = find_blocks(armored)
        _, _, payload = decode(blocks[0])
        assert payload == SAMPLE_PAYLOAD


# ---------------------------------------------------------------------------
# b64 helpers
# ---------------------------------------------------------------------------


class TestB64Helpers:
    def test_roundtrip(self):
        data = b"\x00\x01\x02\xff"
        assert b64d(b64(data)) == data

    def test_empty(self):
        assert b64d(b64(b"")) == b""
