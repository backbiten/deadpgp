"""
ASCII Armor encoding and decoding for deadpgp.

Classic PGP introduced "ASCII armor" so that binary encrypted data could be
safely transmitted through systems that only handled printable text (e-mail,
newsgroups, …).  The format wraps base64-encoded data with a header and footer
banner and appends a CRC-24 checksum.

This module implements the same design described in RFC 4880 §6.

Armor type header values
------------------------
``MESSAGE``        – encrypted message (output of :func:`~deadpgp.encrypt.encrypt`)
``SIGNATURE``      – detached signature (output of :func:`~deadpgp.sign.sign`)
``PUBLIC KEY``     – exported public key
``PRIVATE KEY``    – exported private key
``SIGNED MESSAGE`` – cleartext + signature (produced by :func:`armor_signed`)
"""

from __future__ import annotations

import base64
import re
import struct
from typing import Tuple


# ---------------------------------------------------------------------------
# CRC-24 (as specified in RFC 4880 §6.1)
# ---------------------------------------------------------------------------

_CRC24_INIT = 0xB704CE
_CRC24_POLY = 0x1864CFB


def _crc24(data: bytes) -> int:
    crc = _CRC24_INIT
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= _CRC24_POLY
    return crc & 0xFFFFFF


def _crc24_b64(data: bytes) -> str:
    crc = _crc24(data)
    return base64.b64encode(struct.pack(">I", crc)[1:]).decode()


# ---------------------------------------------------------------------------
# Armor / dearmor
# ---------------------------------------------------------------------------

def armor(data: bytes, armor_type: str = "MESSAGE") -> str:
    """Encode *data* as an ASCII-armored block.

    Parameters
    ----------
    data:
        Raw binary data to encode.
    armor_type:
        One of ``"MESSAGE"``, ``"SIGNATURE"``, ``"PUBLIC KEY"``,
        ``"PRIVATE KEY"``.  Defaults to ``"MESSAGE"``.

    Returns
    -------
    str
        The ASCII-armored text including header, body, CRC line, and footer.
    """
    armor_type = armor_type.upper()
    b64 = base64.b64encode(data).decode()
    # Split into 76-character lines (RFC 4880 §6.3)
    lines = [b64[i : i + 76] for i in range(0, len(b64), 76)]
    crc_line = f"={_crc24_b64(data)}"
    body = "\n".join(lines)
    return (
        f"-----BEGIN DEADPGP {armor_type}-----\n"
        f"\n"
        f"{body}\n"
        f"{crc_line}\n"
        f"-----END DEADPGP {armor_type}-----\n"
    )


def dearmor(armored_text: str) -> Tuple[bytes, str]:
    """Decode an ASCII-armored block produced by :func:`armor`.

    Parameters
    ----------
    armored_text:
        The full armored block as a string.

    Returns
    -------
    (data, armor_type)
        The decoded binary *data* and the *armor_type* string extracted from
        the header (e.g. ``"MESSAGE"``).

    Raises
    ------
    ValueError
        If the block is malformed, the header/footer are mismatched, or the
        CRC-24 checksum does not match.
    """
    lines = armored_text.strip().splitlines()

    # Locate header and footer
    header_re = re.compile(r"^-----BEGIN DEADPGP (.+)-----$")
    footer_re = re.compile(r"^-----END DEADPGP (.+)-----$")

    header_idx = footer_idx = -1
    armor_type_from_header = armor_type_from_footer = ""

    for i, line in enumerate(lines):
        hm = header_re.match(line)
        if hm and header_idx == -1:
            header_idx = i
            armor_type_from_header = hm.group(1)
            continue
        fm = footer_re.match(line)
        if fm:
            footer_idx = i
            armor_type_from_footer = fm.group(1)

    if header_idx == -1:
        raise ValueError("No armored header found")
    if footer_idx == -1:
        raise ValueError("No armored footer found")
    if armor_type_from_header != armor_type_from_footer:
        raise ValueError(
            f"Header/footer type mismatch: {armor_type_from_header!r} vs "
            f"{armor_type_from_footer!r}"
        )

    # Lines between header+1 (skip blank line) and footer
    inner = lines[header_idx + 1 : footer_idx]

    # Separate CRC line (starts with '='); it is the last non-empty inner line
    if not inner or not inner[-1].startswith("="):
        raise ValueError("CRC line not found in armored block")

    crc_line = inner[-1]
    body_lines = [l for l in inner if not l.startswith("=") and l != ""]

    b64_data = "".join(body_lines)
    data = base64.b64decode(b64_data)

    # Verify CRC-24
    expected_crc = _crc24_b64(data)
    actual_crc = crc_line[1:]  # strip leading '='
    if actual_crc != expected_crc:
        raise ValueError(
            f"CRC-24 mismatch: expected ={expected_crc}, got ={actual_crc}"
        )

    return data, armor_type_from_header
