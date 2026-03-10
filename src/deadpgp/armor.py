"""ASCII-armor encoding/decoding for deadpgp.

Mirrors the PGP ASCII-armor format (RFC 4880 §6) but uses a simplified
header set appropriate for deadpgp messages.

Header lines
------------
``-----BEGIN DEADPGP <TYPE>-----``
``-----END DEADPGP <TYPE>-----``

*TYPE* is one of: ``MESSAGE``, ``PUBLIC KEY``, ``PRIVATE KEY``, ``SIGNATURE``.

The body is standard Base64 (RFC 4648) with a CRC-24 checksum appended on its
own line, prefixed with ``=`` (same as GPG).
"""

from __future__ import annotations

import base64
import re
import struct


# ---------------------------------------------------------------------------
# CRC-24 (same polynomial as RFC 4880)
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


def _crc24_str(data: bytes) -> str:
    crc = _crc24(data)
    crc_bytes = struct.pack(">I", crc)[1:]  # 3 bytes big-endian
    return base64.b64encode(crc_bytes).decode("ascii")


# ---------------------------------------------------------------------------
# Armor types
# ---------------------------------------------------------------------------

ARMOR_MESSAGE = "MESSAGE"
ARMOR_PUBLIC_KEY = "PUBLIC KEY"
ARMOR_PRIVATE_KEY = "PRIVATE KEY"
ARMOR_SIGNATURE = "SIGNATURE"

_VALID_TYPES = {ARMOR_MESSAGE, ARMOR_PUBLIC_KEY, ARMOR_PRIVATE_KEY, ARMOR_SIGNATURE}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def armor(data: bytes, armor_type: str) -> str:
    """Encode *data* as an ASCII-armored string.

    Parameters
    ----------
    data:
        Raw bytes to encode.
    armor_type:
        One of the ``ARMOR_*`` constants defined in this module.

    Returns
    -------
    Armored string including header, Base64 body, checksum, and footer.

    Raises
    ------
    ValueError
        If *armor_type* is not recognised.
    """
    if armor_type not in _VALID_TYPES:
        raise ValueError(
            f"Unknown armor type '{armor_type}'. "
            f"Expected one of: {', '.join(sorted(_VALID_TYPES))}"
        )
    body = base64.b64encode(data).decode("ascii")
    # Wrap at 76 characters per line (PGP convention)
    wrapped = "\n".join(body[i : i + 76] for i in range(0, len(body), 76))
    checksum = _crc24_str(data)
    return (
        f"-----BEGIN DEADPGP {armor_type}-----\n"
        f"{wrapped}\n"
        f"={checksum}\n"
        f"-----END DEADPGP {armor_type}-----"
    )


def dearmor(armored: str) -> tuple[bytes, str]:
    """Decode an ASCII-armored string.

    Parameters
    ----------
    armored:
        String previously produced by :func:`armor`.

    Returns
    -------
    ``(data_bytes, armor_type)``

    Raises
    ------
    ValueError
        If the armor is malformed or the checksum does not match.
    """
    lines = armored.strip().splitlines()

    # Find header / footer
    header_re = re.compile(r"^-----BEGIN DEADPGP (.+)-----$")
    footer_re = re.compile(r"^-----END DEADPGP (.+)-----$")

    header_match = header_re.match(lines[0]) if lines else None
    if not header_match:
        raise ValueError("Missing or malformed armor header")

    armor_type = header_match.group(1)
    if armor_type not in _VALID_TYPES:
        raise ValueError(f"Unrecognised armor type: '{armor_type}'")

    footer_match = footer_re.match(lines[-1]) if lines else None
    if not footer_match or footer_match.group(1) != armor_type:
        raise ValueError("Missing or mismatched armor footer")

    # Extract body lines and checksum
    body_lines: list[str] = []
    checksum_line: str | None = None
    for line in lines[1:-1]:
        if line.startswith("="):
            checksum_line = line[1:]
        else:
            body_lines.append(line)

    if checksum_line is None:
        raise ValueError("Missing CRC-24 checksum line")

    data = base64.b64decode("".join(body_lines))

    # Verify checksum
    expected = _crc24_str(data)
    if checksum_line != expected:
        raise ValueError(
            f"CRC-24 mismatch: expected '={expected}', got '={checksum_line}'"
        )

    return data, armor_type
