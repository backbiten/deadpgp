"""Armor encoding / decoding for DeadPGP messages and keys.

Format example::

    -----BEGIN DEADPGP MESSAGE-----
    Version: 1
    Mode: pubkey
    To: ab12cd34...
    Nonce: <base64>
    Ciphertext: <base64>
    -----END DEADPGP MESSAGE-----
"""

from __future__ import annotations

import base64
import re

_ARMOR_HEADER_RE = re.compile(r"^-----BEGIN (DEADPGP [A-Z ]+)-----$")
_ARMOR_FOOTER_RE = re.compile(r"^-----END (DEADPGP [A-Z ]+)-----$")

HEADER_SEP = ": "


class ArmorError(ValueError):
    """Raised when armor parsing fails."""


def encode(label: str, headers: dict[str, str], payload: bytes) -> str:
    """Return an armored block as a string.

    Parameters
    ----------
    label:
        The label used in the BEGIN/END lines (e.g. ``"DEADPGP MESSAGE"``).
    headers:
        Ordered key/value pairs written before the payload.
    payload:
        Raw bytes that will be base64-encoded as the *Ciphertext* / *Key* field.
        Pass ``b""`` if all data is already in *headers*.
    """
    lines: list[str] = [f"-----BEGIN {label}-----"]
    for key, value in headers.items():
        lines.append(f"{key}{HEADER_SEP}{value}")
    if payload:
        lines.append("")
        lines.append(base64.b64encode(payload).decode("ascii"))
    lines.append(f"-----END {label}-----")
    return "\n".join(lines) + "\n"


def decode(text: str) -> tuple[str, dict[str, str], bytes]:
    """Parse an armored block.

    Returns
    -------
    label:
        The label from the BEGIN/END lines (e.g. ``"DEADPGP MESSAGE"``).
    headers:
        Key/value pairs from the header section.
    payload:
        Decoded bytes from the base64 body (empty bytes if no body).

    Raises
    ------
    ArmorError
        If the block is malformed or the labels do not match.
    """
    raw_lines = [line.rstrip() for line in text.splitlines()]

    # Find BEGIN line
    begin_index = None
    for i, line in enumerate(raw_lines):
        if _ARMOR_HEADER_RE.match(line):
            begin_index = i
            break

    if begin_index is None:
        raise ArmorError("No '-----BEGIN DEADPGP ...' line found")

    label_match = _ARMOR_HEADER_RE.match(raw_lines[begin_index])
    assert label_match  # already matched above
    label = label_match.group(1)

    # Find END line
    end_index = None
    for i in range(begin_index + 1, len(raw_lines)):
        m = _ARMOR_FOOTER_RE.match(raw_lines[i])
        if m:
            if m.group(1) != label:
                raise ArmorError(
                    f"BEGIN label '{label}' does not match END label '{m.group(1)}'"
                )
            end_index = i
            break

    if end_index is None:
        raise ArmorError(f"No '-----END {label}-----' line found")

    body_lines = raw_lines[begin_index + 1 : end_index]

    # Split headers from optional base64 payload (separated by blank line)
    headers: dict[str, str] = {}
    payload_b64 = ""
    blank_found = False

    for line in body_lines:
        if blank_found:
            payload_b64 += line
        elif line == "":
            blank_found = True
        elif HEADER_SEP in line:
            key, _, value = line.partition(HEADER_SEP)
            headers[key.strip()] = value.strip()
        else:
            raise ArmorError(f"Unexpected line in armor headers: {line!r}")

    payload = base64.b64decode(payload_b64) if payload_b64 else b""
    return label, headers, payload


def find_blocks(text: str) -> list[str]:
    """Return every armored block found in *text* as separate strings."""
    blocks: list[str] = []
    lines = text.splitlines(keepends=True)
    current: list[str] = []
    in_block = False

    for line in lines:
        stripped = line.rstrip()
        if _ARMOR_HEADER_RE.match(stripped):
            in_block = True
            current = [line]
        elif in_block:
            current.append(line)
            if _ARMOR_FOOTER_RE.match(stripped):
                blocks.append("".join(current))
                current = []
                in_block = False

    return blocks


def b64(data: bytes) -> str:
    """Return URL-safe base64 encoding of *data*."""
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """Decode a base64-encoded string to bytes."""
    return base64.b64decode(text)
