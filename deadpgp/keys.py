"""Key generation and management for DeadPGP.

Keys are stored as JSON files with the following structure::

    {
        "version": 1,
        "type": "x25519",
        "fingerprint": "<hex>",
        "public_key": "<base64>",
        "private_key": "<base64>"   // only in private-key files
    }

Public-key files omit ``private_key``.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .armor import b64, b64d

_KEY_VERSION = 1
_KEY_TYPE = "x25519"


class KeyFileError(ValueError):
    """Raised on invalid key file content."""


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------


def fingerprint(public_key_bytes: bytes) -> str:
    """Return the SHA-256 fingerprint (hex) of a raw 32-byte X25519 public key."""
    return hashlib.sha256(public_key_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


def generate_keypair() -> dict:
    """Generate a new X25519 keypair and return a dict with all key material."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    raw_public = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    raw_private = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )

    fp = fingerprint(raw_public)

    return {
        "version": _KEY_VERSION,
        "type": _KEY_TYPE,
        "fingerprint": fp,
        "public_key": b64(raw_public),
        "private_key": b64(raw_private),
    }


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def save_private_key(key_data: dict, path: Path | str) -> None:
    """Write the full keypair (private + public) to *path*."""
    path = Path(path)
    path.write_text(json.dumps(key_data, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def save_public_key(key_data: dict, path: Path | str) -> None:
    """Write the public portion of *key_data* to *path*."""
    path = Path(path)
    pub = {
        "version": key_data["version"],
        "type": key_data["type"],
        "fingerprint": key_data["fingerprint"],
        "public_key": key_data["public_key"],
    }
    path.write_text(json.dumps(pub, indent=2) + "\n", encoding="utf-8")


def load_key_file(path: Path | str) -> dict:
    """Load and minimally validate a key file from *path*."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KeyFileError(f"Cannot read key file '{path}': {exc}") from exc

    for field in ("version", "type", "fingerprint", "public_key"):
        if field not in data:
            raise KeyFileError(f"Key file '{path}' is missing field '{field}'")

    if data.get("type") != _KEY_TYPE:
        raise KeyFileError(
            f"Unsupported key type '{data.get('type')}'; expected '{_KEY_TYPE}'"
        )

    return data


# ---------------------------------------------------------------------------
# Crypto-object helpers
# ---------------------------------------------------------------------------


def public_key_from_data(key_data: dict) -> X25519PublicKey:
    """Return a :class:`X25519PublicKey` from a loaded key dict."""
    raw = b64d(key_data["public_key"])
    return X25519PublicKey.from_public_bytes(raw)


def private_key_from_data(key_data: dict) -> X25519PrivateKey:
    """Return a :class:`X25519PrivateKey` from a loaded key dict.

    Raises :class:`KeyFileError` if the private key material is absent.
    """
    if "private_key" not in key_data:
        raise KeyFileError(
            "This key file contains only a public key; a private key is required for decryption."
        )
    raw = b64d(key_data["private_key"])
    return X25519PrivateKey.from_private_bytes(raw)


def raw_public_bytes(key_data: dict) -> bytes:
    """Return the raw 32-byte public key from a key dict."""
    return b64d(key_data["public_key"])
