"""Public-key encryption for DeadPGP.

Algorithm:
  - Ephemeral X25519 key agreement → shared secret
  - HKDF-SHA-256 to derive a 32-byte symmetric key
  - ChaCha20-Poly1305 AEAD for authenticated encryption

Armored message header fields:
  - Version: 1
  - Mode: pubkey
  - To: <recipient fingerprint>
  - EphemeralKey: <base64 ephemeral public key>
  - Nonce: <base64 12-byte nonce>
  - Ciphertext: <base64 ciphertext + 16-byte Poly1305 tag>
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .armor import b64, b64d, decode, encode
from .keys import (
    fingerprint,
    private_key_from_data,
    public_key_from_data,
    raw_public_bytes,
)

_LABEL = "DEADPGP MESSAGE"
_MODE = "pubkey"
_NONCE_LEN = 12
_KEY_LEN = 32
_HKDF_INFO = b"deadpgp-v1-pubkey"


def _derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte symmetric key using HKDF-SHA-256."""
    hkdf = HKDF(
        algorithm=SHA256(),
        length=_KEY_LEN,
        salt=salt,
        info=_HKDF_INFO,
    )
    return hkdf.derive(shared_secret)


def encrypt(plaintext: bytes, recipient_key_data: dict) -> str:
    """Encrypt *plaintext* for *recipient_key_data* and return an armored string.

    Parameters
    ----------
    plaintext:
        The message to encrypt.
    recipient_key_data:
        A key dict as returned by :func:`deadpgp.keys.load_key_file`.

    Returns
    -------
    str
        An armored DeadPGP message block.
    """
    recipient_pub: X25519PublicKey = public_key_from_data(recipient_key_data)
    recipient_fp = recipient_key_data["fingerprint"]

    # Generate ephemeral keypair
    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key()
    ephemeral_pub_bytes = ephemeral_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Key agreement
    shared_secret = ephemeral_priv.exchange(recipient_pub)

    # Derive symmetric key (use ephemeral public key as HKDF salt)
    sym_key = _derive_key(shared_secret, ephemeral_pub_bytes)

    # Encrypt
    nonce = os.urandom(_NONCE_LEN)
    aead = ChaCha20Poly1305(sym_key)
    ciphertext = aead.encrypt(nonce, plaintext, None)

    headers = {
        "Version": "1",
        "Mode": _MODE,
        "To": recipient_fp,
        "EphemeralKey": b64(ephemeral_pub_bytes),
        "Nonce": b64(nonce),
    }
    return encode(_LABEL, headers, ciphertext)


def decrypt(armored: str, identity_key_data: dict) -> bytes:
    """Decrypt an armored pubkey-mode message using *identity_key_data*.

    Parameters
    ----------
    armored:
        The armored message string (BEGIN/END block).
    identity_key_data:
        A private key dict as returned by :func:`deadpgp.keys.load_key_file`.

    Returns
    -------
    bytes
        The decrypted plaintext.

    Raises
    ------
    ValueError
        If the message mode is wrong, headers are missing, or decryption fails.
    """
    label, headers, ciphertext = decode(armored)

    if label != _LABEL:
        raise ValueError(f"Expected label '{_LABEL}', got '{label}'")
    if headers.get("Mode") != _MODE:
        raise ValueError(
            f"Expected mode '{_MODE}', got '{headers.get('Mode')}'; "
            "use the correct decrypt function for this message type."
        )

    for field in ("EphemeralKey", "Nonce"):
        if field not in headers:
            raise ValueError(f"Missing required header field '{field}'")

    ephemeral_pub_bytes = b64d(headers["EphemeralKey"])
    nonce = b64d(headers["Nonce"])

    ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
    my_private: X25519PrivateKey = private_key_from_data(identity_key_data)

    # Key agreement
    shared_secret = my_private.exchange(ephemeral_pub)
    sym_key = _derive_key(shared_secret, ephemeral_pub_bytes)

    aead = ChaCha20Poly1305(sym_key)
    try:
        return aead.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError("Decryption failed: invalid key or corrupted message.") from exc
