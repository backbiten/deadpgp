"""
Hybrid encryption for deadpgp.

Classic PGP used hybrid encryption: a random session key (originally IDEA,
later 3DES/AES) is generated and encrypted with the recipient's RSA public
key, while the actual message is encrypted symmetrically with that session
key.

This module follows the same design but uses AES-256-GCM (authenticated
encryption) for the symmetric layer and OAEP with SHA-256 for the asymmetric
layer, giving both confidentiality and integrity guarantees.

Wire format (all length prefixes are 4-byte big-endian unsigned integers):
    [4 bytes] length of the RSA-encrypted session key
    [N bytes] RSA-OAEP encrypted session key
    [12 bytes] AES-GCM nonce
    [remaining bytes] AES-256-GCM ciphertext + 16-byte authentication tag
"""

from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

_SESSION_KEY_BYTES = 32   # 256-bit AES key
_NONCE_BYTES = 12         # 96-bit GCM nonce (NIST recommendation)
_LENGTH_PREFIX_FMT = ">I"  # big-endian unsigned 32-bit integer
_LENGTH_PREFIX_SIZE = struct.calcsize(_LENGTH_PREFIX_FMT)


def _oaep_padding():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encrypt(plaintext: bytes, public_key) -> bytes:
    """Encrypt *plaintext* for the owner of *public_key*.

    Parameters
    ----------
    plaintext:
        Raw bytes to encrypt.
    public_key:
        Recipient's RSA public key.

    Returns
    -------
    bytes
        Ciphertext blob in the deadpgp wire format.
    """
    session_key = os.urandom(_SESSION_KEY_BYTES)
    nonce = os.urandom(_NONCE_BYTES)

    encrypted_session_key = public_key.encrypt(session_key, _oaep_padding())

    aes = AESGCM(session_key)
    ciphertext = aes.encrypt(nonce, plaintext, None)

    key_len = struct.pack(_LENGTH_PREFIX_FMT, len(encrypted_session_key))
    return key_len + encrypted_session_key + nonce + ciphertext


def decrypt(ciphertext: bytes, private_key) -> bytes:
    """Decrypt a ciphertext blob produced by :func:`encrypt`.

    Parameters
    ----------
    ciphertext:
        Ciphertext blob in the deadpgp wire format.
    private_key:
        Recipient's RSA private key.

    Returns
    -------
    bytes
        The original plaintext.

    Raises
    ------
    ValueError
        If the blob is truncated or otherwise malformed.
    """
    if len(ciphertext) < _LENGTH_PREFIX_SIZE:
        raise ValueError("Ciphertext is too short to contain a length prefix")

    (key_len,) = struct.unpack_from(_LENGTH_PREFIX_FMT, ciphertext, 0)
    offset = _LENGTH_PREFIX_SIZE

    if len(ciphertext) < offset + key_len + _NONCE_BYTES:
        raise ValueError("Ciphertext is truncated")

    encrypted_session_key = ciphertext[offset : offset + key_len]
    offset += key_len

    nonce = ciphertext[offset : offset + _NONCE_BYTES]
    offset += _NONCE_BYTES

    aes_ciphertext = ciphertext[offset:]

    session_key = private_key.decrypt(encrypted_session_key, _oaep_padding())

    aes = AESGCM(session_key)
    return aes.decrypt(nonce, aes_ciphertext, None)
