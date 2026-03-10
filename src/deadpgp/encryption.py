"""Hybrid encryption and decryption for deadpgp.

Architecture
------------
The same hybrid approach used by classic PGP is preserved but with modern,
audited algorithms:

+--------------------+------------------------------------------------------+
| Classic PGP        | deadpgp                                              |
+====================+======================================================+
| RSA (PKCS#1 v1.5)  | RSA-OAEP (SHA-256, MGF1-SHA-256) or ECDH-X25519     |
| IDEA / 3DES        | AES-256-GCM (authenticated encryption)              |
| MD5 / SHA-1        | SHA-256                                              |
+--------------------+------------------------------------------------------+

Wire format
-----------
The encrypted blob returned by :func:`encrypt` is structured as follows
(all integers are big-endian):

    [4 bytes]  Length of the encrypted session key (ESK)
    [N bytes]  Encrypted session key
    [12 bytes] AES-GCM nonce
    [M bytes]  AES-GCM ciphertext + 16-byte authentication tag

This format is intentionally simple and self-describing.
"""

from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    EllipticCurvePrivateKey,
    ECDH,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

_BACKEND = default_backend()

_AES_KEY_LEN = 32  # AES-256
_NONCE_LEN = 12    # GCM recommended 96-bit nonce
_OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encrypt(plaintext: bytes, recipient_public_key: object) -> bytes:
    """Encrypt *plaintext* for *recipient_public_key*.

    Parameters
    ----------
    plaintext:
        Arbitrary bytes to encrypt.
    recipient_public_key:
        An RSA, EC (NIST curves), or X25519 public key object.

    Returns
    -------
    Ciphertext bytes in deadpgp wire format.

    Raises
    ------
    TypeError
        If *recipient_public_key* is not a supported key type.
    """
    if isinstance(recipient_public_key, RSAPublicKey):
        return _encrypt_rsa(plaintext, recipient_public_key)
    if isinstance(recipient_public_key, EllipticCurvePublicKey):
        return _encrypt_ec(plaintext, recipient_public_key)
    if isinstance(recipient_public_key, X25519PublicKey):
        return _encrypt_x25519(plaintext, recipient_public_key)
    raise TypeError(
        f"Unsupported public key type: {type(recipient_public_key).__name__}. "
        "Expected RSAPublicKey, EllipticCurvePublicKey, or X25519PublicKey."
    )


def decrypt(ciphertext: bytes, recipient_private_key: object) -> bytes:
    """Decrypt *ciphertext* using *recipient_private_key*.

    Parameters
    ----------
    ciphertext:
        Bytes previously produced by :func:`encrypt`.
    recipient_private_key:
        The private key corresponding to the public key used during
        encryption.

    Returns
    -------
    Original plaintext bytes.

    Raises
    ------
    TypeError
        If *recipient_private_key* is not a supported key type.
    ValueError
        If the ciphertext is malformed or authentication fails.
    """
    if isinstance(recipient_private_key, RSAPrivateKey):
        return _decrypt_rsa(ciphertext, recipient_private_key)
    if isinstance(recipient_private_key, EllipticCurvePrivateKey):
        return _decrypt_ec(ciphertext, recipient_private_key)
    if isinstance(recipient_private_key, X25519PrivateKey):
        return _decrypt_x25519(ciphertext, recipient_private_key)
    raise TypeError(
        f"Unsupported private key type: {type(recipient_private_key).__name__}. "
        "Expected RSAPrivateKey, EllipticCurvePrivateKey, or X25519PrivateKey."
    )


# ---------------------------------------------------------------------------
# RSA helpers
# ---------------------------------------------------------------------------

def _encrypt_rsa(plaintext: bytes, public_key: RSAPublicKey) -> bytes:
    session_key = os.urandom(_AES_KEY_LEN)
    esk = public_key.encrypt(session_key, _OAEP_PADDING)
    return _build_packet(esk, session_key, plaintext)


def _decrypt_rsa(ciphertext: bytes, private_key: RSAPrivateKey) -> bytes:
    esk, nonce, body = _parse_packet(ciphertext)
    session_key = private_key.decrypt(esk, _OAEP_PADDING)
    return _aes_gcm_decrypt(session_key, nonce, body)


# ---------------------------------------------------------------------------
# ECDH (NIST curves) helpers
# ---------------------------------------------------------------------------

def _encrypt_ec(plaintext: bytes, public_key: EllipticCurvePublicKey) -> bytes:
    ephemeral_private = ec.generate_private_key(public_key.curve, _BACKEND)
    shared_secret = ephemeral_private.exchange(ECDH(), public_key)
    session_key = _derive_key(shared_secret)

    # Serialise ephemeral public key so the recipient can reproduce the exchange
    ephemeral_pub_bytes = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # ESK = ephemeral_pub_bytes; the session key is derived, not transmitted
    return _build_packet(ephemeral_pub_bytes, session_key, plaintext)


def _decrypt_ec(ciphertext: bytes, private_key: EllipticCurvePrivateKey) -> bytes:
    ephemeral_pub_bytes, nonce, body = _parse_packet(ciphertext)
    ephemeral_pub = serialization.load_der_public_key(ephemeral_pub_bytes, _BACKEND)
    shared_secret = private_key.exchange(ECDH(), ephemeral_pub)
    session_key = _derive_key(shared_secret)
    return _aes_gcm_decrypt(session_key, nonce, body)


# ---------------------------------------------------------------------------
# X25519 helpers
# ---------------------------------------------------------------------------

def _encrypt_x25519(plaintext: bytes, public_key: X25519PublicKey) -> bytes:
    ephemeral_private = X25519PrivateKey.generate()
    shared_secret = ephemeral_private.exchange(public_key)
    session_key = _derive_key(shared_secret)
    ephemeral_pub_bytes = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _build_packet(ephemeral_pub_bytes, session_key, plaintext)


def _decrypt_x25519(ciphertext: bytes, private_key: X25519PrivateKey) -> bytes:
    ephemeral_pub_bytes, nonce, body = _parse_packet(ciphertext)
    ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
    shared_secret = private_key.exchange(ephemeral_pub)
    session_key = _derive_key(shared_secret)
    return _aes_gcm_decrypt(session_key, nonce, body)


# ---------------------------------------------------------------------------
# Packet helpers
# ---------------------------------------------------------------------------

def _build_packet(esk: bytes, session_key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = _aes_gcm_encrypt(session_key, nonce, plaintext)
    return struct.pack(">I", len(esk)) + esk + nonce + ciphertext


def _parse_packet(data: bytes) -> tuple[bytes, bytes, bytes]:
    if len(data) < 4:
        raise ValueError("Ciphertext too short")
    (esk_len,) = struct.unpack(">I", data[:4])
    offset = 4 + esk_len
    if len(data) < offset + _NONCE_LEN:
        raise ValueError("Ciphertext truncated (missing nonce or body)")
    esk = data[4:offset]
    nonce = data[offset : offset + _NONCE_LEN]
    body = data[offset + _NONCE_LEN :]
    return esk, nonce, body


# ---------------------------------------------------------------------------
# AES-256-GCM helpers
# ---------------------------------------------------------------------------

def _aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, None)


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError("Decryption failed – wrong key or corrupted data") from exc


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------

def _derive_key(shared_secret: bytes) -> bytes:
    """Derive a 256-bit AES session key from an ECDH/X25519 shared secret."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_AES_KEY_LEN,
        salt=None,
        info=b"deadpgp-session-key-v1",
        backend=_BACKEND,
    )
    return hkdf.derive(shared_secret)
