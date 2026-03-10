"""Key generation and serialisation helpers for deadpgp.

Supported key types
-------------------
RSA-4096
    Classic public-key algorithm still widely used in PGP/GPG.
    Uses RSA-OAEP (SHA-256) for encryption and RSA-PSS (SHA-256) for signing.

ECDH / Ed25519
    Modern elliptic-curve alternatives.
    * X25519  – key agreement (used in hybrid encryption)
    * Ed25519 – signing

All private keys are serialised in PEM / PKCS8 format (optionally with
password-based encryption using AES-256-CBC + SHA-256 PBKDF2), and all
public keys in SubjectPublicKeyInfo (SPKI) PEM format.
"""

from __future__ import annotations

import os
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    SECP256R1,
    SECP384R1,
    SECP521R1,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.backends import default_backend

# Union type alias for any supported private key
AnyPrivateKey = RSAPrivateKey | EllipticCurvePrivateKey | Ed25519PrivateKey | X25519PrivateKey
AnyPublicKey = RSAPublicKey | EllipticCurvePublicKey | Ed25519PublicKey | X25519PublicKey

_BACKEND = default_backend()


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def generate_rsa_keypair(key_size: int = 4096) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate an RSA key pair.

    Parameters
    ----------
    key_size:
        Bit length of the modulus.  Minimum 2048; default 4096.

    Returns
    -------
    (private_key, public_key)
    """
    if key_size < 2048:
        raise ValueError("RSA key size must be at least 2048 bits")
    private_key: RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=_BACKEND,
    )
    return private_key, private_key.public_key()


def generate_ec_keypair(
    curve: str = "secp256r1",
) -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate an ECDSA/ECDH key pair on the requested named curve.

    Parameters
    ----------
    curve:
        Named curve: ``'secp256r1'`` (P-256), ``'secp384r1'`` (P-384), or
        ``'secp521r1'`` (P-521).

    Returns
    -------
    (private_key, public_key)
    """
    _CURVES: dict[str, type] = {
        "secp256r1": SECP256R1,
        "secp384r1": SECP384R1,
        "secp521r1": SECP521R1,
    }
    if curve not in _CURVES:
        raise ValueError(f"Unsupported curve '{curve}'. Choose from: {', '.join(_CURVES)}")
    private_key: EllipticCurvePrivateKey = ec.generate_private_key(
        _CURVES[curve](),
        backend=_BACKEND,
    )
    return private_key, private_key.public_key()


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 signing key pair.

    Returns
    -------
    (private_key, public_key)
    """
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def generate_x25519_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate an X25519 key-agreement key pair.

    Returns
    -------
    (private_key, public_key)
    """
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

def serialize_private_key(
    private_key: AnyPrivateKey,
    password: Optional[bytes] = None,
) -> bytes:
    """Serialise *private_key* to PEM / PKCS8 bytes.

    Parameters
    ----------
    private_key:
        Any supported private key object.
    password:
        Optional passphrase; when supplied the private key is encrypted
        with AES-256-CBC and PBKDF2-HMAC-SHA256.

    Returns
    -------
    PEM bytes (``b'-----BEGIN ...'``).
    """
    encryption: serialization.KeySerializationEncryption
    if password is not None:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def serialize_public_key(public_key: AnyPublicKey) -> bytes:
    """Serialise *public_key* to PEM / SPKI bytes.

    Returns
    -------
    PEM bytes (``b'-----BEGIN PUBLIC KEY-----...'``).
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ---------------------------------------------------------------------------
# Deserialisation
# ---------------------------------------------------------------------------

def load_private_key(
    pem_data: bytes,
    password: Optional[bytes] = None,
) -> AnyPrivateKey:
    """Load a private key from PEM bytes.

    Parameters
    ----------
    pem_data:
        PEM-encoded private key (PKCS8 format, optionally encrypted).
    password:
        Passphrase to decrypt an encrypted private key, or ``None``.

    Returns
    -------
    A private key object.

    Raises
    ------
    ValueError
        If the PEM data cannot be decoded or the password is wrong.
    """
    try:
        return serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=_BACKEND,
        )
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Failed to load private key: {exc}") from exc


def load_public_key(pem_data: bytes) -> AnyPublicKey:
    """Load a public key from PEM bytes.

    Parameters
    ----------
    pem_data:
        PEM-encoded public key (SPKI format).

    Returns
    -------
    A public key object.

    Raises
    ------
    ValueError
        If the PEM data cannot be decoded.
    """
    try:
        return serialization.load_pem_public_key(pem_data, backend=_BACKEND)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Failed to load public key: {exc}") from exc
