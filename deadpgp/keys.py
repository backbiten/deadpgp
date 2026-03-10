"""
Key generation and management for deadpgp.

Classic PGP used RSA for asymmetric key operations.  This module keeps that
heritage while moving the default key size to 4096 bits and using modern
serialisation formats (PEM / PKCS#8).
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_KEY_SIZE = 4096
PUBLIC_EXPONENT = 65537


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keypair(key_size: int = DEFAULT_KEY_SIZE):
    """Generate an RSA key pair.

    Parameters
    ----------
    key_size:
        RSA modulus length in bits.  Must be at least 2048.  Defaults to
        4096.

    Returns
    -------
    (private_key, public_key)
        A tuple of
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
        and
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`.
    """
    if key_size < 2048:
        raise ValueError("key_size must be at least 2048 bits")

    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=key_size,
        backend=default_backend(),
    )
    return private_key, private_key.public_key()


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def export_private_key(private_key, password: bytes | None = None) -> bytes:
    """Serialise a private key to PEM-encoded PKCS#8 bytes.

    Parameters
    ----------
    private_key:
        An RSA private key object.
    password:
        Optional passphrase used to encrypt the private key.  When supplied
        the key is encrypted with AES-256-CBC + PBKDF2-HMAC-SHA256.

    Returns
    -------
    bytes
        PEM-encoded private key.
    """
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password is not None
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def export_public_key(public_key) -> bytes:
    """Serialise a public key to PEM-encoded SubjectPublicKeyInfo bytes.

    Parameters
    ----------
    public_key:
        An RSA public key object.

    Returns
    -------
    bytes
        PEM-encoded public key.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem_data: bytes, password: bytes | None = None):
    """Deserialise a PEM-encoded private key.

    Parameters
    ----------
    pem_data:
        PEM-encoded private key bytes.
    password:
        Passphrase if the key is encrypted.

    Returns
    -------
    RSAPrivateKey
    """
    return serialization.load_pem_private_key(
        pem_data,
        password=password,
        backend=default_backend(),
    )


def load_public_key(pem_data: bytes):
    """Deserialise a PEM-encoded public key.

    Parameters
    ----------
    pem_data:
        PEM-encoded public key bytes.

    Returns
    -------
    RSAPublicKey
    """
    return serialization.load_pem_public_key(pem_data, backend=default_backend())
