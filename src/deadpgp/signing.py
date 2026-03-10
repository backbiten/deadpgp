"""Digital signing and verification for deadpgp.

Algorithm mapping
-----------------
+--------------------+------------------------------------------------------+
| Classic PGP        | deadpgp                                              |
+====================+======================================================+
| RSA + MD5/SHA-1    | RSA-PSS + SHA-256                                    |
| DSA + SHA-1        | ECDSA + SHA-256 (NIST curves) or Ed25519            |
+--------------------+------------------------------------------------------+

The signature is returned / expected as raw bytes.  Use :mod:`deadpgp.armor`
to wrap signatures in ASCII-armor for transmission.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    ECDSA,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

_PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)
_ECDSA_ALGORITHM = ECDSA(hashes.SHA256())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def sign(message: bytes, private_key: object) -> bytes:
    """Sign *message* with *private_key*.

    Parameters
    ----------
    message:
        Arbitrary bytes to sign.
    private_key:
        An RSA, EC (NIST curves), or Ed25519 private key object.

    Returns
    -------
    Signature bytes.

    Raises
    ------
    TypeError
        If *private_key* is not a supported key type.
    """
    if isinstance(private_key, RSAPrivateKey):
        return private_key.sign(message, _PSS_PADDING, hashes.SHA256())
    if isinstance(private_key, EllipticCurvePrivateKey):
        return private_key.sign(message, _ECDSA_ALGORITHM)
    if isinstance(private_key, Ed25519PrivateKey):
        return private_key.sign(message)
    raise TypeError(
        f"Unsupported private key type: {type(private_key).__name__}. "
        "Expected RSAPrivateKey, EllipticCurvePrivateKey, or Ed25519PrivateKey."
    )


def verify(message: bytes, signature: bytes, public_key: object) -> bool:
    """Verify *signature* over *message* using *public_key*.

    Parameters
    ----------
    message:
        The original message bytes.
    signature:
        Signature bytes returned by :func:`sign`.
    public_key:
        The public key corresponding to the private key used to sign.

    Returns
    -------
    ``True`` if the signature is valid, ``False`` otherwise.

    Raises
    ------
    TypeError
        If *public_key* is not a supported key type.
    """
    try:
        _verify_raw(message, signature, public_key)
        return True
    except InvalidSignature:
        return False


def _verify_raw(message: bytes, signature: bytes, public_key: object) -> None:
    """Like :func:`verify` but raises :exc:`~cryptography.exceptions.InvalidSignature`."""
    if isinstance(public_key, RSAPublicKey):
        public_key.verify(signature, message, _PSS_PADDING, hashes.SHA256())
        return
    if isinstance(public_key, EllipticCurvePublicKey):
        public_key.verify(signature, message, _ECDSA_ALGORITHM)
        return
    if isinstance(public_key, Ed25519PublicKey):
        public_key.verify(signature, message)
        return
    raise TypeError(
        f"Unsupported public key type: {type(public_key).__name__}. "
        "Expected RSAPublicKey, EllipticCurvePublicKey, or Ed25519PublicKey."
    )
