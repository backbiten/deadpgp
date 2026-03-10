"""
Digital signatures for deadpgp.

Classic PGP used RSA with PKCS#1 v1.5 padding for signatures and MD5 / SHA-1
for hashing.  This module keeps RSA as the asymmetric primitive but upgrades
to RSA-PSS padding (more secure) and SHA-256 hashing.

Wire format produced by :func:`sign`:
    [4 bytes big-endian] signature length
    [N bytes] raw RSA-PSS signature
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


_LENGTH_PREFIX_FMT = ">I"
_LENGTH_PREFIX_SIZE = struct.calcsize(_LENGTH_PREFIX_FMT)


def _pss_padding():
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def sign(message: bytes, private_key) -> bytes:
    """Create a detached RSA-PSS signature over *message*.

    Parameters
    ----------
    message:
        The data to sign.
    private_key:
        Signer's RSA private key.

    Returns
    -------
    bytes
        Length-prefixed signature blob.
    """
    raw_sig = private_key.sign(message, _pss_padding(), hashes.SHA256())
    prefix = struct.pack(_LENGTH_PREFIX_FMT, len(raw_sig))
    return prefix + raw_sig


def verify(message: bytes, signature: bytes, public_key) -> None:
    """Verify an RSA-PSS signature produced by :func:`sign`.

    Parameters
    ----------
    message:
        The data that was signed.
    signature:
        Signature blob as produced by :func:`sign`.
    public_key:
        Signer's RSA public key.

    Raises
    ------
    ValueError
        If the signature blob is malformed.
    cryptography.exceptions.InvalidSignature
        If the signature does not match *message*.
    """
    if len(signature) < _LENGTH_PREFIX_SIZE:
        raise ValueError("Signature blob is too short")

    (sig_len,) = struct.unpack_from(_LENGTH_PREFIX_FMT, signature, 0)
    raw_sig = signature[_LENGTH_PREFIX_SIZE : _LENGTH_PREFIX_SIZE + sig_len]

    if len(raw_sig) != sig_len:
        raise ValueError("Signature blob is truncated")

    public_key.verify(raw_sig, message, _pss_padding(), hashes.SHA256())
