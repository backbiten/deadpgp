"""deadpgp – Revamped PGP-style encryption.

Classic PGP protocols from the 1980s/1990s, modernised with strong
cryptographic primitives suitable for the 21st century:

  * RSA-4096 or ECDH (X25519) for key exchange
  * AES-256-GCM for symmetric encryption
  * RSA-PSS or Ed25519 for digital signatures
  * SHA-256 / SHA-512 for hashing
  * PEM / ASCII-armor for key and message encoding
"""

from .keys import (
    generate_rsa_keypair,
    generate_ec_keypair,
    load_private_key,
    load_public_key,
    serialize_private_key,
    serialize_public_key,
)
from .encryption import encrypt, decrypt
from .signing import sign, verify

__all__ = [
    "generate_rsa_keypair",
    "generate_ec_keypair",
    "load_private_key",
    "load_public_key",
    "serialize_private_key",
    "serialize_public_key",
    "encrypt",
    "decrypt",
    "sign",
    "verify",
]
