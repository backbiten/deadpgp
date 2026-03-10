"""
deadpgp – Old PGP protocols from the 1980s and 1990s, reinvented for the
modern 21st century.

Public API:
    Key management : generate_keypair, load_public_key, load_private_key,
                     export_public_key, export_private_key
    Encryption     : encrypt, decrypt
    Signing        : sign, verify
    ASCII Armor    : armor, dearmor
"""

from .keys import generate_keypair, load_public_key, load_private_key, export_public_key, export_private_key
from .encrypt import encrypt, decrypt
from .sign import sign, verify
from .armor import armor, dearmor

__all__ = [
    "generate_keypair",
    "load_public_key",
    "load_private_key",
    "export_public_key",
    "export_private_key",
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "armor",
    "dearmor",
]

__version__ = "0.1.0"
