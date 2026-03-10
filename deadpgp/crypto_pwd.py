"""Password-based encryption for DeadPGP.

Algorithm:
  - Argon2id (preferred) or scrypt (fallback) key derivation
  - ChaCha20-Poly1305 AEAD for authenticated encryption

Argon2id is the winner of the Password Hashing Competition (2015) and is
the recommended KDF for new designs.  scrypt is used as a fallback when the
``argon2-cffi`` package is not installed.

Armored message header fields:
  - Version: 1
  - Mode: password-argon2id  (or password-scrypt)
  - Salt: <base64 16-byte salt>
  - Params: <algorithm-specific parameters>
  - Nonce: <base64 12-byte nonce>
  - Ciphertext: <base64 ciphertext + 16-byte Poly1305 tag>
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .armor import b64, b64d, decode, encode

_LABEL = "DEADPGP MESSAGE"
_NONCE_LEN = 12
_SALT_LEN = 16
_KEY_LEN = 32

# ---------------------------------------------------------------------------
# KDF helpers
# ---------------------------------------------------------------------------

def _try_argon2() -> bool:
    """Return True if argon2-cffi is available."""
    try:
        import argon2.low_level  # noqa: F401
        return True
    except ImportError:
        return False


# Argon2id parameters (OWASP minimum: m=19456, t=2, p=1; we use defaults)
_ARGON2_TIME_COST = 3
_ARGON2_MEMORY_KIB = 65536  # 64 MiB
_ARGON2_PARALLELISM = 4


def _kdf_argon2id(password: bytes, salt: bytes) -> tuple[bytes, str]:
    """Derive a key with Argon2id; return (key, params_string)."""
    from argon2.low_level import Type, hash_secret_raw

    key = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=_ARGON2_TIME_COST,
        memory_cost=_ARGON2_MEMORY_KIB,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=_KEY_LEN,
        type=Type.ID,
    )
    params = (
        f"t={_ARGON2_TIME_COST},m={_ARGON2_MEMORY_KIB},p={_ARGON2_PARALLELISM}"
    )
    return key, params


# scrypt parameters (N=2^17, r=8, p=1 ≈ 128 MiB)
_SCRYPT_N = 2**17
_SCRYPT_R = 8
_SCRYPT_P = 1


def _kdf_scrypt(password: bytes, salt: bytes) -> tuple[bytes, str]:
    """Derive a key with scrypt; return (key, params_string)."""
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    kdf = Scrypt(salt=salt, length=_KEY_LEN, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    key = kdf.derive(password)
    params = f"N={_SCRYPT_N},r={_SCRYPT_R},p={_SCRYPT_P}"
    return key, params


def _derive_key(
    password: bytes, salt: bytes
) -> tuple[bytes, str, str]:
    """Derive a symmetric key from *password* and *salt*.

    Returns
    -------
    key : bytes
        32-byte symmetric key.
    mode_tag : str
        ``"password-argon2id"`` or ``"password-scrypt"``.
    params : str
        Human-readable KDF parameters.
    """
    if _try_argon2():
        key, params = _kdf_argon2id(password, salt)
        return key, "password-argon2id", params
    else:
        key, params = _kdf_scrypt(password, salt)
        return key, "password-scrypt", params


def _derive_key_with_params(
    password: bytes, salt: bytes, mode: str, params_str: str
) -> bytes:
    """Re-derive the key using the KDF specified in *mode* and *params_str*."""
    if mode == "password-argon2id":
        params = _parse_params(params_str)
        from argon2.low_level import Type, hash_secret_raw

        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=int(params["t"]),
            memory_cost=int(params["m"]),
            parallelism=int(params["p"]),
            hash_len=_KEY_LEN,
            type=Type.ID,
        )
    elif mode == "password-scrypt":
        params = _parse_params(params_str)
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        kdf = Scrypt(
            salt=salt,
            length=_KEY_LEN,
            n=int(params["N"]),
            r=int(params["r"]),
            p=int(params["p"]),
        )
        return kdf.derive(password)
    else:
        raise ValueError(f"Unknown password-mode KDF: '{mode}'")


def _parse_params(params_str: str) -> dict[str, str]:
    """Parse ``"key=value,key=value"`` parameter strings."""
    result: dict[str, str] = {}
    for part in params_str.split(","):
        key, _, value = part.partition("=")
        result[key.strip()] = value.strip()
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def encrypt(plaintext: bytes, password: str) -> str:
    """Encrypt *plaintext* with *password* and return an armored string.

    Parameters
    ----------
    plaintext:
        The message to encrypt.
    password:
        A passphrase string.

    Returns
    -------
    str
        An armored DeadPGP message block.
    """
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)

    key, mode_tag, params = _derive_key(password.encode("utf-8"), salt)

    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, plaintext, None)

    headers = {
        "Version": "1",
        "Mode": mode_tag,
        "Salt": b64(salt),
        "Params": params,
        "Nonce": b64(nonce),
    }
    return encode(_LABEL, headers, ciphertext)


def decrypt(armored: str, password: str) -> bytes:
    """Decrypt an armored password-mode message.

    Parameters
    ----------
    armored:
        The armored message string (BEGIN/END block).
    password:
        The passphrase used during encryption.

    Returns
    -------
    bytes
        The decrypted plaintext.

    Raises
    ------
    ValueError
        If the mode is unexpected, headers are missing, or decryption fails.
    """
    label, headers, ciphertext = decode(armored)

    if label != _LABEL:
        raise ValueError(f"Expected label '{_LABEL}', got '{label}'")

    mode = headers.get("Mode", "")
    if not mode.startswith("password-"):
        raise ValueError(
            f"Expected a password-mode message (Mode: password-*), got '{mode}'; "
            "use the correct decrypt function for this message type."
        )

    for field in ("Salt", "Params", "Nonce"):
        if field not in headers:
            raise ValueError(f"Missing required header field '{field}'")

    salt = b64d(headers["Salt"])
    params_str = headers["Params"]
    nonce = b64d(headers["Nonce"])

    key = _derive_key_with_params(password.encode("utf-8"), salt, mode, params_str)

    aead = ChaCha20Poly1305(key)
    try:
        return aead.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError(
            "Decryption failed: wrong password or corrupted message."
        ) from exc
