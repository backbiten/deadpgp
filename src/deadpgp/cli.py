"""Command-line interface for deadpgp.

Usage
-----
    deadpgp keygen --type rsa --output mykey
    deadpgp encrypt --recipient mykey.pub --output msg.dpgp plaintext.txt
    deadpgp decrypt --key mykey.pem --output plaintext.txt msg.dpgp
    deadpgp sign --key mykey.pem --output msg.sig plaintext.txt
    deadpgp verify --key mykey.pub plaintext.txt msg.sig
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import keys as _keys
from . import encryption as _enc
from . import signing as _sig
from . import armor as _armor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def _read_file(path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        _die(str(exc))


def _write_file(path: str, data: bytes) -> None:
    try:
        Path(path).write_bytes(data)
    except OSError as exc:
        _die(str(exc))


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_keygen(args: argparse.Namespace) -> None:
    key_type: str = args.type.lower()
    output: str = args.output

    if key_type == "rsa":
        priv, pub = _keys.generate_rsa_keypair(args.bits)
    elif key_type == "ec":
        priv, pub = _keys.generate_ec_keypair(args.curve)
    elif key_type == "ed25519":
        priv, pub = _keys.generate_ed25519_keypair()
    elif key_type == "x25519":
        priv, pub = _keys.generate_x25519_keypair()
    else:
        _die(f"Unknown key type '{key_type}'. Choose: rsa, ec, ed25519, x25519")

    password: bytes | None = None
    if args.passphrase:
        password = args.passphrase.encode()

    priv_pem = _keys.serialize_private_key(priv, password)
    pub_pem = _keys.serialize_public_key(pub)

    priv_path = output if output.endswith(".pem") else output + ".pem"
    pub_path = output + ".pub" if not output.endswith(".pem") else output[:-4] + ".pub"

    _write_file(priv_path, priv_pem)
    _write_file(pub_path, pub_pem)
    print(f"Private key: {priv_path}")
    print(f"Public key:  {pub_path}")


def cmd_encrypt(args: argparse.Namespace) -> None:
    pub_pem = _read_file(args.recipient)
    pub_key = _keys.load_public_key(pub_pem)
    plaintext = _read_file(args.input)

    ciphertext = _enc.encrypt(plaintext, pub_key)
    armored = _armor.armor(ciphertext, _armor.ARMOR_MESSAGE)

    output = args.output or (args.input + ".dpgp")
    _write_file(output, armored.encode())
    print(f"Encrypted: {output}")


def cmd_decrypt(args: argparse.Namespace) -> None:
    password: bytes | None = args.passphrase.encode() if args.passphrase else None
    priv_pem = _read_file(args.key)
    priv_key = _keys.load_private_key(priv_pem, password)

    armored_bytes = _read_file(args.input)
    try:
        ciphertext, armor_type = _armor.dearmor(armored_bytes.decode())
    except (ValueError, UnicodeDecodeError) as exc:
        _die(f"Failed to de-armor input: {exc}")

    if armor_type != _armor.ARMOR_MESSAGE:
        _die(f"Expected armor type MESSAGE, got {armor_type}")

    try:
        plaintext = _enc.decrypt(ciphertext, priv_key)
    except ValueError as exc:
        _die(str(exc))

    output = args.output or args.input.removesuffix(".dpgp")
    _write_file(output, plaintext)
    print(f"Decrypted: {output}")


def cmd_sign(args: argparse.Namespace) -> None:
    password: bytes | None = args.passphrase.encode() if args.passphrase else None
    priv_pem = _read_file(args.key)
    priv_key = _keys.load_private_key(priv_pem, password)

    message = _read_file(args.input)
    signature = _sig.sign(message, priv_key)
    armored = _armor.armor(signature, _armor.ARMOR_SIGNATURE)

    output = args.output or (args.input + ".sig")
    _write_file(output, armored.encode())
    print(f"Signature: {output}")


def cmd_verify(args: argparse.Namespace) -> None:
    pub_pem = _read_file(args.key)
    pub_key = _keys.load_public_key(pub_pem)

    message = _read_file(args.input)
    armored_bytes = _read_file(args.signature)
    try:
        sig_bytes, armor_type = _armor.dearmor(armored_bytes.decode())
    except (ValueError, UnicodeDecodeError) as exc:
        _die(f"Failed to de-armor signature: {exc}")

    if armor_type != _armor.ARMOR_SIGNATURE:
        _die(f"Expected armor type SIGNATURE, got {armor_type}")

    if _sig.verify(message, sig_bytes, pub_key):
        print("Signature valid.")
    else:
        print("Signature INVALID.", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deadpgp",
        description="Revamped PGP-style encryption with modern cryptography",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # keygen
    kg = sub.add_parser("keygen", help="Generate a key pair")
    kg.add_argument(
        "--type", default="rsa",
        choices=["rsa", "ec", "ed25519", "x25519"],
        help="Key type (default: rsa)",
    )
    kg.add_argument("--bits", type=int, default=4096, help="RSA key size (default: 4096)")
    kg.add_argument("--curve", default="secp256r1", help="EC curve (default: secp256r1)")
    kg.add_argument("--passphrase", help="Passphrase to protect the private key")
    kg.add_argument("--output", required=True, help="Base path for output key files")

    # encrypt
    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("--recipient", required=True, help="Recipient public key file")
    enc.add_argument("--output", help="Output file (default: <input>.dpgp)")
    enc.add_argument("input", help="Plaintext file to encrypt")

    # decrypt
    dec = sub.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("--key", required=True, help="Private key file")
    dec.add_argument("--passphrase", help="Passphrase for encrypted private key")
    dec.add_argument("--output", help="Output file")
    dec.add_argument("input", help="Encrypted file (.dpgp)")

    # sign
    sg = sub.add_parser("sign", help="Sign a file")
    sg.add_argument("--key", required=True, help="Private key file")
    sg.add_argument("--passphrase", help="Passphrase for encrypted private key")
    sg.add_argument("--output", help="Output signature file (default: <input>.sig)")
    sg.add_argument("input", help="File to sign")

    # verify
    vf = sub.add_parser("verify", help="Verify a signature")
    vf.add_argument("--key", required=True, help="Signer public key file")
    vf.add_argument("input", help="File whose signature should be verified")
    vf.add_argument("signature", help="Signature file (.sig)")

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        "keygen": cmd_keygen,
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "sign": cmd_sign,
        "verify": cmd_verify,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
