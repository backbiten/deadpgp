"""
Command-line interface for deadpgp.

Usage
-----
Generate a key pair::

    deadpgp keygen --out alice

Encrypt a file for a recipient::

    deadpgp encrypt --recipient alice.pub --in plaintext.txt --out message.asc

Decrypt a message::

    deadpgp decrypt --key alice.key --in message.asc --out plaintext.txt

Sign a file::

    deadpgp sign --key alice.key --in document.txt --out document.sig.asc

Verify a signature::

    deadpgp verify --key alice.pub --in document.txt --sig document.sig.asc
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import (
    generate_keypair,
    export_private_key,
    export_public_key,
    load_private_key,
    load_public_key,
    encrypt,
    decrypt,
    sign,
    verify,
    armor,
    dearmor,
)


def _cmd_keygen(args: argparse.Namespace) -> None:
    key_size = args.key_size
    print(f"Generating {key_size}-bit RSA key pair …", file=sys.stderr)
    private_key, public_key = generate_keypair(key_size)

    password = None
    if args.passphrase:
        password = args.passphrase.encode()

    priv_pem = export_private_key(private_key, password=password)
    pub_pem = export_public_key(public_key)

    base = args.out
    priv_path = Path(f"{base}.key")
    pub_path = Path(f"{base}.pub")

    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)

    print(f"Private key → {priv_path}", file=sys.stderr)
    print(f"Public key  → {pub_path}", file=sys.stderr)


def _cmd_encrypt(args: argparse.Namespace) -> None:
    pub_pem = Path(args.recipient).read_bytes()
    public_key = load_public_key(pub_pem)

    plaintext = Path(args.input).read_bytes()
    ciphertext = encrypt(plaintext, public_key)

    armored = armor(ciphertext, "MESSAGE")
    Path(args.output).write_text(armored, encoding="ascii")
    print(f"Encrypted → {args.output}", file=sys.stderr)


def _cmd_decrypt(args: argparse.Namespace) -> None:
    priv_pem = Path(args.key).read_bytes()
    password = args.passphrase.encode() if args.passphrase else None
    private_key = load_private_key(priv_pem, password=password)

    armored_text = Path(args.input).read_text(encoding="ascii")
    ciphertext, _ = dearmor(armored_text)

    plaintext = decrypt(ciphertext, private_key)
    Path(args.output).write_bytes(plaintext)
    print(f"Decrypted → {args.output}", file=sys.stderr)


def _cmd_sign(args: argparse.Namespace) -> None:
    priv_pem = Path(args.key).read_bytes()
    password = args.passphrase.encode() if args.passphrase else None
    private_key = load_private_key(priv_pem, password=password)

    message = Path(args.input).read_bytes()
    signature = sign(message, private_key)

    armored = armor(signature, "SIGNATURE")
    Path(args.output).write_text(armored, encoding="ascii")
    print(f"Signature  → {args.output}", file=sys.stderr)


def _cmd_verify(args: argparse.Namespace) -> None:
    pub_pem = Path(args.key).read_bytes()
    public_key = load_public_key(pub_pem)

    message = Path(args.input).read_bytes()

    armored_text = Path(args.sig).read_text(encoding="ascii")
    signature, _ = dearmor(armored_text)

    try:
        verify(message, signature, public_key)
        print("Signature is VALID.", file=sys.stderr)
    except Exception as exc:
        print(f"Signature is INVALID: {exc}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="deadpgp",
        description="Old PGP protocols, reinvented for the 21st century.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # keygen
    p_keygen = sub.add_parser("keygen", help="Generate an RSA key pair")
    p_keygen.add_argument("--out", required=True, metavar="BASE",
                          help="Output base name (produces BASE.key and BASE.pub)")
    p_keygen.add_argument("--key-size", type=int, default=4096, metavar="BITS",
                          help="RSA key size in bits (default: 4096)")
    p_keygen.add_argument("--passphrase", metavar="PASS",
                          help="Encrypt private key with this passphrase")

    # encrypt
    p_enc = sub.add_parser("encrypt", help="Encrypt a file")
    p_enc.add_argument("--recipient", required=True, metavar="PUBKEY",
                       help="Recipient public key file (.pub)")
    p_enc.add_argument("--in", dest="input", required=True, metavar="FILE",
                       help="Input plaintext file")
    p_enc.add_argument("--out", dest="output", required=True, metavar="FILE",
                       help="Output armored ciphertext file")

    # decrypt
    p_dec = sub.add_parser("decrypt", help="Decrypt a file")
    p_dec.add_argument("--key", required=True, metavar="PRIVKEY",
                       help="Private key file (.key)")
    p_dec.add_argument("--in", dest="input", required=True, metavar="FILE",
                       help="Input armored ciphertext file")
    p_dec.add_argument("--out", dest="output", required=True, metavar="FILE",
                       help="Output plaintext file")
    p_dec.add_argument("--passphrase", metavar="PASS",
                       help="Passphrase for encrypted private key")

    # sign
    p_sign = sub.add_parser("sign", help="Sign a file")
    p_sign.add_argument("--key", required=True, metavar="PRIVKEY",
                        help="Private key file (.key)")
    p_sign.add_argument("--in", dest="input", required=True, metavar="FILE",
                        help="Input file to sign")
    p_sign.add_argument("--out", dest="output", required=True, metavar="FILE",
                        help="Output armored signature file")
    p_sign.add_argument("--passphrase", metavar="PASS",
                        help="Passphrase for encrypted private key")

    # verify
    p_verify = sub.add_parser("verify", help="Verify a signature")
    p_verify.add_argument("--key", required=True, metavar="PUBKEY",
                          help="Signer's public key file (.pub)")
    p_verify.add_argument("--in", dest="input", required=True, metavar="FILE",
                          help="Input file that was signed")
    p_verify.add_argument("--sig", required=True, metavar="FILE",
                          help="Armored signature file")

    args = parser.parse_args()

    commands = {
        "keygen": _cmd_keygen,
        "encrypt": _cmd_encrypt,
        "decrypt": _cmd_decrypt,
        "sign": _cmd_sign,
        "verify": _cmd_verify,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
