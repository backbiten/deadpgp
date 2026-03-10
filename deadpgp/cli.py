"""DeadPGP command-line interface.

Usage
-----
  deadpgp keygen   [--name NAME] [--out DIR]
  deadpgp encrypt  [--to PUBKEY | --password] [FILE]
  deadpgp decrypt  [--identity KEY | --password] [--break-glass PHRASE] [FILE]
  deadpgp qa       [--direct | --proxy | --all]
  deadpgp doctor

Run ``deadpgp <subcommand> --help`` for details.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------

def cmd_keygen(args: argparse.Namespace) -> int:
    from . import keys as _keys

    out_dir = Path(args.out) if args.out else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)

    key_data = _keys.generate_keypair()
    fp_short = key_data["fingerprint"][:16]

    base = args.name or fp_short

    priv_path = out_dir / f"{base}.key"
    pub_path = out_dir / f"{base}.pub"

    _keys.save_private_key(key_data, priv_path)
    _keys.save_public_key(key_data, pub_path)

    print("Generated new X25519 keypair")
    print(f"  Fingerprint : {key_data['fingerprint']}")
    print(f"  Private key : {priv_path}")
    print(f"  Public key  : {pub_path}")
    print()
    print("Share the public key file with anyone who wants to send you messages.")
    print("Keep the private key file secret and never share it.")
    return 0


# ---------------------------------------------------------------------------
# encrypt
# ---------------------------------------------------------------------------

def cmd_encrypt(args: argparse.Namespace) -> int:
    # ── QA gate (always blocking for encrypt) ────────────────────────────
    from .qa import enforce_gate, QAGateError
    try:
        enforce_gate()
    except QAGateError as exc:
        print(f"deadpgp: BLOCKED by QA gate\n\n{exc}", file=sys.stderr)
        return 2

    # Read plaintext
    if args.file:
        try:
            plaintext = Path(args.file).read_bytes()
        except OSError as exc:
            print(f"deadpgp: error reading input file: {exc}", file=sys.stderr)
            return 1
    else:
        plaintext = sys.stdin.buffer.read()

    if args.password:
        # Password mode
        import getpass
        from . import crypto_pwd

        pw = getpass.getpass("Enter password: ")
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            print("deadpgp: passwords do not match.", file=sys.stderr)
            return 1
        armored = crypto_pwd.encrypt(plaintext, pw)
    else:
        # Public-key mode
        if not args.to:
            print(
                "deadpgp: specify a recipient public key with --to <file>, "
                "or use --password for password mode.",
                file=sys.stderr,
            )
            return 1

        from . import keys as _keys, crypto_box

        try:
            recipient = _keys.load_key_file(args.to)
        except _keys.KeyFileError as exc:
            print(f"deadpgp: {exc}", file=sys.stderr)
            return 1

        armored = crypto_box.encrypt(plaintext, recipient)

    # Write output
    if args.out:
        Path(args.out).write_text(armored, encoding="utf-8")
    else:
        sys.stdout.write(armored)
    return 0


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------

def cmd_decrypt(args: argparse.Namespace) -> int:
    # ── QA gate (blocking; break-glass bypasses with explicit phrase) ─────
    from .qa import enforce_gate, QAGateError, BREAK_GLASS_PHRASE
    try:
        enforce_gate(break_glass=getattr(args, "break_glass", None))
    except QAGateError as exc:
        print(f"deadpgp: BLOCKED by QA gate\n\n{exc}", file=sys.stderr)
        return 2

    # Read armored input
    if args.file:
        try:
            armored = Path(args.file).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"deadpgp: error reading input file: {exc}", file=sys.stderr)
            return 1
    else:
        armored = sys.stdin.read()

    # Detect mode from armor headers if not specified by flags
    from .armor import decode as armor_decode, ArmorError, find_blocks

    # Find first block
    blocks = find_blocks(armored)
    if not blocks:
        blocks = [armored]

    try:
        _, headers, _ = armor_decode(blocks[0])
    except ArmorError as exc:
        print(f"deadpgp: cannot parse message: {exc}", file=sys.stderr)
        return 1

    mode = headers.get("Mode", "")

    if args.password or mode.startswith("password-"):
        # Password mode
        import getpass
        from . import crypto_pwd

        pw = getpass.getpass("Enter password: ")
        try:
            plaintext = crypto_pwd.decrypt(blocks[0], pw)
        except ValueError as exc:
            print(f"deadpgp: decryption failed: {exc}", file=sys.stderr)
            return 1
    else:
        # Public-key mode
        if not args.identity:
            print(
                "deadpgp: specify your private key with --identity <file>, "
                "or use --password for password-mode messages.",
                file=sys.stderr,
            )
            return 1

        from . import keys as _keys, crypto_box

        try:
            identity = _keys.load_key_file(args.identity)
        except _keys.KeyFileError as exc:
            print(f"deadpgp: {exc}", file=sys.stderr)
            return 1

        try:
            plaintext = crypto_box.decrypt(blocks[0], identity)
        except ValueError as exc:
            print(f"deadpgp: decryption failed: {exc}", file=sys.stderr)
            return 1

    # Write output
    if args.out:
        Path(args.out).write_bytes(plaintext)
    else:
        sys.stdout.buffer.write(plaintext)
    return 0


# ---------------------------------------------------------------------------
# qa
# ---------------------------------------------------------------------------

def cmd_qa(args: argparse.Namespace) -> int:
    """Run QA/QC checks and print a report."""
    from . import qa as _qa

    tier = getattr(args, "tier", "direct")

    if tier == "direct":
        report = _qa.run_direct_checks()
    elif tier == "proxy":
        report = _qa.run_proxy_checks()
    elif tier == "all":
        report = _qa.run_all_checks()
    else:
        report = _qa.run_direct_checks()

    report.print_report()
    return 0 if report.passed else 1


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

def cmd_doctor(args: argparse.Namespace) -> int:
    """Validate repository structure."""
    from .doctor import cmd_doctor as _doctor
    return _doctor()


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deadpgp",
        description="DeadPGP – modern encryption for everyone.",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # keygen
    p_keygen = sub.add_parser("keygen", help="Generate a new keypair.")
    p_keygen.add_argument("--name", metavar="NAME", help="Base name for key files.")
    p_keygen.add_argument(
        "--out", metavar="DIR", help="Directory to write key files (default: current dir)."
    )

    # encrypt
    p_enc = sub.add_parser("encrypt", help="Encrypt a message.")
    p_enc.add_argument("--to", metavar="PUBKEY", help="Recipient's public key file.")
    p_enc.add_argument(
        "--password", action="store_true", help="Use password-based encryption."
    )
    p_enc.add_argument(
        "--out", metavar="FILE", help="Write armored output to FILE (default: stdout)."
    )
    p_enc.add_argument("file", nargs="?", metavar="FILE", help="Input file (default: stdin).")

    # decrypt
    p_dec = sub.add_parser("decrypt", help="Decrypt a message.")
    p_dec.add_argument("--identity", metavar="KEY", help="Your private key file.")
    p_dec.add_argument(
        "--password", action="store_true", help="Decrypt a password-based message."
    )
    p_dec.add_argument(
        "--break-glass",
        metavar="PHRASE",
        dest="break_glass",
        help=(
            "Emergency decrypt bypass when QA gate fails. "
            "Requires an exact confirmation phrase — see documentation."
        ),
    )
    p_dec.add_argument(
        "--out", metavar="FILE", help="Write decrypted output to FILE (default: stdout)."
    )
    p_dec.add_argument("file", nargs="?", metavar="FILE", help="Input file (default: stdin).")

    # qa
    p_qa = sub.add_parser("qa", help="Run QA/QC checks.")
    tier_group = p_qa.add_mutually_exclusive_group()
    tier_group.add_argument(
        "--direct",
        dest="tier",
        action="store_const",
        const="direct",
        help="Run fast direct checks only (default).",
    )
    tier_group.add_argument(
        "--proxy",
        dest="tier",
        action="store_const",
        const="proxy",
        help="Run subprocess-based checks (pytest, linter).",
    )
    tier_group.add_argument(
        "--all",
        dest="tier",
        action="store_const",
        const="all",
        help="Run all checks (direct + proxy + docs).",
    )
    p_qa.set_defaults(tier="direct")

    # doctor
    sub.add_parser("doctor", help="Validate expected repository structure.")

    return parser



# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    handlers = {
        "keygen": cmd_keygen,
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "qa": cmd_qa,
        "doctor": cmd_doctor,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
