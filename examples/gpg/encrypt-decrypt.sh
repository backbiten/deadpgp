#!/usr/bin/env bash
# encrypt-decrypt.sh — Encrypt or decrypt a file using OpenPGP.
#
# Usage:
#   bash encrypt-decrypt.sh encrypt <file> <recipient-email-or-fingerprint> [<additional-recipient> ...]
#   bash encrypt-decrypt.sh decrypt <file.gpg>
#
# Requires: GnuPG 2.1+

set -euo pipefail

usage() {
  echo "Usage:"
  echo "  $0 encrypt <file> <recipient> [<recipient2> ...]"
  echo "  $0 decrypt <file.gpg>"
  exit 1
}

[[ $# -lt 2 ]] && usage

COMMAND="$1"
shift

case "$COMMAND" in
  encrypt)
    INFILE="$1"
    shift

    if [[ $# -lt 1 ]]; then
      echo "Error: at least one recipient is required." >&2
      usage
    fi

    if [[ ! -f "$INFILE" ]]; then
      echo "Error: input file not found: $INFILE" >&2
      exit 1
    fi

    # Build recipient flags
    RECIPIENT_FLAGS=()
    for RECIP in "$@"; do
      RECIPIENT_FLAGS+=("--recipient" "$RECIP")
    done

    OUTFILE="${INFILE}.gpg"

    echo "=== Encrypting $INFILE ==="
    echo "Recipients: $*"
    echo "Output:     $OUTFILE"
    echo ""

    gpg --armor \
        --output "$OUTFILE" \
        "${RECIPIENT_FLAGS[@]}" \
        --encrypt "$INFILE"

    echo "Done. Encrypted file: $OUTFILE"
    echo ""
    echo "Note: --armor produces a text file (.asc-style); omit --armor for binary .gpg output."
    ;;

  decrypt)
    INFILE="$1"

    if [[ ! -f "$INFILE" ]]; then
      echo "Error: input file not found: $INFILE" >&2
      exit 1
    fi

    # Derive output filename by stripping .gpg or .asc suffix
    OUTFILE="${INFILE%.gpg}"
    OUTFILE="${OUTFILE%.asc}"
    if [[ "$OUTFILE" == "$INFILE" ]]; then
      OUTFILE="${INFILE}.decrypted"
    fi

    echo "=== Decrypting $INFILE ==="
    echo "Output: $OUTFILE"
    echo ""

    gpg --output "$OUTFILE" --decrypt "$INFILE"

    echo "Done. Decrypted file: $OUTFILE"
    ;;

  *)
    usage
    ;;
esac
