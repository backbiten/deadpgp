#!/usr/bin/env bash
# sign-verify.sh — Create or verify a detached OpenPGP signature.
#
# Usage:
#   bash sign-verify.sh sign   <file> <signer-email-or-fingerprint>
#   bash sign-verify.sh verify <file> [<signature-file>]
#
# A detached signature is stored separately from the data file, which means
# the original file is not modified.
#
# Requires: GnuPG 2.1+

set -euo pipefail

usage() {
  echo "Usage:"
  echo "  $0 sign   <file> <signer-email-or-fingerprint>"
  echo "  $0 verify <file> [<signature-file>]"
  exit 1
}

[[ $# -lt 2 ]] && usage

COMMAND="$1"
shift

case "$COMMAND" in
  sign)
    [[ $# -lt 2 ]] && usage
    INFILE="$1"
    SIGNER="$2"

    if [[ ! -f "$INFILE" ]]; then
      echo "Error: file not found: $INFILE" >&2
      exit 1
    fi

    SIGFILE="${INFILE}.sig"

    echo "=== Signing $INFILE as $SIGNER ==="
    echo "Signature output: $SIGFILE"
    echo ""

    # --detach-sign creates a detached signature.
    # --armor produces ASCII output (readable/pasteable).
    gpg --armor \
        --detach-sign \
        --local-user "$SIGNER" \
        --output "$SIGFILE" \
        "$INFILE"

    echo "Done. Detached signature: $SIGFILE"
    echo ""
    echo "Distribute both $INFILE and $SIGFILE to allow verification."
    ;;

  verify)
    INFILE="$1"
    # Default signature file is <file>.sig; allow override as second argument
    SIGFILE="${2:-${INFILE}.sig}"

    if [[ ! -f "$INFILE" ]]; then
      echo "Error: data file not found: $INFILE" >&2
      exit 1
    fi

    if [[ ! -f "$SIGFILE" ]]; then
      echo "Error: signature file not found: $SIGFILE" >&2
      exit 1
    fi

    echo "=== Verifying signature ==="
    echo "Data:      $INFILE"
    echo "Signature: $SIGFILE"
    echo ""

    # gpg --verify exits 0 on success, non-zero on failure.
    if gpg --verify "$SIGFILE" "$INFILE"; then
      echo ""
      echo "Signature is VALID."
    else
      echo ""
      echo "Signature is INVALID or key is not in the keyring." >&2
      exit 1
    fi
    ;;

  *)
    usage
    ;;
esac
