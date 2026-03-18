#!/usr/bin/env bash
# export-import.sh — Export your public key or import someone else's.
#
# Usage:
#   bash export-import.sh export <email-or-fingerprint>
#   bash export-import.sh import <file.asc>
#
# Requires: GnuPG 2.1+

set -euo pipefail

# Default keyserver — override with: KEYSERVER=hkps://example.com bash export-import.sh ...
KEYSERVER="${KEYSERVER:-hkps://keys.openpgp.org}"

usage() {
  echo "Usage:"
  echo "  $0 export <email-or-fingerprint>   Export public key to stdout and a .asc file"
  echo "  $0 import <file.asc>               Import a public key from an ASCII-armored file"
  exit 1
}

[[ $# -lt 2 ]] && usage

COMMAND="$1"
TARGET="$2"

case "$COMMAND" in
  export)
    OUTFILE="${TARGET//[@.]/_}.asc"
    echo "=== Exporting public key for: $TARGET ==="
    gpg --armor --export "$TARGET" | tee "$OUTFILE"
    echo ""
    echo "Public key written to: $OUTFILE"
    echo ""
    echo "Share this file (or its contents) with anyone who wants to send you"
    echo "encrypted messages or verify your signatures."
    echo ""
    echo "To publish to a keyserver:"
    echo "  gpg --keyserver $KEYSERVER --send-keys $TARGET"
    ;;

  import)
    FILE="$TARGET"
    if [[ ! -f "$FILE" ]]; then
      echo "Error: file not found: $FILE" >&2
      exit 1
    fi
    echo "=== Importing public key from: $FILE ==="
    gpg --import "$FILE"
    echo ""
    echo "After importing, verify the fingerprint out-of-band before trusting the key."
    echo "To mark the key as trusted:"
    echo "  gpg --edit-key <FINGERPRINT>"
    echo "  > trust"
    echo "  > 5  (ultimate trust — only for your own key)"
    echo "  > quit"
    ;;

  *)
    usage
    ;;
esac
