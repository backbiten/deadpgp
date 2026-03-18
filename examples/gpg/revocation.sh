#!/usr/bin/env bash
# revocation.sh — Generate and/or import a revocation certificate.
#
# Usage:
#   bash revocation.sh generate <FINGERPRINT>
#   bash revocation.sh import   <revocation-cert.asc> [--send-keys]
#
# A revocation certificate should be generated immediately after key creation
# and stored securely offline. If your key is ever compromised or lost, import
# the certificate to mark the key as revoked in your keyring and (optionally)
# publish the revocation to a keyserver.
#
# Requires: GnuPG 2.1+

set -euo pipefail

# Default keyserver — override with: KEYSERVER=hkps://example.com bash revocation.sh ...
KEYSERVER="${KEYSERVER:-hkps://keys.openpgp.org}"

usage() {
  echo "Usage:"
  echo "  $0 generate <FINGERPRINT>"
  echo "  $0 import   <revocation-cert.asc> [--send-keys]"
  exit 1
}

[[ $# -lt 2 ]] && usage

COMMAND="$1"
shift

case "$COMMAND" in
  generate)
    FINGERPRINT="$1"
    OUTFILE="revoke-${FINGERPRINT}.asc"

    echo "=== Generating revocation certificate for $FINGERPRINT ==="
    echo "Output: $OUTFILE"
    echo ""
    echo "WARNING: Store this file securely offline (e.g., encrypted USB drive)."
    echo "Anyone who obtains this file can revoke your key."
    echo ""

    gpg --output "$OUTFILE" --gen-revoke "$FINGERPRINT"

    echo ""
    echo "Revocation certificate saved to: $OUTFILE"
    echo ""
    echo "Recommended storage:"
    echo "  - Encrypt a copy: gpg --symmetric $OUTFILE"
    echo "  - Store on an offline, physically secured medium."
    echo "  - Keep a separate printed/paper copy in a secure location."
    ;;

  import)
    CERTFILE="$1"
    SEND_KEYS=false
    if [[ "${2:-}" == "--send-keys" ]]; then
      SEND_KEYS=true
    fi

    if [[ ! -f "$CERTFILE" ]]; then
      echo "Error: file not found: $CERTFILE" >&2
      exit 1
    fi

    echo "=== Importing revocation certificate: $CERTFILE ==="
    echo ""
    echo "This will mark the affected key as REVOKED in your keyring."
    read -r -p "Are you sure? [yes/N] " CONFIRM
    if [[ "$CONFIRM" != "yes" ]]; then
      echo "Aborted."
      exit 0
    fi

    gpg --import "$CERTFILE"
    echo ""
    echo "Key revoked in local keyring."

    if [[ "$SEND_KEYS" == true ]]; then
      # Extract the fingerprint from the cert file
      FINGERPRINT=$(gpg --with-colons --import-options show-only --import "$CERTFILE" 2>/dev/null \
        | awk -F: '/^fpr:/ { print $10; exit }')
      if [[ -n "$FINGERPRINT" ]]; then
        echo ""
        echo "Publishing revocation to $KEYSERVER ..."
        gpg --keyserver "$KEYSERVER" --send-keys "$FINGERPRINT"
        echo "Done."
      else
        echo "Warning: could not determine fingerprint to send to keyserver." >&2
      fi
    else
      echo ""
      echo "To publish the revocation to a keyserver:"
      echo "  gpg --keyserver $KEYSERVER --send-keys <FINGERPRINT>"
    fi
    ;;

  *)
    usage
    ;;
esac
