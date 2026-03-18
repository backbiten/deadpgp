#!/usr/bin/env bash
# keygen.sh — Generate a new OpenPGP key pair with modern algorithm defaults.
#
# Usage:
#   bash keygen.sh
#
# You will be prompted for:
#   - Your real name
#   - Your email address
#   - A strong passphrase (use a password manager or diceware)
#
# The script generates:
#   - An Ed25519 primary (certify + sign) key
#   - A Cv25519 encryption subkey
#
# Requires: GnuPG 2.1+

set -euo pipefail

echo "=== GPG Key Generation (Ed25519 + Cv25519) ==="
echo ""
echo "You will be prompted for your name, email, and passphrase."
echo "Use a strong, randomly generated passphrase."
echo ""

# --full-gen-key provides the interactive wizard.
# For unattended / batch generation see 'gpg --batch' and a parameter file.
gpg --full-gen-key --default-new-key-algo "ed25519/cert,sign+cv25519/encr"

echo ""
echo "=== Key generated successfully ==="
echo ""
echo "Next steps:"
echo "  1. Record your key fingerprint:"
echo "       gpg --list-secret-keys --keyid-format 0xlong <your-email>"
echo "  2. Generate a revocation certificate immediately:"
echo "       bash revocation.sh <FINGERPRINT>"
echo "  3. Export and back up your public key:"
echo "       bash export-import.sh export <your-email>"
