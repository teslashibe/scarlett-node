#!/usr/bin/env bash
# Import one PKCS#12 code-signing identity into a new temporary keychain for
# sign-macos-bundle.py. The release workflow (the real key, decoded from its
# environment secret) and the PR rehearsal (an ephemeral key) both use this, so
# a rehearsal exercises the release commands. The PKCS#12 file is deleted after
# import and the key is not extractable. The user keychain search list is not
# changed here: the signer adds this keychain only while signing, then restores
# the original list. Requires SCARLETT_MAC_P12_PASSWORD; prints no secret.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo 'usage: import-macos-identity.sh <absolute-identity.p12> <new-absolute.keychain-db> <pinned-sha1>' >&2
  exit 2
fi
p12=$1
keychain=$2
sha1=$3
if [[ "$p12" != /* || ! -f "$p12" || -L "$p12" ]]; then
  echo 'Supply an absolute regular PKCS#12 file' >&2; exit 2
fi
if [[ "$keychain" != /*.keychain-db || -e "$keychain" || -L "$keychain" ]]; then
  echo 'Supply a new absolute .keychain-db path' >&2; exit 2
fi
if [[ ! "$sha1" =~ ^[0-9a-f]{40}$ ]]; then
  echo 'Supply the pinned lowercase certificate SHA-1' >&2; exit 2
fi
if [[ -z "${SCARLETT_MAC_P12_PASSWORD:-}" ]]; then
  echo 'SCARLETT_MAC_P12_PASSWORD is required' >&2; exit 2
fi

umask 077
keychain_password=$(/usr/bin/openssl rand -hex 32)
security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
status=0
security import "$p12" -k "$keychain" -f pkcs12 -x -T /usr/bin/codesign -P "$SCARLETT_MAC_P12_PASSWORD" > /dev/null || status=$?
rm -P "$p12"
if [[ $status -ne 0 ]]; then
  echo 'The signing identity could not be imported' >&2; exit 1
fi
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$keychain_password" "$keychain" > /dev/null
# Without -v: a self-signed identity is listed although macOS does not trust it.
pin=$(printf '%s' "$sha1" | tr 'a-f' 'A-F')
if ! security find-identity -p codesigning "$keychain" | grep -Eq "^[[:space:]]*[0-9]+\) $pin \""; then
  echo 'The imported identity does not match the pinned SHA-1' >&2; exit 1
fi
echo 'Imported the pinned code-signing identity into a temporary keychain'
