#!/usr/bin/env bash
# Rehearse the self-signed-stable Mac release with no secrets: every PR runs
# the real signing path against its complete debug app.
#
# A throwaway RSA-3072 certificate with the release extensions and one day of
# validity is imported through import-macos-identity.sh, exactly as the release
# key is. sign-macos-bundle.py then signs a copy of the app and builds the DMG
# in rehearsal mode, so its evidence says "rehearsal": true and can never be
# published. The key, keychain and signing copy are removed on exit.
#
# usage: rehearse-macos-signing.sh <absolute Scarlett Node.app> <new absolute work directory>
# Output: <work>/Scarlett-Node-rehearsal.dmg and its .evidence.json.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'usage: rehearse-macos-signing.sh <absolute Scarlett Node.app> <new absolute work directory>' >&2
  exit 2
fi
app=$1
work=$2
if [[ "$(uname -s)" != Darwin || "$app" != /*.app || ! -d "$app" || "$work" != /* || -e "$work" ]]; then
  echo 'Run on a Mac with an absolute app and a new absolute work directory' >&2
  exit 2
fi
scripts=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
openssl=/usr/bin/openssl
umask 077
mkdir -p "$work/key" "$work/copy"
keychain="$work/rehearsal.keychain-db"

cleanup() {
  local status=$?
  security delete-keychain "$keychain" 2> /dev/null || true
  rm -rf "$work/key" "$work/copy"
  exit "$status"
}
trap cleanup EXIT

# Same extensions as the release certificate (plan section 1).
cat > "$work/key/codesign-ext.cnf" << EOF
[req]
prompt = no
distinguished_name = dn
x509_extensions = ext
[dn]
O = Scarlett Rehearsal
CN = Scarlett Node Rehearsal macOS $("$openssl" rand -hex 4)
[ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
subjectKeyIdentifier = hash
EOF
"$openssl" req -x509 -newkey rsa:3072 -nodes -keyout "$work/key/key.pem" -out "$work/key/cert.pem" \
  -config "$work/key/codesign-ext.cnf" -sha256 -days 1 -set_serial "0x$("$openssl" rand -hex 16)" 2> /dev/null
SCARLETT_MAC_P12_PASSWORD=$("$openssl" rand -hex 24)
export SCARLETT_MAC_P12_PASSWORD
# Legacy PBE-SHA1-3DES with a SHA-1 MAC, matching the release PKCS#12 export.
"$openssl" pkcs12 -export -inkey "$work/key/key.pem" -in "$work/key/cert.pem" -name 'Scarlett Node Rehearsal macOS' \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
  -passout env:SCARLETT_MAC_P12_PASSWORD -out "$work/key/identity.p12"
rm -P "$work/key/key.pem"

identities="$work/rehearsal-identities.json"
python3 "$scripts/signing_identities.py" rehearsal --macos-certificate "$work/key/cert.pem" --output "$identities"
export SCARLETT_SIGNING_REHEARSAL=1 SCARLETT_SIGNING_IDENTITIES="$identities"
sha1=$(python3 "$scripts/signing_identities.py" get macos.sha1)
"$scripts/import-macos-identity.sh" "$work/key/identity.p12" "$keychain" "$sha1"
unset SCARLETT_MAC_P12_PASSWORD

# Sign a copy so the tested debug app and its uploaded artifacts stay unsigned.
ditto "$app" "$work/copy/Scarlett Node.app"
search_list=$(security list-keychains -d user)
dmg="$work/Scarlett-Node-rehearsal.dmg"
SCARLETT_SIGNING_SCHEME=self-signed-stable SCARLETT_MAC_KEYCHAIN="$keychain" \
  python3 "$scripts/sign-macos-bundle.py" "$work/copy/Scarlett Node.app" "$dmg"
if [[ "$(security list-keychains -d user)" != "$search_list" ]]; then
  echo 'The signer did not restore the user keychain search list' >&2
  exit 1
fi

# Independent checks, not through the signer's own helpers.
requirement=$(python3 "$scripts/signing_identities.py" get macos.designatedRequirement)
for code in "$work/copy/Scarlett Node.app" "$dmg"; do
  codesign --verify --strict "-R=certificate leaf = H\"$sha1\"" "$code"
done
if [[ "$(codesign -d -r- "$work/copy/Scarlett Node.app" 2> /dev/null)" != "$requirement" ]]; then
  echo 'Signed app does not carry the pinned designated requirement' >&2
  exit 1
fi
python3 - "$dmg" "$identities" << 'PY'
import hashlib, json, sys
from pathlib import Path
dmg = Path(sys.argv[1])
identity = json.loads(Path(sys.argv[2]).read_text())['macos']
evidence = json.loads(dmg.with_suffix('.evidence.json').read_text())
assert evidence['rehearsal'] is True, 'Rehearsal evidence must be marked'
assert evidence['signature'] == 'self-signed-stable'
assert (evidence['certificateSha1'], evidence['certificateSha256']) == (identity['sha1'], identity['sha256'])
assert evidence['designatedRequirement'] == identity['designatedRequirement']
assert evidence['sha256'] == hashlib.sha256(dmg.read_bytes()).hexdigest()
print(json.dumps({'rehearsal': True, 'signature': evidence['signature'], 'designatedRequirement': evidence['designatedRequirement'],
                  'dmgBytes': evidence['bytes'], 'notarization': evidence['notarization']}))
PY
echo 'Self-signed Mac rehearsal signed, sealed and verified the complete app and DMG'
