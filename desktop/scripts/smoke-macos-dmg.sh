#!/usr/bin/env bash
# Launch the app from a self-signed-stable DMG on a disposable Mac runner. This
# exercises hardened runtime and library validation for the signed bundle; it
# starts no node work, pairing or provider login. CI copies carry no quarantine,
# so Gatekeeper approval is a separate, manual check.
#
# Before launching, the shipped bytes are checked against the signer's
# neighbouring <name>.evidence.json (which the release assembler checks against
# desktop/signing/identities.json): the DMG digest, the DMG signature, and the
# app and sidecars inside the DMG, each with its pinned designated requirement.
# The signer verified the app before packaging; this proves what was packaged.
#
# usage: smoke-macos-dmg.sh <absolute signed .dmg> <new absolute work directory>
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'usage: smoke-macos-dmg.sh <absolute signed .dmg> <new absolute work directory>' >&2
  exit 2
fi
dmg=$1
work=$2
if [[ "$(uname -s)" != Darwin || "$dmg" != /*.dmg || ! -f "$dmg" || "$work" != /* || -e "$work" ]]; then
  echo 'Run on a Mac with an absolute DMG and a new absolute work directory' >&2
  exit 2
fi
if [[ "${GITHUB_ACTIONS:-}" != true ]]; then
  echo 'The launch smoke creates app state; run it only on a disposable CI runner' >&2
  exit 2
fi
evidence=${dmg%.dmg}.evidence.json
if [[ ! -f "$evidence" || -L "$evidence" ]]; then
  echo 'The signed disk image has no neighbouring signing evidence' >&2
  exit 2
fi
if ! sha1=$(python3 - "$dmg" "$evidence" << 'PY'
import hashlib, json, re, sys
from pathlib import Path
dmg, evidence = Path(sys.argv[1]), json.loads(Path(sys.argv[2]).read_text())
sha1 = evidence.get('certificateSha1')
if evidence.get('signature') != 'self-signed-stable' or not isinstance(sha1, str) or not re.fullmatch('[0-9a-f]{40}', sha1) or \
        evidence.get('designatedRequirement') != 'designated => identifier "ai.scarlett.node" and certificate leaf = H"%s"' % sha1:
    raise SystemExit('The evidence does not name one pinned self-signed certificate')
with dmg.open('rb') as stream:
    if hashlib.file_digest(stream, 'sha256').hexdigest() != evidence.get('sha256'):
        raise SystemExit('The disk image differs from its signing evidence')
print(sha1)
PY
); then
  exit 1
fi
pin="certificate leaf = H\"$sha1\""
codesign --verify --strict "-R=identifier \"ai.scarlett.node.dmg\" and $pin" "$dmg"
if pgrep -x scarlett-node-desktop > /dev/null; then
  echo 'Another Scarlett Node desktop is already running' >&2
  exit 1
fi

mkdir -p "$work/mount"
hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$work/mount" "$dmg" > /dev/null
status=0
ditto "$work/mount/Scarlett Node.app" "$work/Scarlett Node.app" || status=$?
hdiutil detach "$work/mount" > /dev/null
if [[ $status -ne 0 ]]; then
  echo 'The app could not be copied out of the disk image' >&2
  exit 1
fi
app="$work/Scarlett Node.app"
codesign --verify --deep --strict "-R=identifier \"ai.scarlett.node\" and $pin" "$app"
if [[ "$(codesign -d -r- "$app" 2> /dev/null)" != "designated => identifier \"ai.scarlett.node\" and $pin" ]]; then
  echo 'The app in the disk image does not carry the pinned designated requirement' >&2
  exit 1
fi
for name in scarlett-node scarlett-prover open-agent-api; do
  codesign --verify --strict "-R=identifier \"ai.scarlett.node.$name\" and $pin" "$app/Contents/MacOS/$name"
done
echo 'The disk image, app and sidecars carry the pinned self-signed signature'

open -n "$app"
sleep 20
if ! pgrep -x scarlett-node-desktop > /dev/null; then
  echo 'The signed app did not stay running for 20 seconds' >&2
  exit 1
fi
echo 'Signed app is running after 20 seconds'

# Ask the app to quit normally, without letting an Apple Event prompt hang CI.
osascript -e 'quit app "Scarlett Node"' > /dev/null 2>&1 &
quitter=$!
for _ in $(seq 1 30); do
  pgrep -x scarlett-node-desktop > /dev/null || break
  sleep 1
done
kill "$quitter" 2> /dev/null || true
if pgrep -x scarlett-node-desktop > /dev/null; then
  echo 'The app did not quit through its Apple Event; stopping it' >&2
  pkill -x scarlett-node-desktop || true
  sleep 5
  if pgrep -x scarlett-node-desktop > /dev/null; then
    echo 'The signed app could not be stopped' >&2
    exit 1
  fi
fi
echo 'Signed app launched from its disk image and quit'
