#!/usr/bin/env bash
# Build, sign and verify one Scarlett Node Mac installer on a local Mac when
# GitHub Actions is unavailable. This repeats the macOS `sign` job of
# .github/workflows/desktop-release.yml with the release commit's own scripts,
# in the same order:
#
#   release-manifest.py check-version, build-complete-runtime.sh, npm ci,
#   tauri build --bundles app --no-sign, import-macos-identity.sh into a
#   temporary keychain, sign-macos-bundle.py (self-signed-stable), keychain
#   removal, then the DMG checks.
#
# Then it applies release-manifest.py's own per-platform assembler checks to the
# output directory. Nothing is published, tagged or pushed, and nothing is
# assembled: `release-manifest.py assemble` still needs all three platforms and
# a workflow run (see desktop/README.md, "Local release when Actions is
# unavailable").
#
# The release commit (default origin/main) is fetched at depth 1 into a new
# repository under the work directory, as actions/checkout does, so local edits
# never reach the build.
#
# DMG checks: this checkout's `smoke-macos-dmg.sh --verify-only` checks the DMG
# digest against the evidence and verifies the DMG, app and sidecars against
# their pinned designated requirements. It does not launch the app: the launch
# smoke creates app state for ai.scarlett.node and shares the app's
# single-instance socket, so it runs only on a disposable Mac.
#
# Secrets: the PKCS#12 file is copied into a private directory under the work
# directory (the importer deletes that copy). Its passphrase is read from the
# login keychain with `security find-generic-password -w` into a shell variable
# and reaches import-macos-identity.sh only through SCARLETT_MAC_P12_PASSWORD,
# as in the release workflow. This script never prints it, writes it or puts it
# on a command line. The temporary keychain is deleted on every exit.
#
# usage: local-release.sh <version> <darwin-arm64|darwin-amd64> <new absolute work directory>
#
# darwin-amd64 needs an Intel Mac with x86_64 Node 26, Go and Rust 1.95 (Rosetta
# stops at the provider version-check timeout; see desktop/README.md).
#
# Optional environment:
#   SCARLETT_RELEASE_COMMIT   exact commit on origin/main to build (default: origin/main)
#   SCARLETT_MAC_P12          PKCS#12 identity, never modified (default: ~/.scarlett-signing/macos.p12)
#   SCARLETT_MAC_P12_SERVICE  login keychain service holding its passphrase (default: scarlett-signing)
#   SCARLETT_MAC_P12_ACCOUNT  login keychain account holding its passphrase (default: macos-export)
#   CARGO_TARGET_DIR          target directory for the Tauri build only (default: <work>/target)
#
# Output, under the work directory:
#   signed-<platform>/  Scarlett-Node-<version>-<platform>.dmg, its .evidence.json
#                       and COMPONENTS.json: the signing job's uploaded artifact
#   LOCAL-BUILD.json    commit, toolchains and host of this local build
set -euo pipefail

die() {
  echo "local-release: $*" >&2
  exit 1
}
step() {
  printf '\n==> [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

if [[ $# -ne 3 ]]; then
  echo 'usage: local-release.sh <version> <darwin-arm64|darwin-amd64> <new absolute work directory>' >&2
  exit 2
fi
version=$1
platform=$2
work=$3
case "$platform" in
  darwin-arm64) native=darwin-arm64 goarch=arm64 triple=aarch64-apple-darwin machine=arm64 ;;
  darwin-amd64) native=darwin-x64 goarch=amd64 triple=x86_64-apple-darwin machine=x86_64 ;;
  *) echo 'The platform is darwin-arm64 or darwin-amd64' >&2; exit 2 ;;
esac
if [[ "$(uname -s)" != Darwin ]]; then
  die 'Mac releases are built on a Mac'
fi
if [[ "$work" != /* || -e "$work" || -L "$work" ]]; then
  die 'Supply a new absolute work directory'
fi
p12=${SCARLETT_MAC_P12:-$HOME/.scarlett-signing/macos.p12}
service=${SCARLETT_MAC_P12_SERVICE:-scarlett-signing}
account=${SCARLETT_MAC_P12_ACCOUNT:-macos-export}
if [[ "$p12" != /* || ! -f "$p12" || -L "$p12" ]]; then
  die 'SCARLETT_MAC_P12 must be an absolute regular PKCS#12 file'
fi
# Release signing never uses a rehearsal identities file.
unset SCARLETT_SIGNING_REHEARSAL SCARLETT_SIGNING_IDENTITIES SCARLETT_MAC_P12_PASSWORD

scripts=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repository=$(git -C "$scripts" rev-parse --path-format=absolute --git-common-dir)
main=$(git -C "$scripts" rev-parse --verify 'refs/remotes/origin/main^{commit}')
commit=${SCARLETT_RELEASE_COMMIT:-$main}
if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  die 'SCARLETT_RELEASE_COMMIT must be a full lowercase commit'
fi
if ! git -C "$scripts" merge-base --is-ancestor "$commit" "$main"; then
  die 'The release commit must be on origin/main; fetch first'
fi

src="$work/src"
signed="$work/signed-$platform"
dmg="$signed/Scarlett-Node-$version-$platform.dmg"
signing="$work/signing"
keychain="$signing/release.keychain-db"
target=${CARGO_TARGET_DIR:-$work/target}
# The signer changes the user keychain search list while it signs, so two local
# releases (darwin-arm64 and darwin-amd64 builds in parallel) sign one at a time.
lock="${TMPDIR:-/tmp}/scarlett-local-release-signing.lock"
locked=false
if [[ "$target" != /* ]]; then
  die 'CARGO_TARGET_DIR must be absolute'
fi

cleanup() {
  local status=$? list
  trap - EXIT
  if [[ -e "$keychain" ]]; then
    security delete-keychain "$keychain" || status=1
  fi
  if [[ -e "$signing/identity.p12" ]]; then
    rm -P "$signing/identity.p12" || status=1
  fi
  rm -rf "$signing"
  if [[ "$locked" == true ]]; then
    rmdir "$lock" || status=1
  fi
  # Read the list first: grep -q in a pipeline under pipefail can mask a match.
  list=$(security list-keychains -d user)
  if grep -qF -- "$keychain" <<< "$list"; then
    echo 'local-release: the signing keychain is still in the search list' >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

step "Checking the host and toolchains for $platform"
translated=$(sysctl -n sysctl.proc_translated 2> /dev/null || echo 0)
if [[ "$(uname -m)" != "$machine" ]]; then
  die "Run $platform builds on a $machine Mac"
fi
if [[ "$(node -p 'process.platform + "-" + process.arch')" != "$native" ]]; then
  die "node on PATH must be the $native build"
fi
if [[ "$(node -p 'process.versions.node.split(".")[0]')" != 26 ]]; then
  die 'The desktop build uses Node 26'
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || die 'python3 3.11 or newer is required'
umask 022
mkdir -p "$work" "$target"

step "Fetching $commit into a clean checkout"
git init -q "$src"
git -C "$src" fetch -q --depth=1 "file://$repository" "$commit"
git -C "$src" -c advice.detachedHead=false checkout -q --detach FETCH_HEAD
if [[ "$(git -C "$src" rev-parse HEAD)" != "$commit" ]]; then
  die 'The clean checkout is not the release commit'
fi
cd "$src"

step 'Requiring the reviewed version and signing pin'
python3 desktop/scripts/release-manifest.py check-version "$version"
sha1=$(python3 desktop/scripts/signing_identities.py get macos.sha1)
echo "Pinned macOS certificate SHA-1: $sha1"

# Go per go.mod, exactly; the go command fetches and verifies that toolchain.
go_version=$(awk '$1 == "go" { print $2; exit }' go.mod)
export GOTOOLCHAIN="go$go_version"
if [[ "$(go env GOVERSION)" != "go$go_version" ]]; then
  die "Go $go_version is required"
fi
if [[ "$(go env GOOS GOARCH GOHOSTARCH | tr '\n' ' ')" != "darwin $goarch $goarch " ]]; then
  die "go must be a native darwin/$goarch toolchain"
fi
rustup toolchain install 1.95 --profile minimal
if [[ "$(rustc +1.95 -vV | sed -n 's/^host: //p')" != "$triple" ]]; then
  die "Rust 1.95 must be the native $triple toolchain"
fi
go version
rustc +1.95 --version
echo "node $(node --version), npm $(npm --version), $(python3 --version)"

step 'Building reviewed components and preparing the complete native runtime'
# build-complete-runtime.sh reads the prover from prover/target in this checkout.
env -u CARGO_TARGET_DIR desktop/scripts/build-complete-runtime.sh "$native" "$work/runtime"

step 'Installing desktop build dependencies'
npm --prefix desktop ci --ignore-scripts

step 'Building the unsigned Mac release app'
rm -rf "$target/release/bundle/macos"
(cd desktop && CARGO_TARGET_DIR="$target" npm run tauri build -- --bundles app --no-sign --config src-tauri/tauri.complete.generated.json)
built="$target/release/bundle/macos/Scarlett Node.app"
if [[ ! -d "$built" ]]; then
  die 'Tauri did not produce the unsigned app'
fi

step 'Waiting for exclusive use of the keychain search list'
until mkdir "$lock" 2> /dev/null; do
  echo "Another local release is signing; waiting for $lock to be removed"
  sleep 15
done
locked=true

step 'Importing the Mac signing key into a temporary keychain'
(umask 077 && mkdir "$signing" && cp "$p12" "$signing/identity.p12")
password=$(security find-generic-password -s "$service" -a "$account" -w) ||
  die 'The PKCS#12 passphrase is not in the login keychain'
# Creates the keychain, imports with -T /usr/bin/codesign, deletes the PKCS#12
# copy, sets the key partition list and checks the pinned SHA-1.
SCARLETT_MAC_P12_PASSWORD=$password desktop/scripts/import-macos-identity.sh "$signing/identity.p12" "$keychain" "$sha1"
unset password

step 'Signing the Mac app and disk image'
mkdir "$work/release" "$signed"
# Sign a copy so the unsigned build remains as provenance.
ditto "$built" "$work/release/Scarlett Node.app"
search_list=$(security list-keychains -d user)
SCARLETT_SIGNING_SCHEME=self-signed-stable SCARLETT_MAC_KEYCHAIN="$keychain" python3 desktop/scripts/sign-macos-bundle.py \
  "$work/release/Scarlett Node.app" "$dmg"
if [[ "$(security list-keychains -d user)" != "$search_list" ]]; then
  die 'The signer did not restore the user keychain search list'
fi
cp "$work/release/Scarlett Node.app/Contents/Resources/runtime/COMPONENTS.json" "$signed/COMPONENTS.json"

step 'Removing the Mac signing keychain'
security delete-keychain "$keychain"
rm -rf "$signing"
list=$(security list-keychains -d user)
if grep -qF -- "$keychain" <<< "$list"; then
  die 'The signing keychain is still in the search list'
fi
rmdir "$lock"
locked=false

step 'Verifying the signed disk image, app and sidecars (no launch)'
"$scripts/smoke-macos-dmg.sh" --verify-only "$dmg" "$work/smoke"

step 'Checking the signed output with the release assembler rules'
python3 - desktop/scripts/release-manifest.py "$signed" "$platform" "$commit" << 'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location('release_manifest', sys.argv[1])
manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest)
identities = manifest.signing_identities.load({})
if identities['rehearsal']:
    raise SystemExit('Rehearsal identities never assemble a release')
item = manifest.verify_platform(sys.argv[2], sys.argv[3], identities, sys.argv[4])
print('Assembler accepts %s: %s  %s (%d bytes)' % (sys.argv[3], item['sha256'], item['installer'].name, item['bytes']))
PY

step 'Recording local build provenance'
python3 - "$work/LOCAL-BUILD.json" "$dmg" "$version" "$platform" "$commit" "$translated" \
  "$(go version)" "$(rustc +1.95 --version)" "$(node --version)" "$(npm --version)" "$(sw_vers -productVersion)" << 'PY'
import hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
out, dmg, version, platform, commit, translated, go, rust, node, npm, macos = sys.argv[1:]
dmg = Path(dmg)
with dmg.open('rb') as stream:
    sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
record = {'schemaVersion': 1, 'version': version, 'platform': platform, 'nodeCommit': commit,
          'builtAt': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
          'build': 'local: desktop/scripts/local-release.sh (not a GitHub Actions run)',
          'host': {'macos': macos, 'rosetta': translated == '1'},
          'toolchains': {'go': go, 'rust': rust, 'node': node, 'npm': npm},
          'installer': {'filename': dmg.name, 'bytes': dmg.stat().st_size, 'sha256': sha256},
          'checks': {'signing': 'sign-macos-bundle.py self-signed-stable',
                     'dmg': 'smoke-macos-dmg.sh --verify-only', 'assembler': 'release-manifest.py verify_platform',
                     'launch': 'not run: needs a disposable Mac'}}
with open(out, 'x') as stream:
    json.dump(record, stream, indent=2)
    stream.write('\n')
PY
ls -l "$signed"
echo "Signed $platform installer and evidence: $signed"
echo 'Not launched, assembled or published. Launch it on a disposable Mac before release.'
