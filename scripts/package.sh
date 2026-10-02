#!/bin/sh
set -eu
umask 077
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=${1:?usage: package.sh VERSION [OUTPUT_DIRECTORY]}
case "$version" in ''|*[!A-Za-z0-9._-]*|.*|-*) echo 'Invalid bundle version' >&2; exit 1;; esac
[ ${#version} -le 80 ] || exit 1
out=${2:-"$repo/dist"}
case "$out" in /*) ;; *) out="$PWD/$out";; esac
case "$(uname -s):$(uname -m)" in
  Linux:x86_64) platform=linux-amd64;;
  Darwin:arm64) platform=darwin-arm64;;
  Darwin:x86_64) platform=darwin-amd64;;
  *) echo 'Unsupported bundle platform' >&2; exit 1;;
esac
[ "$(go env GOOS)-$(go env GOARCH)" = "$platform" ] || { echo 'Package on the native Go/Rust platform' >&2; exit 1; }
mkdir -p "$out"
stage=$(mktemp -d "$out/.package.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
name="scarlett-node-$version-$platform"
mkdir "$stage/$name"
bundle="$stage/$name"
(cd "$repo" && CGO_ENABLED=0 go build -trimpath -o "$bundle/scarlett-node" .)
(cd "$repo/prover" && cargo build --release --locked)
cp "$repo/prover/target/release/scarlett-prover" "$bundle/"
module=$(cd "$repo" && go list -m -f '{{.Dir}}' github.com/teslashibe/open-agent-api)
cp "$module/codex_profile.json" "$module/codex_scaffold.json" "$bundle/"
cp "$repo/scripts/install.sh" "$repo/packaging/node.env.example" "$repo/packaging/scarlett-node.service" "$repo/packaging/INSTALL.md" "$bundle/"
printf '%s\n' "$version" > "$bundle/VERSION"
printf '%s\n' "$platform" > "$bundle/PLATFORM"
chmod 0755 "$bundle/scarlett-node" "$bundle/scarlett-prover" "$bundle/install.sh"
(cd "$bundle" && for file in scarlett-node scarlett-prover codex_profile.json codex_scaffold.json install.sh node.env.example scarlett-node.service INSTALL.md VERSION PLATFORM; do
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$file"; else shasum -a 256 "$file"; fi
done > SHA256SUMS)
tar -czf "$out/$name.tar.gz" -C "$stage" "$name"
(cd "$out" && if command -v sha256sum >/dev/null 2>&1; then sha256sum "$name.tar.gz"; else shasum -a 256 "$name.tar.gz"; fi > "$name.tar.gz.sha256")
printf 'Built %s\n' "$out/$name.tar.gz"
