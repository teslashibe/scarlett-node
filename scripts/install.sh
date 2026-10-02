#!/bin/sh
set -eu
umask 077
bundle=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=${1:-"$HOME/.local/lib/scarlett-node"}
bin=${2:-"$HOME/.local/bin"}
case "$root:$bin" in /*:/*) ;; *) echo 'Installation paths must be absolute' >&2; exit 1;; esac
[ "$root" != / ] && [ "$bin" != / ] || exit 1
case "$(uname -s):$(uname -m)" in
  Linux:x86_64) platform=linux-amd64;;
  Darwin:arm64) platform=darwin-arm64;;
  Darwin:x86_64) platform=darwin-amd64;;
  *) echo 'Unsupported installation platform' >&2; exit 1;;
esac
[ "$(cat "$bundle/PLATFORM")" = "$platform" ] || { echo 'Bundle does not match this platform' >&2; exit 1; }
version=$(cat "$bundle/VERSION")
case "$version" in ''|*[!A-Za-z0-9._-]*|.*|-*) echo 'Invalid bundle version' >&2; exit 1;; esac
[ ${#version} -le 80 ] || exit 1
# Check only the fixed bundle files; a checksum manifest may not read other paths.
awk 'NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ || $2 !~ /^(scarlett-node|scarlett-prover|codex_profile\.json|codex_scaffold\.json|install\.sh|node\.env\.example|scarlett-node\.service|INSTALL\.md|VERSION|PLATFORM)$/ || seen[$2]++ {bad=1} END {exit bad || NR!=10}' "$bundle/SHA256SUMS" || { echo 'Invalid bundle checksums' >&2; exit 1; }
for file in scarlett-node scarlett-prover codex_profile.json codex_scaffold.json install.sh node.env.example scarlett-node.service INSTALL.md VERSION PLATFORM; do
  [ -f "$bundle/$file" ] && [ ! -L "$bundle/$file" ] || { echo 'Invalid bundle file' >&2; exit 1; }
done
(cd "$bundle" && if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi) >/dev/null
[ ! -L "$root" ] && [ ! -L "$bin" ] || { echo 'Installation directories may not be symlinks' >&2; exit 1; }
[ ! -L "$root/versions" ] || exit 1
mkdir -p "$root" "$bin"
# Never change permissions on a caller's existing shared installation root.
case "$platform" in
  darwin-*) root_mode=$(stat -f '%Lp' "$root"); root_owner=$(stat -f '%u' "$root");;
  *) root_mode=$(stat -c '%a' "$root"); root_owner=$(stat -c '%u' "$root");;
esac
[ "$root_mode" = 700 ] && [ "$root_owner" = "$(id -u)" ] || { echo 'Installation root must be owned by you and private (0700)' >&2; exit 1; }
mkdir -p "$root/versions"
mkdir "$root/.install-lock" || { echo 'Another installation is in progress' >&2; exit 1; }
stage=''
link="$root/.current-$$"
trap 'rm -f "$link"; [ -z "$stage" ] || rm -rf "$stage"; rmdir "$root/.install-lock"' EXIT HUP INT TERM
target="$root/versions/$version-$platform"
for file in scarlett-node scarlett-prover; do
  if [ -e "$bin/$file" ] || [ -L "$bin/$file" ]; then
    [ -L "$bin/$file" ] && [ "$(readlink "$bin/$file")" = "$root/current/$file" ] || { echo 'Refusing to replace an unrelated executable' >&2; exit 1; }
  fi
done
[ ! -e "$root/current" ] || [ -L "$root/current" ] || { echo 'Invalid active version destination' >&2; exit 1; }
if [ -e "$target" ] || [ -L "$target" ]; then
  [ -d "$target" ] && [ ! -L "$target" ] && cmp -s "$bundle/SHA256SUMS" "$target/SHA256SUMS" || { echo 'Version already installed with different contents' >&2; exit 1; }
  (cd "$target" && if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi) >/dev/null
else
  stage=$(mktemp -d "$root/versions/.install.XXXXXX")
  for file in scarlett-node scarlett-prover codex_profile.json codex_scaffold.json install.sh node.env.example scarlett-node.service INSTALL.md VERSION PLATFORM SHA256SUMS; do cp "$bundle/$file" "$stage/$file"; done
  chmod 0755 "$stage/scarlett-node" "$stage/scarlett-prover" "$stage/install.sh"
  mv "$stage" "$target"
  stage=''
fi
ln -s "versions/$version-$platform" "$link"
case "$platform" in darwin-*) mv -fh "$link" "$root/current";; *) mv -fT "$link" "$root/current";; esac
for file in scarlett-node scarlett-prover; do
  [ -L "$bin/$file" ] || ln -s "$root/current/$file" "$bin/$file"
done
printf 'Installed %s for %s\nAdd %s to PATH\n' "$version" "$platform" "$bin"
printf 'Configuration example: %s/node.env.example\n' "$target"
