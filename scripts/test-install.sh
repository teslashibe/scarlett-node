#!/bin/sh
set -eu
umask 077
out=${1:?usage: test-install.sh BUNDLE_DIRECTORY}
testdir=$(mktemp -d)
trap 'rm -rf "$testdir"' EXIT HUP INT TERM
for archive in "$out"/*.tar.gz; do
  [ -f "$archive" ] || exit 1
  (cd "$out" && if command -v sha256sum >/dev/null 2>&1; then sha256sum -c "$(basename "$archive").sha256"; else shasum -a 256 -c "$(basename "$archive").sha256"; fi) >/dev/null
  mkdir "$testdir/extracted"
  tar -xzf "$archive" -C "$testdir/extracted"
  set -- "$testdir/extracted"/*
  [ "$#" = 1 ] && [ -d "$1" ] || exit 1
  bundle=$1
  root="$testdir/install root"
  bin="$testdir/bin"
  "$bundle/install.sh" "$root" "$bin"
  "$bundle/install.sh" "$root" "$bin"
  [ -x "$bin/scarlett-node" ] && [ -x "$bin/scarlett-prover" ] || exit 1
  SCARLETT_STATE_DIR="$testdir/node-state" "$bin/scarlett-node" status > "$testdir/status"
  grep '"state":"offline"' "$testdir/status" >/dev/null
  # The installed binary reports its release for the updater's health check;
  # outside an install.sh layout the updater refuses to change anything.
  "$bin/scarlett-node" update version | grep '"release":"' >/dev/null
  if "$bundle/scarlett-node" update check > "$testdir/update" 2>&1; then echo 'Updater ran outside an installation' >&2; exit 1; fi
  grep 'install.sh' "$testdir/update" >/dev/null
  [ -f "$root/current/scarlett-node-update.service" ] && [ -f "$root/current/scarlett-node-update.timer" ] || exit 1
  # The installed web runtime extracts with every hash checked and passes its
  # self-check and driver check here; no browser is downloaded.
  SCARLETT_STATE_DIR="$testdir/node-state" "$bin/scarlett-node" web-runtime check > "$testdir/web-runtime"
  grep '"webRuntime":"passed"' "$testdir/web-runtime" >/dev/null
  if "$bin/scarlett-prover" > "$testdir/helper" 2>&1; then echo 'Proof helper did not reject a missing command' >&2; exit 1; fi
  grep 'usage: scarlett-prover' "$testdir/helper" >/dev/null
  printf 'Keep journal and identity\n' > "$testdir/node-state/synthetic-preserve"
  cp -R "$bundle" "$testdir/upgrade"
  original=$(cat "$bundle/VERSION")
  printf '%s\n' "$original-upgrade" > "$testdir/upgrade/VERSION"
  hash=$(if command -v sha256sum >/dev/null 2>&1; then sha256sum "$testdir/upgrade/VERSION"; else shasum -a 256 "$testdir/upgrade/VERSION"; fi)
  hash=${hash%% *}
  awk -v hash="$hash" '$2=="VERSION" {$1=hash} {print $1 "  " $2}' "$testdir/upgrade/SHA256SUMS" > "$testdir/checksums"
  mv "$testdir/checksums" "$testdir/upgrade/SHA256SUMS"
  "$testdir/upgrade/install.sh" "$root" "$bin"
  [ "$(cat "$root/current/VERSION")" = "$original-upgrade" ] || exit 1
  "$bundle/install.sh" "$root" "$bin"
  [ "$(cat "$root/current/VERSION")" = "$original" ] || exit 1
  rm -rf "$testdir/upgrade"
  # Reinstall must reject altered installed executables before invoking them.
  cp "$root/current/x-login-runtime/node" "$testdir/saved-node"
  printf '#!/bin/sh\ntouch "%s"\nexit 1\n' "$testdir/unsafe-runtime-executed" > "$root/current/x-login-runtime/node"
  if "$bundle/install.sh" "$root" "$bin" > /dev/null 2>&1; then echo 'Changed installed runtime accepted' >&2; exit 1; fi
  [ ! -e "$testdir/unsafe-runtime-executed" ] || { echo 'Changed runtime executed before checksum validation' >&2; exit 1; }
  cp "$testdir/saved-node" "$root/current/x-login-runtime/node"
  rm "$testdir/saved-node"
  # Every native bundle supplies a pinned local helper; neither installation
  # nor this fixture launches Chrome or contacts a provider.
  [ -x "$root/current/x-login-runtime/node" ] || exit 1
  "$root/current/x-login-runtime/node" "$root/current/verify-x-login-runtime.mjs" "$root/current/x-login-runtime" "$(cat "$bundle/PLATFORM")" > /dev/null
  cp -R "$bundle" "$testdir/runtime-tamper"
  printf 'changed runtime source\n' >> "$testdir/runtime-tamper/x-login-runtime/social-login/src/server.js"
  if "$testdir/runtime-tamper/install.sh" "$root" "$bin" > /dev/null 2>&1; then echo 'Changed runtime source installed' >&2; exit 1; fi
  rm -rf "$testdir/runtime-tamper"
  cp -R "$bundle" "$testdir/runtime-missing"
  rm "$testdir/runtime-missing/x-login-runtime/social-login/node_modules/playwright/package.json"
  if "$testdir/runtime-missing/install.sh" "$root" "$bin" > /dev/null 2>&1; then echo 'Incomplete runtime installed' >&2; exit 1; fi
  rm -rf "$testdir/runtime-missing"
  # A changed or missing web runtime never installs; with its checksums
  # rewritten to match, a changed, missing or other-platform archive still
  # fails the runtime check.
  platform=$(cat "$bundle/PLATFORM")
  rewrite_sums() {
    (cd "$1" && for file in $(awk '{print $2}' SHA256SUMS); do
      [ -f "$file" ] || continue
      if command -v sha256sum >/dev/null 2>&1; then sha256sum "$file"; else shasum -a 256 "$file"; fi
    done > SHA256SUMS.new && mv SHA256SUMS.new SHA256SUMS)
  }
  web_check_fails() {
    if SCARLETT_STATE_DIR="$testdir/web-state-$2" "$bin/scarlett-node" web-runtime check --resources "$1" > /dev/null 2>&1; then echo "Web runtime check accepted a $2 archive" >&2; exit 1; fi
  }
  cp -R "$bundle" "$testdir/web-tamper"
  printf 'x' >> "$testdir/web-tamper/web-runtime-$platform.tar.gz"
  if "$testdir/web-tamper/install.sh" "$root" "$bin" > /dev/null 2>&1; then echo 'Changed web runtime installed' >&2; exit 1; fi
  rewrite_sums "$testdir/web-tamper"
  web_check_fails "$testdir/web-tamper" tampered
  rm -rf "$testdir/web-tamper"
  cp -R "$bundle" "$testdir/web-missing"
  rm "$testdir/web-missing/web-runtime-$platform.tar.gz"
  if "$testdir/web-missing/install.sh" "$root" "$bin" > /dev/null 2>&1; then echo 'Bundle without its web runtime installed' >&2; exit 1; fi
  web_check_fails "$testdir/web-missing" missing
  rm -rf "$testdir/web-missing"
  cp -R "$bundle" "$testdir/web-platform"
  case "$platform" in linux-amd64) other=darwin-arm64;; *) other=linux-amd64;; esac
  mv "$testdir/web-platform/web-runtime-$platform.tar.gz" "$testdir/web-platform/web-runtime-$other.tar.gz"
  sed "s/$platform/$other/g" "$testdir/web-platform/web-runtime.json" > "$testdir/web-platform/web-runtime.json.new"
  mv "$testdir/web-platform/web-runtime.json.new" "$testdir/web-platform/web-runtime.json"
  web_check_fails "$testdir/web-platform" wrong-platform
  rm -rf "$testdir/web-platform" "$testdir"/web-state-*
  # Reinstallation refuses changed bytes; the active version stays intact.
  printf 'corrupted\n' >> "$bundle/scarlett-node"
  if "$bundle/install.sh" "$root" "$bin" > /dev/null 2>&1; then echo 'Corrupt bundle installed' >&2; exit 1; fi
  [ "$(cat "$testdir/node-state/synthetic-preserve")" = 'Keep journal and identity' ] || exit 1
  SCARLETT_STATE_DIR="$testdir/node-state" "$bin/scarlett-node" status > /dev/null
  # A valid bundle cannot overwrite another application in the chosen bin.
  rm -rf "$testdir/extracted"
  mkdir "$testdir/extracted"
  tar -xzf "$archive" -C "$testdir/extracted"
  set -- "$testdir/extracted"/*
  bundle=$1
  mkdir "$testdir/unrelated-bin"
  printf 'unrelated\n' > "$testdir/unrelated-bin/scarlett-node"
  if "$bundle/install.sh" "$root" "$testdir/unrelated-bin" > /dev/null 2>&1; then echo 'Unrelated executable replaced' >&2; exit 1; fi
  [ "$(cat "$testdir/unrelated-bin/scarlett-node")" = unrelated ] || exit 1
  rm -rf "$testdir/extracted" "$root" "$bin" "$testdir/node-state" "$testdir/unrelated-bin"
done
printf 'Native bundle installation, private local status, web runtime, helper startup and failure checks passed\n'
