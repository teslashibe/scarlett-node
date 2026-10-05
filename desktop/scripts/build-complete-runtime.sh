#!/usr/bin/env bash
# Build Scarlett's three native components, fetch and verify the pinned official
# provider packages, then prepare desktop/src-tauri/runtime for a complete bundle.
# The PR complete-bundle workflow and the release workflow both call this, so
# tested and released bundles are assembled by one copy of these commands.
# No account login, provider request or signing happens here.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'usage: build-complete-runtime.sh <darwin-arm64|darwin-x64|win32-x64> <absolute-output-directory>' >&2
  exit 2
fi
platform=$1
out=$2
case "$platform" in
  darwin-arm64 | darwin-x64) suffix='' ;;
  win32-x64) suffix='.exe' ;;
  *) echo 'Unsupported native platform' >&2; exit 2 ;;
esac
case "$out" in
  /* | [A-Za-z]:[\\/]*) ;;
  *) echo 'The output directory must be absolute' >&2; exit 2 ;;
esac

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
# Native Windows tools need a drive path, not the Git Bash /d/... spelling.
if [[ -n "$suffix" ]]; then root=$(pwd -W); else root=$(pwd); fi

mkdir -p "$out/codex" "$out/claude"
go build -trimpath -o "$out/scarlett-node$suffix" .
GOBIN="$out" go install github.com/teslashibe/open-agent-api/cmd/open-agent-api@v0.1.32
cargo +1.95 build --release --locked --manifest-path prover/Cargo.toml

fetch() {
  local directory=$1 package=$2 archive
  (
    cd "$directory"
    npm pack "$package" --ignore-scripts --json > pack.json
    archive=$(node -p 'JSON.parse(require("node:fs").readFileSync("pack.json","utf8"))[0].filename')
    node "$root/desktop/scripts/verify-provider-archive.mjs" "$package" "$archive"
    tar -xzf "$archive"
  )
}
fetch "$out/codex" "@openai/codex@0.159.2-$platform"
fetch "$out/claude" "@anthropic-ai/claude-code-$platform@2.1.286"

node desktop/scripts/prepare-complete-bundle.mjs \
  "$out/scarlett-node$suffix" \
  "$root/prover/target/release/scarlett-prover$suffix" \
  "$out/open-agent-api$suffix" \
  "$out/codex/package" \
  "$out/claude/package"
