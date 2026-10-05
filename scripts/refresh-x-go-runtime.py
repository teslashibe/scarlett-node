#!/usr/bin/env python3
"""Refresh the runtime snapshot from a committed, reviewed x-go revision."""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="x-go checkout")
    parser.add_argument("revision", help="reviewed commit or ref")
    args = parser.parse_args()
    revision = git(args.source, "rev-parse", "--verify", args.revision + "^{commit}").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise SystemExit("Invalid upstream revision")
    root = Path(__file__).resolve().parents[1]
    destination = root / "third_party" / "x-go"
    names = git(args.source, "ls-tree", "--name-only", revision).decode().splitlines()
    runtime = sorted(name for name in names if name.endswith(".go") and not name.endswith("_test.go"))
    if not runtime:
        raise SystemExit("Upstream runtime source is missing")
    destination.mkdir(parents=True, exist_ok=True)
    for stale in destination.glob("*.go"):
        if stale.name not in runtime:
            stale.unlink()
    hashes = {}
    for name in runtime:
        content = git(args.source, "show", f"{revision}:{name}")
        (destination / name).write_bytes(content)
        hashes[name] = hashlib.sha256(content).hexdigest()
    for name in ["README.md", "LICENSE", "LICENSE.md", "NOTICE"]:
        if name in names:
            (destination / name).write_bytes(git(args.source, "show", f"{revision}:{name}"))
    module = git(args.source, "show", f"{revision}:go.mod").decode()
    go_version = re.search(r"(?m)^go ([0-9.]+)$", module)
    if not go_version:
        raise SystemExit("Upstream Go version is missing")
    (destination / "go.mod").write_text(
        "module github.com/teslashibe/x-go\n\ngo " + go_version.group(1) + "\n"
    )
    metadata = {
        "module": "github.com/teslashibe/x-go",
        "version": "v1.13.0",
        "source_repository": "https://github.com/teslashibe/x-go",
        "source_revision": revision,
        "scope": "Unmodified runtime package at source_revision; v1.13.0 is the local replacement label, not a claim that this commit is a tagged release. Commands, MCP and upstream tests are omitted.",
        "refresh": "python3 scripts/refresh-x-go-runtime.py /path/to/x-go <reviewed-commit>",
        "sha256": hashes,
    }
    (destination / "UPSTREAM.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Refreshed {len(runtime)} runtime files at {revision}")


if __name__ == "__main__":
    main()
