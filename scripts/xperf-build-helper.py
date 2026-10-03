#!/usr/bin/env python3
"""Build an isolated, pinned shared-OT candidate without changing production deps."""
import argparse
import copy
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tomllib

MPZ_URL = "https://github.com/privacy-ethereum/mpz"
MPZ_BASE = "6ebfe619490c3155a589fc6a3be83b0976de19dc"
SDK = "bb4cdc32ae2e80296a27143a348d4bc1769fd09e"
PATCH_SHA = "28b5cac7bc5095c66882bfcf3647f4f5ce22c0797fd4627b2545a010cc741d3d"
TOOLCHAIN = "1.95.0"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd)


def audit_lock(original, candidate):
    expected = copy.deepcopy(original)
    patched = []
    for package in expected["package"]:
        if package.get("source", "").startswith("git+" + MPZ_URL + "?"):
            if not package["source"].endswith("#" + MPZ_BASE):
                raise ValueError("unexpected MPZ source pin")
            patched.append(package["name"])
            del package["source"]
    if len(patched) != 24 or expected != candidate:
        raise ValueError("candidate changed unrelated lockfile content")
    return patched


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mpz-source", type=Path, required=True,
                        help="Git checkout containing the exact upstream MPZ base")
    parser.add_argument("--output", type=Path, required=True,
                        help="New private output directory outside the node checkout")
    parser.add_argument("--node", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--target-dir", type=Path, help="Optional isolated Cargo compilation cache")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    node, output = args.node.resolve(), args.output.resolve()
    if output.is_relative_to(node) or node.is_relative_to(output):
        raise ValueError("output must be separate from the node checkout")
    revision = command(["git", "rev-parse", "HEAD"], node).decode().strip()
    if command(["git", "status", "--porcelain"], node).strip():
        raise ValueError("commit node changes before pinning a candidate")
    patch = Path(__file__).resolve().parents[1] / "experiments/mpz-shared-rcot-generation.patch"
    if digest(patch) != PATCH_SHA:
        raise ValueError("unexpected shared-OT patch")
    source = args.mpz_source.resolve()
    if command(["git", "rev-parse", MPZ_BASE + "^{commit}"], source).decode().strip() != MPZ_BASE:
        raise ValueError("missing exact MPZ base")
    manifest = tomllib.loads((node / "prover/Cargo.toml").read_text())
    if manifest["dependencies"]["tlsn"]["rev"] != SDK or "patch" in manifest:
        raise ValueError("candidate expects the original pinned SDK and dependencies")
    original = tomllib.loads((node / "prover/Cargo.lock").read_text())
    packages = [p for p in original["package"] if p.get("source", "").startswith("git+" + MPZ_URL + "?")]
    if len(packages) != 24 or any(not p["source"].endswith("#" + MPZ_BASE) for p in packages):
        raise ValueError("unexpected original MPZ graph")
    output.mkdir(mode=0o700)
    project, mpz = output / "project", output / "mpz"
    project.mkdir()
    mpz.mkdir()
    archive = command(["git", "archive", "--format=tar", MPZ_BASE], source)
    with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
        stream.extractall(mpz, filter="data")
    subprocess.run(["git", "apply", "--check", str(patch)], cwd=mpz, check=True)
    subprocess.run(["git", "apply", str(patch)], cwd=mpz, check=True)
    shutil.copytree(node / "prover/src", project / "src")
    for name in ["Cargo.toml", "Cargo.lock"]:
        shutil.copy2(node / "prover" / name, project / name)
    for name in ["api/fixtures/lease-x.json", "internal/config/codex-model-catalog.json"]:
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(node / name, destination)
    paths = {}
    for path in mpz.rglob("Cargo.toml"):
        package = tomllib.loads(path.read_text()).get("package", {})
        if package.get("name") in {p["name"] for p in packages}:
            paths[package["name"]] = path.parent
    if set(paths) != {p["name"] for p in packages}:
        raise ValueError("incomplete MPZ package map")
    with (project / "Cargo.toml").open("a") as stream:
        stream.write('\n[patch."' + MPZ_URL + '"]\n')
        for name, path in sorted(paths.items()):
            stream.write(name + " = { path = " + json.dumps(str(path)) + " }\n")
    environment = os.environ.copy()
    for key in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"]:
        environment.pop(key, None)
    environment["CARGO_BUILD_JOBS"] = "2"
    target = args.target_dir.resolve() if args.target_dir else output / "target"
    environment["CARGO_TARGET_DIR"] = str(target)
    rust = command(["rustc", "+" + TOOLCHAIN, "-vV"]).decode()
    host = next(line.removeprefix("host: ") for line in rust.splitlines() if line.startswith("host: "))
    provenance = {"node_source": revision, "sdk_source": SDK, "mpz_base": MPZ_BASE,
                  "patch_sha256": PATCH_SHA, "toolchain": TOOLCHAIN, "host": host,
                  "provider_calls": 0, "production_dependencies_changed": False}

    def run(stage, arguments):
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        log = output / (stage + ".private.log")
        with log.open("xb") as stream:
            code = subprocess.run(["cargo", "+" + TOOLCHAIN, *arguments], cwd=project,
                                  env=environment, stdout=stream, stderr=subprocess.STDOUT).returncode
        result = {**provenance, "stage": stage, "started_utc": started,
                  "ended_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "terminal": True, "underlying_exit_code": code, "log_sha256": digest(log)}
        (output / (stage + "-terminal.json")).write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"stage": stage, "terminal": True, "underlying_exit_code": code}), flush=True)
        if code != 0:
            raise SystemExit(code)

    offline = ["--offline"] if args.offline else []
    run("metadata", ["metadata", "--format-version=1", "--filter-platform", host, *offline])
    patched = audit_lock(original, tomllib.loads((project / "Cargo.lock").read_text()))
    provenance.update(patched_packages=patched, lockfile_sha256=digest(project / "Cargo.lock"),
                      original_lockfile_sha256=digest(node / "prover/Cargo.lock"),
                      manifest_sha256=digest(project / "Cargo.toml"), unrelated_dependencies_changed=False)
    (output / "manifest.json").write_text(json.dumps(provenance, indent=2) + "\n")
    if args.prepare_only:
        print(json.dumps({"prepared": True, "provider_calls": 0}), flush=True)
        return
    run("tests", ["test", "--locked", "--bin", "scarlett-prover", *offline])
    run("build", ["build", "--release", "--locked", "--bin", "scarlett-prover", *offline])
    binary = target / "release/scarlett-prover"
    fingerprints = list((target / "release/.fingerprint").glob("scarlett-prover-*/bin-scarlett-prover.json"))
    if not fingerprints or any(tom.get("rustflags") for tom in (json.loads(p.read_text()) for p in fingerprints)):
        raise ValueError("unexpected release compiler flags")
    provenance.update(helper_sha256=digest(binary), release_rustflags_empty=True)
    (output / "manifest.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(json.dumps({"complete": True, "helper_sha256": provenance["helper_sha256"], "provider_calls": 0}), flush=True)


if __name__ == "__main__":
    main()
