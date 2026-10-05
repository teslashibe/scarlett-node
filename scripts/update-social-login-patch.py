#!/usr/bin/env python3
"""Explicit maintainer-only provenance refresh against the pinned upstream checkout."""
import difflib
import hashlib
import json
import pathlib
import subprocess
import sys
root = pathlib.Path(__file__).resolve().parents[1]
snapshot = root / 'third_party/social-login'
upstream = pathlib.Path(sys.argv[1]).resolve()
metadata = json.loads((snapshot / 'UPSTREAM.json').read_text())
revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=upstream, text=True).strip()
if revision != metadata['revision']:
    raise SystemExit('Upstream checkout does not match pinned revision')
patch = []
for filename, expected in metadata['original_sha256'].items():
    original = (upstream / filename).read_bytes()
    if hashlib.sha256(original).hexdigest() != expected:
        raise SystemExit(f'Upstream checkout bytes differ: {filename}')
    local = (snapshot / filename).read_bytes()
    if original != local:
        patch.extend(difflib.unified_diff(original.decode().splitlines(True), local.decode().splitlines(True), fromfile='a/' + filename, tofile='b/' + filename))
for filename in ['test/interactive-x.test.js', 'test/aggregate-budget.test.js']:
    patch.extend(difflib.unified_diff([], (snapshot / filename).read_text().splitlines(True), fromfile='/dev/null', tofile='b/' + filename))
(snapshot / 'patches').mkdir(exist_ok=True)
(snapshot / 'patches/interactive-x.patch').write_text(''.join(patch))
hashes = {}
for file in sorted(snapshot.rglob('*')):
    if 'node_modules' in file.parts or not file.is_file() or file.name == 'PATCHED.json':
        continue
    hashes[file.relative_to(snapshot).as_posix()] = hashlib.sha256(file.read_bytes()).hexdigest()
(snapshot / 'PATCHED.json').write_text(json.dumps({'upstream_revision': revision, 'sha256': hashes}, indent=2) + '\n')
