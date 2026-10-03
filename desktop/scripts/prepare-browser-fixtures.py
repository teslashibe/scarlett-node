#!/usr/bin/env python3
"""Synthetic closed browser stores for installed Windows acceptance, no logins."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys


def prepare(root):
    root.mkdir()  # Refuse an existing fixture or browser home
    roaming, local = root / 'Roaming', root / 'Local'
    firefox = roaming / 'Mozilla/Firefox/Profiles/isolated.default/cookies.sqlite'
    chrome = local / 'Google/Chrome/User Data/Default/Network/Cookies'
    for path in (firefox, chrome):
        path.parent.mkdir(parents=True)
    token, csrf = 'a' * 40, 'b' * 64
    with sqlite3.connect(firefox) as db:
        db.execute('CREATE TABLE moz_cookies(host TEXT,name TEXT,value TEXT,expiry INTEGER,originAttributes TEXT,path TEXT,isSecure INTEGER)')
        db.executemany('INSERT INTO moz_cookies VALUES(?,?,?,?,?,?,?)', [
            ('.x.com', 'auth_token', token, 0, '', '/', 1),
            ('.x.com', 'ct0', csrf, 0, '', '/', 1),
            ('.example.invalid', 'other', 'unrelated-synthetic-cookie', 0, '', '/', 1),
        ])
    with sqlite3.connect(chrome) as db:
        db.executescript("CREATE TABLE cookies(host_key TEXT,name TEXT,value TEXT,expires_utc INTEGER,top_frame_site_key TEXT,path TEXT,is_secure INTEGER,encrypted_value BLOB);CREATE TABLE meta(key TEXT,value TEXT);INSERT INTO meta VALUES('version','24');")
        db.executemany('INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?)', [
            ('.x.com', 'auth_token', '', 0, '', '/', 1, b'v20' + b'c' * 40),
            ('.x.com', 'ct0', '', 0, '', '/', 1, b'v20' + b'd' * 64),
        ])
    manifest = {
        'syntheticOnly': True, 'roaming': str(roaming), 'local': str(local),
        'authToken': token, 'csrf': csrf,
        'stores': [{'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in (firefox, chrome)],
    }
    (root / 'fixture.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Windows' or sys.platform != 'win32':
        raise SystemExit('Fixture generation requires a disposable Windows CI runner')
    if len(sys.argv) != 2 or not os.environ.get('RUNNER_TEMP'):
        raise SystemExit('Supply a new absolute directory below RUNNER_TEMP')
    root = Path(sys.argv[1])
    temporary = Path(os.environ['RUNNER_TEMP']).resolve()
    if not root.is_absolute() or root.is_symlink() or not root.resolve().is_relative_to(temporary) or root.resolve() == temporary:
        raise SystemExit('Fixture destination must be a fresh disposable runner directory')
    prepare(root)
