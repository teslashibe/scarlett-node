#!/usr/bin/env python3
"""Load Scarlett's self-signed release identities and prove their public pins.

desktop/signing/identities.json names each committed public certificate with
its lowercase SHA-1 and SHA-256 over DER. Loading recomputes both hashes, the
subject, the expiry and self-issuance from the PEM itself, so a pin can only
change together with its certificate, in a reviewed pull request.

Rehearsals (PR CI with an ephemeral key) may substitute another file through
SCARLETT_SIGNING_IDENTITIES, honoured only with SCARLETT_SIGNING_REHEARSAL=1.
The override is otherwise ignored. Anything signed in a rehearsal records
"rehearsal": true, which the release assembler rejects.

Command line (public values only; this never touches a private key):
  signing_identities.py get macos.sha1
  signing_identities.py rehearsal --macos-certificate PEM --output JSON
"""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import sys

REPOSITORY = Path(__file__).resolve().parents[2]
DEFAULT = REPOSITORY / 'desktop' / 'signing' / 'identities.json'
SCHEME = 'self-signed-stable'
MAC_IDENTIFIERS = {
    'app': 'ai.scarlett.node',
    'scarlett-node': 'ai.scarlett.node.scarlett-node',
    'scarlett-prover': 'ai.scarlett.node.scarlett-prover',
    'open-agent-api': 'ai.scarlett.node.open-agent-api',
    'dmg': 'ai.scarlett.node.dmg',
}
# RFC3161 endpoints are exact strings. The token itself is signed and verified,
# so plain HTTP carries no trust; an unlisted endpoint is still refused.
TIMESTAMP_URLS = ('http://timestamp.digicert.com',)
PLATFORM_KEYS = {
    'macos': {'subject', 'certificate', 'sha1', 'sha256', 'notAfter', 'identifiers', 'designatedRequirement'},
    'windows': {'subject', 'certificate', 'sha1', 'sha256', 'notAfter', 'timestampUrl'},
}
SHA1 = re.compile('[0-9a-f]{40}')
SHA256 = re.compile('[0-9a-f]{64}')
NOT_AFTER = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')
COMMITTED_CERTIFICATE = re.compile(r'desktop/signing/[a-z0-9-]+\.cert\.pem')
ATTRIBUTES = {b'\x55\x04\x03': 'CN', b'\x55\x04\x0a': 'O', b'\x55\x04\x0b': 'OU', b'\x55\x04\x06': 'C'}


def designated_requirement(identifier, sha1):
    """The explicit Mac requirement; TCC grants follow it across updates."""
    return 'designated => identifier "%s" and certificate leaf = H"%s"' % (identifier, sha1)


def _element(data, offset, end):
    if offset + 2 > end:
        raise ValueError('Truncated certificate')
    tag, length = data[offset], data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7f
        if not 1 <= count <= 3 or offset + count > end:
            raise ValueError('Unsupported certificate length')
        length = int.from_bytes(data[offset:offset + count], 'big')
        offset += count
    if offset + length > end:
        raise ValueError('Truncated certificate')
    return tag, offset, offset + length


def _children(data, start, end):
    items = []
    while start < end:
        item = _element(data, start, end)
        items.append(item)
        start = item[2]
    return items


def _name(data, start, end):
    parts = []
    for tag, rdn_start, rdn_end in _children(data, start, end):
        if tag != 0x31:
            raise ValueError('Unexpected certificate name')
        for _, pair_start, pair_end in _children(data, rdn_start, rdn_end):
            (oid_tag, oid_start, oid_end), (value_tag, value_start, value_end) = _children(data, pair_start, pair_end)
            label = ATTRIBUTES.get(bytes(data[oid_start:oid_end]))
            if oid_tag != 0x06 or not label or value_tag not in (0x0c, 0x13):
                raise ValueError('Unsupported certificate name attribute')
            parts.append(label + '=' + data[value_start:value_end].decode('utf-8'))
    return ', '.join(parts)


def _time(data, tag, start, end):
    text = data[start:end].decode('ascii')
    if tag == 0x17 and re.fullmatch(r'\d{12}Z', text):
        year = int(text[:2])
        text = ('19' if year >= 50 else '20') + text
    elif tag != 0x18 or not re.fullmatch(r'\d{14}Z', text):
        raise ValueError('Unsupported certificate time')
    return datetime.strptime(text, '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)


def describe(der):
    """Return subject, issuer and validity from a DER X.509 certificate."""
    tag, start, end = _element(der, 0, len(der))
    if tag != 0x30 or end != len(der):
        raise ValueError('Expected one DER certificate')
    tbs_tag, tbs_start, tbs_end = _children(der, start, end)[0]
    fields = _children(der, tbs_start, tbs_end)
    if tbs_tag != 0x30 or not fields or fields[0][0] != 0xa0:
        raise ValueError('Expected an X.509 v3 certificate')
    _, _, _, issuer, validity, subject = fields[:6]
    not_before, not_after = _children(der, validity[1], validity[2])
    return {'subject': _name(der, subject[1], subject[2]), 'issuer': _name(der, issuer[1], issuer[2]),
            'notBefore': _time(der, *not_before), 'notAfter': _time(der, *not_after)}


def certificate_der(path):
    """Read one public PEM certificate. A file holding any key is refused."""
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise ValueError('Signing certificates must be small regular PEM files')
    text = path.read_text(encoding='ascii')
    if text.count('-----BEGIN ') != 1 or text.count('-----BEGIN CERTIFICATE-----') != 1 or 'KEY-----' in text:
        raise ValueError('A signing certificate file holds exactly one public certificate')
    return ssl.PEM_cert_to_DER_cert(text.strip())


def fingerprints(der):
    return hashlib.sha1(der).hexdigest(), hashlib.sha256(der).hexdigest()


def _certificate_path(value, rehearsal):
    if not isinstance(value, str):
        raise ValueError('Invalid certificate path')
    if COMMITTED_CERTIFICATE.fullmatch(value):
        return REPOSITORY / value
    if rehearsal and Path(value).is_absolute():
        return Path(value)
    raise ValueError('Release identities use committed certificates in desktop/signing')


def _check_platform(name, section, rehearsal):
    if not isinstance(section, dict) or set(section) != PLATFORM_KEYS[name]:
        raise ValueError('Unexpected %s signing identity fields' % name)
    if not isinstance(section['sha1'], str) or not SHA1.fullmatch(section['sha1']) or \
            not isinstance(section['sha256'], str) or not SHA256.fullmatch(section['sha256']):
        raise ValueError('Signing pins are lowercase hex SHA-1 and SHA-256')
    if not isinstance(section['subject'], str) or not 0 < len(section['subject']) <= 160 or \
            not isinstance(section['notAfter'], str) or not NOT_AFTER.fullmatch(section['notAfter']):
        raise ValueError('Invalid signing subject or expiry')
    der = certificate_der(_certificate_path(section['certificate'], rehearsal))
    if fingerprints(der) != (section['sha1'], section['sha256']):
        raise ValueError('Committed certificate does not match its pinned hashes')
    details = describe(der)
    if details['subject'] != section['subject'] or details['issuer'] != details['subject']:
        raise ValueError('Pinned certificate must be the self-issued subject on record')
    if details['notAfter'].strftime('%Y-%m-%dT%H:%M:%SZ') != section['notAfter']:
        raise ValueError('Pinned certificate expiry differs from the record')
    if name == 'macos':
        if section['identifiers'] != MAC_IDENTIFIERS:
            raise ValueError('Mac signing identifiers are fixed')
        if section['designatedRequirement'] != designated_requirement(MAC_IDENTIFIERS['app'], section['sha1']):
            raise ValueError('Mac designated requirement must pin the app identifier and certificate')
    elif section['timestampUrl'] not in TIMESTAMP_URLS:
        raise ValueError('Windows timestamps use the reviewed RFC3161 endpoint')


def validate(identities, rehearsal=False):
    if not isinstance(identities, dict) or set(identities) != {'schemaVersion', 'scheme', 'macos', 'windows'} or \
            identities['schemaVersion'] != 1 or identities['scheme'] != SCHEME:
        raise ValueError('Expected self-signed-stable identities, schema version 1')
    for name in ('macos', 'windows'):
        _check_platform(name, identities[name], rehearsal)
    if identities['macos']['sha256'] == identities['windows']['sha256']:
        raise ValueError('Each platform uses its own certificate')
    return identities


def load(environ=None):
    """Return the validated identities plus "rehearsal" (always a bool)."""
    environ = os.environ if environ is None else environ
    flag = environ.get('SCARLETT_SIGNING_REHEARSAL', '')
    if flag not in ('', '1'):
        raise ValueError('SCARLETT_SIGNING_REHEARSAL is either unset or 1')
    rehearsal = flag == '1'
    path = DEFAULT
    override = environ.get('SCARLETT_SIGNING_IDENTITIES', '')
    if rehearsal and override:
        path = Path(override)
        if not path.is_absolute():
            raise ValueError('Rehearsal identities require an absolute path')
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise ValueError('Signing identities must be a small regular JSON file')
    identities = validate(json.loads(path.read_text()), rehearsal)
    return dict(identities, rehearsal=rehearsal)


def rehearsal_identities(macos_certificate=None, windows_certificate=None):
    """Committed identities with ephemeral rehearsal certificates substituted."""
    identities = copy.deepcopy(validate(json.loads(DEFAULT.read_text())))
    for name, certificate in (('macos', macos_certificate), ('windows', windows_certificate)):
        if certificate is None:
            continue
        certificate = Path(certificate).resolve()
        der = certificate_der(certificate)
        details = describe(der)
        section = identities[name]
        section['certificate'] = str(certificate)
        section['sha1'], section['sha256'] = fingerprints(der)
        section['subject'] = details['subject']
        section['notAfter'] = details['notAfter'].strftime('%Y-%m-%dT%H:%M:%SZ')
        if name == 'macos':
            section['designatedRequirement'] = designated_requirement(MAC_IDENTIFIERS['app'], section['sha1'])
    return validate(identities, rehearsal=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    get = commands.add_parser('get', help='print one public value, such as macos.sha1')
    get.add_argument('field')
    rehearsal = commands.add_parser('rehearsal', help='write identities for an ephemeral rehearsal key')
    rehearsal.add_argument('--macos-certificate', type=Path)
    rehearsal.add_argument('--windows-certificate', type=Path)
    rehearsal.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == 'get':
        value = load()
        for part in args.field.split('.'):
            value = value[part]
        if not isinstance(value, str):
            raise ValueError('Select a single public value')
        print(value)
        return
    if not args.macos_certificate and not args.windows_certificate:
        raise ValueError('Supply at least one ephemeral rehearsal certificate')
    identities = rehearsal_identities(args.macos_certificate, args.windows_certificate)
    with args.output.open('x') as stream:
        json.dump(identities, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError):
        print('Signing identities are invalid or unavailable', file=sys.stderr)
        raise SystemExit(1) from None
