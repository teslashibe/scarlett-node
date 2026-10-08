#!/usr/bin/env python3
"""Verify the updater's minisign signatures without third-party packages.

The release signs each installer and headless bundle with
`tauri signer sign --app-version <v>` (pinned @tauri-apps/cli 2.12.1). A .sig
value is base64 of a minisign signature file whose algorithm must be "ED"
(Ed25519 over the file's BLAKE2b-512 hash) and whose trusted comment must be
exactly "timestamp:<n>\\tfile:<name>\\tversion:<v>". The Go client
(internal/update/minisign.go) applies the same rules; this copy lets the
secret-free assemble job check every signature before writing the manifest.

Ed25519 here is the RFC 8032 section 6 reference algorithm (cofactorless
verification, like Go's crypto/ed25519). It only ever verifies public data.
"""
import base64
import hashlib
import re

P = 2 ** 255 - 19
Q = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
KEY_ID = re.compile('[0-9A-F]{16}')


def _sha512_modq(data):
    return int.from_bytes(hashlib.sha512(data).digest(), 'little') % Q


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    e1 = (y1 - x1) * (y2 - x2) % P
    e2 = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = e2 - e1, d - c, d + c, e2 + e1
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(scalar, point):
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    if x & 1 != sign:
        x = P - x
    return x


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
G = (_GX, _GY, 1, _GX * _GY % P)


def _compress(point):
    inverse = pow(point[2], P - 2, P)
    x, y = point[0] * inverse % P, point[1] * inverse % P
    return (y | (x & 1) << 255).to_bytes(32, 'little')


def _decompress(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, 'little')
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    a, r = _decompress(public), _decompress(signature[:32])
    s = int.from_bytes(signature[32:], 'little')
    if a is None or r is None or s >= Q:
        return False
    h = _sha512_modq(signature[:32] + public + message)
    return _equal(_mul(s, G), _add(r, _mul(h, a)))


def _expand(secret):
    digest = hashlib.sha512(secret).digest()
    scalar = int.from_bytes(digest[:32], 'little')
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def ed25519_public(secret):
    return _compress(_mul(_expand(secret)[0], G))


def ed25519_sign(secret, message):
    """Test fixtures only; release signing is the pinned tauri signer."""
    scalar, prefix = _expand(secret)
    public = _compress(_mul(scalar, G))
    r = _sha512_modq(prefix + message)
    encoded_r = _compress(_mul(r, G))
    s = (r + _sha512_modq(encoded_r + public + message) * scalar) % Q
    return encoded_r + s.to_bytes(32, 'little')


def key_id(keynum):
    """minisign's display form: the key number as a little-endian integer."""
    return keynum[::-1].hex().upper()


def parse_public_key(text):
    """A bare minisign key line ("RWQ...") or Tauri's base64-wrapped key file."""
    if not isinstance(text, str) or not 0 < len(text.strip()) <= 1024:
        raise ValueError('Invalid minisign public key')
    text = text.strip()
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        raise ValueError('Invalid minisign public key') from None
    if len(raw) != 42:
        lines = raw.decode('utf-8', 'replace').rstrip('\n').split('\n')
        if len(lines) != 2 or not lines[0].startswith('untrusted comment: '):
            raise ValueError('Invalid minisign public key')
        try:
            raw = base64.b64decode(lines[1], validate=True)
        except ValueError:
            raise ValueError('Invalid minisign public key') from None
    if len(raw) != 42 or raw[:2] != b'Ed':
        raise ValueError('Invalid minisign public key')
    return {'keynum': raw[2:10], 'public': raw[10:], 'keyId': key_id(raw[2:10]),
            'line': base64.b64encode(raw).decode()}


def parse_signature(encoded):
    if not isinstance(encoded, str) or not 0 < len(encoded.strip()) <= 4096:
        raise ValueError('Invalid updater signature')
    try:
        text = base64.b64decode(encoded.strip(), validate=True).decode('utf-8')
    except ValueError:
        raise ValueError('Invalid updater signature') from None
    lines = text[:-1].split('\n') if text.endswith('\n') else text.split('\n')
    if '\r' in text or len(lines) != 4 or not lines[0].startswith('untrusted comment: ') or \
            not lines[2].startswith('trusted comment: '):
        raise ValueError('Invalid updater signature')
    try:
        box, global_signature = base64.b64decode(lines[1], validate=True), base64.b64decode(lines[3], validate=True)
    except ValueError:
        raise ValueError('Invalid updater signature') from None
    if len(box) != 74 or box[:2] != b'ED' or len(global_signature) != 64:
        raise ValueError('Updater signatures are prehashed minisign (ED) signatures')
    trusted = lines[2][len('trusted comment: '):]
    match = re.fullmatch(r'timestamp:([0-9]{1,20})\tfile:([^\t]+)\tversion:([^\t]+)', trusted)
    if not match:
        raise ValueError('Updater signatures carry timestamp, file and version')
    return {'keynum': box[2:10], 'keyId': key_id(box[2:10]), 'signature': box[10:], 'trusted': trusted,
            'global': global_signature, 'file': match.group(2), 'version': match.group(3)}


def blake2b_file(path):
    digest = hashlib.blake2b(digest_size=64)
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            digest.update(chunk)
    return digest.digest()


def verify(encoded, prehash, filename, version, keys):
    """Return the signing key's ID, or raise ValueError."""
    signature = parse_signature(encoded)
    key = next((k for k in keys if k['keynum'] == signature['keynum']), None)
    if key is None:
        raise ValueError('Updater signature is not from a pinned key')
    if not ed25519_verify(key['public'], prehash, signature['signature']):
        raise ValueError('Updater signature does not match the file')
    if not ed25519_verify(key['public'], signature['signature'] + signature['trusted'].encode('utf-8'), signature['global']):
        raise ValueError('Updater signature trusted comment is invalid')
    if signature['file'] != filename or signature['version'] != version:
        raise ValueError('Updater signature belongs to another file or version')
    return key['keyId']


def sign_for_tests(secret, keynum, prehash, filename, version, timestamp=1791480419):
    """A Tauri-format .sig value from a throwaway key (tests only)."""
    trusted = 'timestamp:%d\tfile:%s\tversion:%s' % (timestamp, filename, version)
    signature = ed25519_sign(secret, prehash)
    global_signature = ed25519_sign(secret, signature + trusted.encode())
    text = 'untrusted comment: signature from tauri secret key\n%s\ntrusted comment: %s\n%s\n' % (
        base64.b64encode(b'ED' + keynum + signature).decode(), trusted, base64.b64encode(global_signature).decode())
    return base64.b64encode(text.encode()).decode()


def public_line_for_tests(secret, keynum):
    return base64.b64encode(b'Ed' + keynum + ed25519_public(secret)).decode()
