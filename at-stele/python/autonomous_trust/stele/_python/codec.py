# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
"""Stele's two signed artifacts. Byte-for-byte twin of
at-stele/c/stele/stele_codec.c; see its header for the forms.

A repo ad is dict-shaped ``{owner, name, url, ref, commit, seq, ts}``; an
attestation ``{verifier, repo_ad_id, commit, scanner, scanner_version,
db_digest, findings_digest, verdict, count, max_severity, ts}``. Envelopes add
``sig``."""

import hashlib
from uuid import UUID

NAME_MAX, URL_MAX, REF_MAX = 64, 256, 64
SCANNER_MAX, VERSION_MAX, SEVERITY_MAX = 32, 32, 16
DIGEST_HEX = 64
VERDICT_CLEAN, VERDICT_VULN = 'clean', 'vuln'

#: The scores an attestation earns its subject (at_stele.h).
SCORE_FINDING = 0.3
SCORE_CLEAN = 0.8

AD_KEYS = ('owner', 'name', 'url', 'ref', 'commit', 'seq', 'ts')
ATTEST_KEYS = ('verifier', 'repo_ad_id', 'commit', 'scanner', 'scanner_version',
               'db_digest', 'findings_digest', 'verdict', 'count',
               'max_severity', 'ts')


def _field_ok(s, max_len, empty_ok=False) -> bool:
    if not isinstance(s, str):
        return False
    b = s.encode('utf-8')
    if len(b) > max_len or (not b and not empty_ok):
        return False
    return all(c >= 0x20 and c != 0x7f and c != ord('|') for c in b)


def _hex_ok(s, n) -> bool:
    return (isinstance(s, str) and len(s) == n
            and all(c in '0123456789abcdef' for c in s))


def _uuid(s):
    try:
        return str(UUID(str(s)))
    except (ValueError, TypeError):
        return None


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def repo_ad_valid(ad) -> bool:
    try:
        return (_uuid(ad['owner']) is not None
                and UUID(str(ad['owner'])).int != 0
                and _field_ok(ad['name'], NAME_MAX)
                and _field_ok(ad['url'], URL_MAX)
                and _field_ok(ad['ref'], REF_MAX)
                and (_hex_ok(ad['commit'], 40) or _hex_ok(ad['commit'], 64))
                and _int(ad['seq']) is not None and ad['seq'] >= 0
                and _int(ad['ts']) is not None and ad['ts'] >= 0)
    except (KeyError, TypeError):
        return False


def attestation_valid(at) -> bool:
    try:
        clean = at['verdict'] == VERDICT_CLEAN
        vuln = at['verdict'] == VERDICT_VULN
        count = _int(at['count'])
        return (_uuid(at['verifier']) is not None
                and UUID(str(at['verifier'])).int != 0
                and _hex_ok(at['repo_ad_id'], DIGEST_HEX)
                and (_hex_ok(at['commit'], 40) or _hex_ok(at['commit'], 64))
                and _field_ok(at['scanner'], SCANNER_MAX)
                and _field_ok(at['scanner_version'], VERSION_MAX)
                and _hex_ok(at['db_digest'], DIGEST_HEX)
                and _hex_ok(at['findings_digest'], DIGEST_HEX)
                and (clean or vuln) and count is not None
                and (count == 0 if clean else count > 0)
                and _field_ok(at['max_severity'], SEVERITY_MAX, empty_ok=True)
                and _int(at['ts']) is not None and at['ts'] >= 0)
    except (KeyError, TypeError):
        return False


def repo_ad_canonical(ad) -> bytes:
    if not repo_ad_valid(ad):
        raise ValueError('invalid repo ad')
    body = '|'.join([_uuid(ad['owner']), ad['name'], ad['url'], ad['ref'],
                     ad['commit'], str(ad['seq']), str(ad['ts'])])
    return b'STELE-REPO\x00' + body.encode('utf-8')


def attestation_canonical(at) -> bytes:
    if not attestation_valid(at):
        raise ValueError('invalid attestation')
    body = '|'.join([_uuid(at['verifier']), at['repo_ad_id'], at['commit'],
                     at['scanner'], at['scanner_version'], at['db_digest'],
                     at['findings_digest'], at['verdict'], str(at['count']),
                     at['max_severity'], str(at['ts'])])
    return b'STELE-ATTEST\x00' + body.encode('utf-8')


def _id(canon: bytes) -> str:
    return hashlib.blake2b(canon, digest_size=32).hexdigest()


def repo_ad_id(ad) -> str:
    return _id(repo_ad_canonical(ad))


def attestation_id(at) -> str:
    """The attestation's id, which is the EVIDENCE DIGEST its score carries."""
    return _id(attestation_canonical(at))


def sign(signing_key, canon: bytes) -> str:
    return signing_key.sign(canon).signature.hex()


def verify(verify_key, canon: bytes, sig_hex) -> bool:
    try:
        sig = bytes.fromhex(sig_hex)
    except (ValueError, TypeError):
        return False
    if len(sig) != 64:
        return False
    from nacl.exceptions import BadSignatureError
    try:
        verify_key.verify(canon, sig)
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def from_envelope(env, keys):
    """``(artifact, sig)`` from an envelope dict, or None when a key is missing
    or of the wrong type (validity is the caller's next check)."""
    if not isinstance(env, dict) or not isinstance(env.get('sig'), str):
        return None
    out = {}
    for k in keys:
        if k not in env:
            return None
        out[k] = env[k]
    for k in ('owner', 'verifier'):
        if k in out:
            u = _uuid(out[k])
            if u is None:
                return None
            out[k] = u
    return out, env['sig']
