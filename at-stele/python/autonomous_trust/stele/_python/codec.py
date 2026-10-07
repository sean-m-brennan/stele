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
"""Stele's signed artifacts. Byte-for-byte twin of
at-stele/c/stele/stele_codec.c; see its header for the forms.

A repo ad is dict-shaped ``{owner, name, url, ref, commit, seq, ts}``; an
attestation ``{verifier, repo_ad_id, commit, scanner, scanner_version,
db_digest, findings_digest, verdict, count, max_severity, ts}``. Version 2
(``'v': 2`` in the dict and the envelope) appends ``description, topics,
sbom_digest, sbom_path, claim_verdict`` to an ad and ``channel, scope`` to an
attestation, under tags of their own, so a v1 artifact's bytes never change.
Version 3 (``'v': 3``, Phase 2) appends ``replicates`` to an attestation: the
id of the attestation a replication re-ran, set exactly on the ``replication``
channel. A rebuttal is ``{owner, attestation_id, text, ts}``. Envelopes add
``sig``."""

import hashlib
from uuid import UUID

NAME_MAX, URL_MAX, REF_MAX = 64, 256, 64
SCANNER_MAX, VERSION_MAX, SEVERITY_MAX = 32, 32, 16
DIGEST_HEX = 64
VERDICT_CLEAN, VERDICT_VULN = 'clean', 'vuln'
CLAIM_NONE = 'none'
DESC_MAX, TOPICS_MAX, PATH_MAX, CHANNEL_MAX, REBUT_MAX = 256, 128, 256, 31, 280
CHANNEL_PROBE, CHANNEL_CERTIFICATE, CHANNEL_SELF_CONSISTENCY = (
    'probe', 'certificate', 'self_consistency')
CHANNELS = (CHANNEL_PROBE, CHANNEL_CERTIFICATE, CHANNEL_SELF_CONSISTENCY)
#: Only a v3 attestation may be on it, since it must name what it replicates.
CHANNEL_REPLICATION = 'replication'
CHANNELS3 = CHANNELS + (CHANNEL_REPLICATION,)

#: The scores an attestation earns its subject (at_stele.h).
SCORE_FINDING = 0.3
SCORE_CLEAN = 0.8

AD_KEYS = ('owner', 'name', 'url', 'ref', 'commit', 'seq', 'ts')
ATTEST_KEYS = ('verifier', 'repo_ad_id', 'commit', 'scanner', 'scanner_version',
               'db_digest', 'findings_digest', 'verdict', 'count',
               'max_severity', 'ts')
AD2_KEYS = ('description', 'topics', 'sbom_digest', 'sbom_path', 'claim_verdict')
ATTEST2_KEYS = ('channel', 'scope')
ATTEST3_KEYS = ATTEST2_KEYS + ('replicates',)
REBUT_KEYS = ('owner', 'attestation_id', 'text', 'ts')


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


def _v2(item) -> bool:
    return isinstance(item, dict) and item.get('v') == 2


def repo_ad_valid(ad) -> bool:
    try:
        if ad.get('v', 1) not in (1, 2):
            return False
        if _v2(ad):
            has_sbom = ad['sbom_digest'] != ''
            if not (_field_ok(ad['description'], DESC_MAX, empty_ok=True)
                    and _field_ok(ad['topics'], TOPICS_MAX, empty_ok=True)
                    and (_hex_ok(ad['sbom_digest'], DIGEST_HEX) if has_sbom
                         else True)
                    and _field_ok(ad['sbom_path'], PATH_MAX, empty_ok=True)
                    and has_sbom == (ad['sbom_path'] != '')
                    and ad['claim_verdict'] in (VERDICT_CLEAN, VERDICT_VULN,
                                                CLAIM_NONE)):
                return False
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
        if at.get('v', 1) not in (1, 2, 3):
            return False
        if _v2(at) and not (at['channel'] in CHANNELS
                            and _hex_ok(at['scope'], DIGEST_HEX)):
            return False
        if at.get('v') == 3:
            repl = at['channel'] == CHANNEL_REPLICATION
            if not (at['channel'] in CHANNELS3
                    and _hex_ok(at['scope'], DIGEST_HEX)
                    and (_hex_ok(at['replicates'], DIGEST_HEX) if repl
                         else at['replicates'] == '')):
                return False
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
    fields = [_uuid(ad['owner']), ad['name'], ad['url'], ad['ref'],
              ad['commit'], str(ad['seq']), str(ad['ts'])]
    if not _v2(ad):
        return b'STELE-REPO\x00' + '|'.join(fields).encode('utf-8')
    fields += [ad[k] for k in AD2_KEYS]
    return b'STELE-REPO2\x00' + '|'.join(fields).encode('utf-8')


def attestation_canonical(at) -> bytes:
    if not attestation_valid(at):
        raise ValueError('invalid attestation')
    fields = [_uuid(at['verifier']), at['repo_ad_id'], at['commit'],
              at['scanner'], at['scanner_version'], at['db_digest'],
              at['findings_digest'], at['verdict'], str(at['count']),
              at['max_severity'], str(at['ts'])]
    if at.get('v', 1) == 1:
        return b'STELE-ATTEST\x00' + '|'.join(fields).encode('utf-8')
    fields += [at['channel'], at['scope']]
    if _v2(at):
        return b'STELE-ATTEST2\x00' + '|'.join(fields).encode('utf-8')
    fields.append(at['replicates'])
    return b'STELE-ATTEST3\x00' + '|'.join(fields).encode('utf-8')


def rebuttal_valid(rb) -> bool:
    try:
        return (_uuid(rb['owner']) is not None
                and UUID(str(rb['owner'])).int != 0
                and _hex_ok(rb['attestation_id'], DIGEST_HEX)
                and _field_ok(rb['text'], REBUT_MAX)
                and _int(rb['ts']) is not None and rb['ts'] >= 0)
    except (KeyError, TypeError):
        return False


def rebuttal_canonical(rb) -> bytes:
    if not rebuttal_valid(rb):
        raise ValueError('invalid rebuttal')
    body = '|'.join([_uuid(rb['owner']), rb['attestation_id'], rb['text'],
                     str(rb['ts'])])
    return b'STELE-REBUT\x00' + body.encode('utf-8')


def rebuttal_id(rb) -> str:
    return _id(rebuttal_canonical(rb))


def scope(owner, name, commit, scanner) -> str:
    """The scope an attestation about (owner, name, commit) by `scanner` names:
    blake2b-256 of ``owner|name|commit|scanner``. A new commit is a new scope,
    so a fresh scan can answer an earlier finding while a repeat about the same
    commit is capped. Mirrors stele_scope."""
    body = '|'.join([_uuid(owner), name, commit, scanner]).encode('utf-8')
    return hashlib.blake2b(body, digest_size=32).hexdigest()


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
    extra = ()
    if 'v' in env:
        versions = {AD_KEYS: {2: AD2_KEYS},
                    ATTEST_KEYS: {2: ATTEST2_KEYS, 3: ATTEST3_KEYS}}.get(tuple(keys), {})
        if env['v'] not in versions or isinstance(env['v'], bool):
            return None
        extra = versions[env['v']]
        out['v'] = env['v']
    for k in tuple(keys) + tuple(extra):
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
