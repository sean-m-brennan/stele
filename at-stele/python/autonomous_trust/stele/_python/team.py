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
"""Stele Phase 3: a team's roster and release authorizations, the two files an
Ethne polity emits for Stele (Ethne design D41). Twin of
at-stele/c/stele/stele_team.c; see its header for the formats.

Both are ``{"body": <exact JSON text>, "sig": <hex>}``. The roster is signed by
the team's root key (``issuer``, which is the team's identity here) under
``stele-team-v1|``, and each member carries its AT node's consent, the node's
own signature over ``stele-team-member-v1|issuer|did|at_uuid``. A release
authorization is signed by its officer under ``stele-release-v1|``."""
import json

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

TEAM_DOMAIN = b'stele-team-v1|'
CONSENT_DOMAIN = 'stele-team-member-v1|'
RELEASE_DOMAIN = b'stele-release-v1|'
TEAM_MAX = 64
TEAM_FILE_MAX = 32768
RELEASE_MAX = 2048
DID_MAX = 64
NAME_MAX, URL_MAX = 64, 256


def _hex(s, n) -> bool:
    return isinstance(s, str) and len(s) == n and all(c in '0123456789abcdef' for c in s)


def _uuid(s) -> bool:
    return (isinstance(s, str) and len(s) == 36
            and all((c == '-') if i in (8, 13, 18, 23) else (c in '0123456789abcdef')
                    for i, c in enumerate(s)))


def _did(s) -> bool:
    return (isinstance(s, str) and s.startswith('did:key:z') and len(s) <= DID_MAX
            and all(0x21 <= ord(c) < 0x7f and c != '|' for c in s))


def _str(v, cap) -> bool:
    return isinstance(v, str) and len(v.encode('utf-8')) < cap


def _sig_ok(key_hex, msg: bytes, sig_hex) -> bool:
    if not _hex(key_hex, 64) or not _hex(sig_hex, 128):
        return False
    try:
        VerifyKey(bytes.fromhex(key_hex)).verify(msg, bytes.fromhex(sig_hex))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def _signed_body(text, domain: bytes, key_field):
    """The parsed body of a signed file, or None unless ``sig`` verifies over
    domain + body under the hex key the body names in ``key_field``."""
    try:
        outer = json.loads(text)
        body, sig = outer['body'], outer['sig']
        parsed = json.loads(body)
    except (ValueError, TypeError, KeyError):
        return None
    if not isinstance(parsed, dict) or not isinstance(body, str):
        return None
    if not _sig_ok(parsed.get(key_field), domain + body.encode('utf-8'), sig):
        return None
    return parsed


def consent_message(issuer, did, at_uuid) -> bytes:
    """The bytes a member's AT node signs to consent. Mirrors
    stele_consent_message and Ethne's consent_message."""
    return ('%s%s|%s|%s' % (CONSENT_DOMAIN, issuer, did, at_uuid)).encode('utf-8')


def parse_team(text):
    """A roster's members, officers and guardian edges, or None unless the
    root signature verifies and the shape holds (every officer and both ends of
    every edge listed; no member or node twice). Consents are NOT checked here
    (:func:`consents_ok`). Mirrors stele_team_parse."""
    if not isinstance(text, str) or len(text) > TEAM_FILE_MAX:
        return None
    b = _signed_body(text, TEAM_DOMAIN, 'issuer')
    if b is None:
        return None
    try:
        if not (b['v'] == 1 and not isinstance(b['v'], bool)
                and b['typename'] == 'stele-team'
                and isinstance(b['seq'], int) and b['seq'] >= 0
                and _did(b['polity'])):
            return None
        members, officers, guardians = b['members'], b['release_officers'], b['guardians']
        if not all(isinstance(x, list) and len(x) <= TEAM_MAX
                   for x in (members, officers, guardians)):
            return None
        team = {'issuer': b['issuer'], 'polity': b['polity'], 'seq': b['seq'],
                'members': [], 'officers': [], 'guardians': []}
        dids, nodes = set(), set()
        for m in members:
            if not (isinstance(m, dict) and _did(m['did']) and _hex(m['key'], 64)
                    and _uuid(m['at_uuid']) and _hex(m['consent'], 128)
                    and m['did'] not in dids and m['at_uuid'] not in nodes):
                return None
            dids.add(m['did'])
            nodes.add(m['at_uuid'])
            team['members'].append({k: m[k] for k in ('did', 'key', 'at_uuid', 'consent')})
        for o in officers:
            if not (isinstance(o, str) and o in dids):
                return None
            team['officers'].append(o)
        for g in guardians:
            if not (isinstance(g, dict) and g['machine'] in dids and g['guardian'] in dids
                    and g['machine'] != g['guardian']):
                return None
            team['guardians'].append({'machine': g['machine'], 'guardian': g['guardian']})
        return team
    except (KeyError, TypeError):
        return None


def member(team, did=None, at_uuid=None):
    for m in team['members']:
        if (did is not None and m['did'] == did) or \
                (at_uuid is not None and m['at_uuid'] == at_uuid):
            return m
    return None


def guardian_of(team, machine):
    return next((g['guardian'] for g in team['guardians'] if g['machine'] == machine),
                None)


def consents_ok(team, lookup):
    """``(True, None)`` when every member's consent verifies under the key
    ``lookup(at_uuid)`` gives (hex, or None when this node holds none), else
    ``(False, at_uuid)`` naming the first that does not. Mirrors
    stele_team_consents_ok."""
    for m in team['members']:
        key = lookup(m['at_uuid'])
        msg = consent_message(team['issuer'], m['did'], m['at_uuid'])
        if key is None or not _sig_ok(key, msg, m['consent']):
            return False, m['at_uuid']
    return True, None


def parse_release(text):
    """A release authorization, or None unless the officer's signature
    verifies. Mirrors stele_release_parse."""
    if not isinstance(text, str) or len(text) > RELEASE_MAX:
        return None
    b = _signed_body(text, RELEASE_DOMAIN, 'officer_key')
    if b is None:
        return None
    try:
        ok = (b['v'] == 1 and not isinstance(b['v'], bool)
              and b['typename'] == 'stele-release'
              and isinstance(b['authorized_at'], int) and b['authorized_at'] >= 0
              and _hex(b['issuer'], 64) and _did(b['polity']) and _did(b['officer'])
              and _str(b['repo'], NAME_MAX + 1) and _str(b['url'], URL_MAX + 1)
              and (_hex(b['commit'], 40) or _hex(b['commit'], 64))
              and ('built_by' not in b or _did(b['built_by'])))
    except (KeyError, TypeError):
        return None
    if not ok:
        return None
    return {k: b[k] for k in ('issuer', 'polity', 'officer', 'officer_key', 'repo',
                              'url', 'commit', 'authorized_at')} | {
        'built_by': b.get('built_by', '')}
