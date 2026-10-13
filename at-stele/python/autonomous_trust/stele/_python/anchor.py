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
"""Stele Phase 4: a polity's group anchor (Ethne design D43, border artifact
#12). Twin of at-stele/c/stele/stele_anchor.c.

``{"body": <exact JSON text>, "sig": <hex>}``, signed by the polity root key
(``issuer``) under ``stele-anchor-v1|``. The body names an AT group
(``group_uuid``), each node in it with its AT public key, its tier and its
consent (the node's own signature over
``stele-anchor-member-v1|issuer|group_uuid|at_uuid|pubkey``), and the
checkpoints the group signed. A reader in another group that follows the
polity takes the group's keys from here, since it holds none of its own.

Unlike a team roster's consents, these name their own key, so they are checked
here, and an anchor with one that fails is not an anchor."""
import json

from .team import _hex, _uuid, _did, _sig_ok, _signed_body

ANCHOR_DOMAIN = b'stele-anchor-v1|'
ANCHOR_CONSENT_DOMAIN = 'stele-anchor-member-v1|'
ANCHOR_TYPENAME = 'stele-group-anchor'
ANCHOR_MEMBERS_MAX = 256
ANCHOR_CHECKPOINTS_MAX = 512
ANCHOR_FILE_MAX = 256 * 1024
TIER_MAX = 4
#: The smallest group a quorum is counted against (AT's ANCHOR_MIN_GROUP).
MIN_GROUP = 3


def consent_message(issuer, group_uuid, at_uuid, pubkey) -> bytes:
    """The bytes a node signs to consent to an anchor. Mirrors
    stele_anchor_consent_message and Ethne's anchor_consent_message."""
    return ('%s%s|%s|%s|%s' % (ANCHOR_CONSENT_DOMAIN, issuer, group_uuid, at_uuid,
                               pubkey)).encode('utf-8')


def _int(v, lo=0) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= lo


def parse_anchor(text):
    """The anchor ``{issuer, polity, seq, group_uuid, members, checkpoints}``,
    or None unless the root signature verifies, the shape holds, and every
    listed node's consent verifies under the key it is listed with. Mirrors
    stele_anchor_parse."""
    if not isinstance(text, str) or len(text) > ANCHOR_FILE_MAX:
        return None
    b = _signed_body(text, ANCHOR_DOMAIN, 'issuer')
    if b is None:
        return None
    try:
        if not (b['v'] == 1 and not isinstance(b['v'], bool)
                and b['typename'] == ANCHOR_TYPENAME and _int(b['seq'])
                and _did(b['polity']) and _uuid(b['group_uuid'])):
            return None
        members, cks = b['members'], b['checkpoints']
        if not (isinstance(members, list) and 1 <= len(members) <= ANCHOR_MEMBERS_MAX
                and isinstance(cks, list) and len(cks) <= ANCHOR_CHECKPOINTS_MAX):
            return None
        out = {'issuer': b['issuer'], 'polity': b['polity'], 'seq': b['seq'],
               'group_uuid': b['group_uuid'], 'members': [], 'checkpoints': []}
        nodes, keys = set(), set()
        for m in members:
            if not (isinstance(m, dict) and _uuid(m['at_uuid']) and _hex(m['pubkey'], 64)
                    and _int(m['tier']) and m['tier'] <= TIER_MAX
                    and _hex(m['consent'], 128)
                    and m['at_uuid'] not in nodes and m['pubkey'] not in keys):
                return None
            msg = consent_message(b['issuer'], b['group_uuid'], m['at_uuid'], m['pubkey'])
            if not _sig_ok(m['pubkey'], msg, m['consent']):
                return None
            nodes.add(m['at_uuid'])
            keys.add(m['pubkey'])
            out['members'].append({k: m[k] for k in ('at_uuid', 'pubkey', 'tier')})
        for c in cks:
            if not (isinstance(c, dict)
                    and (c['group_uuid'] == '' or _uuid(c['group_uuid']))
                    and _int(c['epoch']) and _hex(c['root'], 64)
                    and _int(c['first_index']) and _int(c['count'])):
                return None
            out['checkpoints'].append({k: c[k] for k in ('group_uuid', 'epoch', 'root',
                                                         'first_index', 'count')})
        return out
    except (KeyError, TypeError):
        return None


def to_at_anchor(anchor, min_group=MIN_GROUP):
    """The anchor AT's ``verify_attested_record`` takes (``load_anchor``'s
    shape), built from a parsed group anchor: every key from the anchor, the
    tiers as the polity states them, and its checkpoints, so a record under one
    of them is ``linked``."""
    return {'group_uuid': anchor['group_uuid'], 'self': '',
            'members': {m['at_uuid']: {'pubkey': m['pubkey'], 'tier': m['tier'],
                                       'member': True}
                        for m in anchor['members']},
            'checkpoints': [dict(c) for c in anchor['checkpoints']],
            'min_group': int(min_group)}


def body_text(text):
    """The exact signed body text of a signed file, or None."""
    try:
        outer = json.loads(text)
        return outer['body'] if isinstance(outer.get('body'), str) else None
    except (ValueError, TypeError, AttributeError):
        return None
