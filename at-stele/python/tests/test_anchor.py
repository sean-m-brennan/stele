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
"""The group anchor (Ethne D43, border artifact #12), the Python half. The
pinned vector is Ethne's (en-uplift stele.rs, the_anchor_file_is_byte_pinned);
c/stele/test/stele_anchor_test.c holds the same file."""
import json

import nacl.signing

from autonomous_trust.stele import anchor

#: Ethne's pinned group anchor: root seed 7, nodes seeds 30, 31, 32.
PINNED = '{"body":"{\\"v\\":1,\\"typename\\":\\"stele-group-anchor\\",\\"polity\\":\\"did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z\\",\\"issuer\\":\\"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c\\",\\"seq\\":4,\\"group_uuid\\":\\"3c4d5e6f-7081-4293-a4b5-c6d7e8f90a1b\\",\\"members\\":[{\\"at_uuid\\":\\"0f1e2d3c-4b5a-4968-8776-655443322110\\",\\"pubkey\\":\\"acdb0e29743f0ccb8686d0a104cb96e05abefec1538765e7595869f7dc8c49aa\\",\\"tier\\":3,\\"consent\\":\\"7ae992f006cb1cb44cc18ada695fd4e03e522b5feab21b4db73a520118b03508054ad59b3bd4beaebd02edcaaf23cc814ebc568b252904528647564dc19b0f0a\\"},{\\"at_uuid\\":\\"1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9\\",\\"pubkey\\":\\"43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de\\",\\"tier\\":1,\\"consent\\":\\"06426d6054275e4d3bf48240ce471af44cf4aa42a4dd58415b646b5ac6d6fa6c3279173a39346e2aac3612cdf8a454fd3753b09b6dce8d56c6a56cb83b9a6001\\"},{\\"at_uuid\\":\\"2b3c4d5e-6f70-4182-93a4-b5c6d7e8f90a\\",\\"pubkey\\":\\"4ed32f63bf35f0eeefcb25f28a2e1fbdc873ae2835671b0c9460f5f12e4556a8\\",\\"tier\\":3,\\"consent\\":\\"bf3475307402da84aca9d15b3101dafe58eb5629f49066fbc70743268cd864602d5b5d3ed5dfaa425fa4a5d75fd66461f1dbc49ba69bb90b130c9483cfdb2202\\"}],\\"checkpoints\\":[{\\"group_uuid\\":\\"\\",\\"epoch\\":1,\\"root\\":\\"0000000000000000000000000000000000000000000000000000000000000001\\",\\"first_index\\":0,\\"count\\":6},{\\"group_uuid\\":\\"\\",\\"epoch\\":2,\\"root\\":\\"0000000000000000000000000000000000000000000000000000000000000002\\",\\"first_index\\":0,\\"count\\":7}]}","sig":"184f26c56101d5a888472c05f01282cc53fe6e8ff3aa8bf2e3b2bab7587d100e572e925176ee79c6bab7f43e3b096b88cc6f15e21b8deb391a743e0b00b54109"}'

GROUP = '3c4d5e6f-7081-4293-a4b5-c6d7e8f90a1b'
ROOT = nacl.signing.SigningKey(bytes([7] * 32))


def _node(seed):
    return nacl.signing.SigningKey(bytes([seed] * 32))


def mint(members, checkpoints, seq=4, group=GROUP, root=ROOT, polity=None):
    """An anchor, written the way Ethne writes it (field order, compact JSON)."""
    issuer = bytes(root.verify_key).hex()
    polity = polity or json.loads(json.loads(PINNED)['body'])['polity']
    listed = []
    for uuid, sk, tier, signer in sorted(members, key=lambda m: m[0]):
        key = bytes(sk.verify_key).hex()
        consent = (signer or sk).sign(anchor.consent_message(issuer, group, uuid, key)).signature.hex()
        listed.append({'at_uuid': uuid, 'pubkey': key, 'tier': tier, 'consent': consent})
    body = json.dumps({'v': 1, 'typename': 'stele-group-anchor', 'polity': polity,
                       'issuer': issuer, 'seq': seq, 'group_uuid': group,
                       'members': listed,
                       'checkpoints': [{'group_uuid': '', 'epoch': e, 'root': r,
                                        'first_index': f, 'count': n}
                                       for e, r, f, n in checkpoints]},
                      separators=(',', ':'))
    sig = root.sign(anchor.ANCHOR_DOMAIN + body.encode()).signature.hex()
    return json.dumps({'body': body, 'sig': sig}, separators=(',', ':'))


MEMBERS = [('0f1e2d3c-4b5a-4968-8776-655443322110', _node(30), 3, None),
           ('1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9', _node(31), 1, None),
           ('2b3c4d5e-6f70-4182-93a4-b5c6d7e8f90a', _node(32), 3, None)]
CKS = [(1, '%064x' % 1, 0, 6), (2, '%064x' % 2, 0, 7)]


def test_ethnes_pinned_anchor_parses_and_this_side_writes_the_same_bytes():
    a = anchor.parse_anchor(PINNED)
    assert a is not None and a['seq'] == 4 and a['group_uuid'] == GROUP
    assert [m['tier'] for m in a['members']] == [3, 1, 3]
    assert [c['epoch'] for c in a['checkpoints']] == [1, 2]
    assert mint(MEMBERS, CKS) == PINNED


def test_a_tampered_or_unconsented_anchor_is_not_an_anchor():
    outer = json.loads(PINNED)
    outer['body'] = outer['body'].replace('"tier":1', '"tier":3')
    assert anchor.parse_anchor(json.dumps(outer)) is None
    # The root lists node 31's key, but node 33 signed the consent.
    forged = [m if m[2] != 1 else (m[0], m[1], m[2], _node(33)) for m in MEMBERS]
    assert anchor.parse_anchor(mint(forged, CKS)) is None
    # A consent for another group does not carry over.
    other = mint(MEMBERS, CKS, group='4d5e6f70-8192-43a4-b5c6-d7e8f90a1b2c')
    body = json.loads(json.loads(other)['body'])
    moved = json.loads(json.loads(mint(MEMBERS, CKS))['body'])
    moved['members'] = body['members']
    text = json.dumps(moved, separators=(',', ':'))
    assert anchor.parse_anchor(json.dumps({'body': text, 'sig': ROOT.sign(
        anchor.ANCHOR_DOMAIN + text.encode()).signature.hex()})) is None
    assert anchor.parse_anchor(mint([], CKS)) is None
    assert anchor.parse_anchor(mint([(MEMBERS[0][0], _node(30), 5, None)], CKS)) is None


def test_the_at_anchor_takes_every_key_and_tier_from_the_polity():
    at = anchor.to_at_anchor(anchor.parse_anchor(PINNED))
    assert at['group_uuid'] == GROUP and at['min_group'] == 3
    assert at['members']['1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9'] == {
        'pubkey': bytes(_node(31).verify_key).hex(), 'tier': 1, 'member': True}
    assert at['checkpoints'][1]['root'] == '%064x' % 2
