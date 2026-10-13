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
"""stele_team's `profile` (Phase 4): the polity's signed Stele profile, from
Ethne when it is importable and from the built-in emitter otherwise, verified
the way a viewer verifies it."""
import json
import os
import sys

import nacl.signing
import pytest

TOOLS = os.path.normpath(os.path.join(os.path.dirname(__file__), '..'))
VIEWER = os.path.normpath(os.path.join(TOOLS, '..', 'viewer'))
for p in (TOOLS, VIEWER):
    if p not in sys.path:
        sys.path.insert(0, p)
import stele_profile  # noqa: E402
import stele_team  # noqa: E402


def _spec(tmp_path, n=3):
    members = {}
    for i in range(n):
        root = tmp_path / ('node%d' % i)
        (root / 'etc' / 'at').mkdir(parents=True)
        sk = nacl.signing.SigningKey(bytes([20 + i]) * 32)
        (root / 'etc' / 'at' / 'identity.cfg.json').write_text(json.dumps(
            {'uuid': '00000000-0000-4000-8000-00000000000%d' % i,
             'signature': {'hex_seed': bytes(sk).hex()}}))
        members['m%d' % i] = str(root)
    spec = {'root': str(tmp_path / 'root.key'), 'members': members, 'officers': [],
            'profile': {'name': 'acme', 'replicas': 3, 'team': 'worst'},
            'profile_seq': 2}
    path = tmp_path / 'spec.json'
    path.write_text(json.dumps(spec))
    return spec, str(path)


def test_the_builtin_profile_verifies_as_a_viewer_reads_it(tmp_path):
    spec, path = _spec(tmp_path)
    out = str(tmp_path / 'acme.profile')
    assert stele_team.main(['x', 'profile', path, out, '--builtin']) == 0
    got = stele_profile.verify_signed(open(out).read())
    assert got['seq'] == 2 and got['issuer'] == bytes(stele_team.root_key(spec).verify_key).hex()
    assert got['profile'] == stele_profile.parse(spec['profile'])


def test_ethne_and_the_builtin_write_the_same_body(tmp_path):
    ethne = pytest.importorskip('ethne')
    if not hasattr(ethne, 'stele_profile'):
        pytest.skip('this Ethne build predates D42')
    spec, path = _spec(tmp_path)
    a, b = str(tmp_path / 'e'), str(tmp_path / 'b')
    assert stele_team.main(['x', 'profile', path, a]) == 0
    assert stele_team.main(['x', 'profile', path, b, '--builtin']) == 0
    ea, eb = (json.loads(json.loads(open(f).read())['body']) for f in (a, b))
    assert ea.pop('set_by') != eb.pop('set_by')      # only Ethne knows the CID
    assert ea == eb
    assert stele_profile.verify_signed(open(a).read())['seq'] == 2


def _anchor_spec(tmp_path):
    """A spec whose first member's roster lists all three nodes, one of them at
    a key that is not its own, and two checkpoints."""
    spec, path = _spec(tmp_path)
    keys = {}
    for name, root in spec['members'].items():
        uid, sk = stele_team.node_key(root)
        keys[uid] = bytes(sk.verify_key).hex()
    uids = sorted(keys)
    members = {u: {'pubkey': keys[u], 'tier': 3, 'member': True} for u in uids}
    members[uids[2]]['pubkey'] = '00' * 32     # a key the node never had
    members['00000000-0000-4000-8000-0000000000ff'] = {'pubkey': '11' * 32, 'member': False}
    roster = {'group_uuid': '3c4d5e6f-7081-4293-a4b5-c6d7e8f90a1b', 'self': uids[0],
              'members': members,
              'checkpoints': [{'group_uuid': '', 'epoch': 2, 'root': '22' * 32,
                               'first_index': 0, 'count': 7},
                              {'group_uuid': '', 'epoch': 1, 'root': '11' * 32,
                               'first_index': 0, 'count': 6}]}
    first = spec['members']['m0']
    with open(os.path.join(first, 'etc', 'at', 'roster.cfg.json'), 'w') as f:
        json.dump(roster, f)
    spec.update(anchor_from=first, anchor_seq=5)
    with open(path, 'w') as f:
        json.dump(spec, f)
    return spec, path, uids


def test_the_builtin_anchor_lists_consenting_members_and_verifies(tmp_path):
    from autonomous_trust.stele import anchor
    spec, path, uids = _anchor_spec(tmp_path)
    out = str(tmp_path / 'acme.anchor')
    assert stele_team.main(['x', 'anchor', path, out, '--builtin']) == 0
    a = anchor.parse_anchor(open(out).read())
    assert a is not None and a['seq'] == 5
    # The node listed under a key it never had cannot consent, so it is left
    # out, as is the roster entry that is not a member.
    assert [m['at_uuid'] for m in a['members']] == uids[:2]
    assert [c['epoch'] for c in a['checkpoints']] == [1, 2]


def test_ethne_and_the_builtin_write_the_same_anchor(tmp_path):
    try:
        import ethne
    except ImportError:
        pytest.skip('no Ethne build importable')
    if not hasattr(ethne, 'stele_group_anchor'):
        pytest.skip('this Ethne build predates D43')
    spec, path, _uids = _anchor_spec(tmp_path)
    a, b = str(tmp_path / 'a'), str(tmp_path / 'b')
    assert stele_team.main(['x', 'anchor', path, a]) == 0
    assert stele_team.main(['x', 'anchor', path, b, '--builtin']) == 0
    assert open(a).read() == open(b).read()
