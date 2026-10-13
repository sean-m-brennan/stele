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
"""Discovery relays (Phase 4): another group's records, which a reader verifies
only under the group anchor of a polity it follows (Ethne D43), and a relay's
answer folded beside what the reader verified. The other group is a second
observer node with real AT records, archived the way test_stele_view's is."""
import glob
import json
import os
import sys

import nacl.signing
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from test_stele_view import NOW, URL, C1, Node  # noqa: E402

import stele_anchors  # noqa: E402
from autonomous_trust.stele import anchor  # noqa: E402

ROOT = nacl.signing.SigningKey(bytes([7] * 32))
OTHER_ROOT = nacl.signing.SigningKey(bytes([8] * 32))


def _confirmed_finding(node):
    ad_id, ad = node.advertise(C1, 1)
    first = node.attest(ad_id, ad, 'vuln', NOW)
    node.attest(ad_id, ad, 'vuln', NOW + 5, by=node.ver2, replicates=first)


def _mint(node, tiers, root=ROOT, seq=1, leave_out=()):
    """The other group's anchor, from its observer's roster, every node
    consenting with its own AT key."""
    with open(os.path.join(str(node.root), 'etc', 'at', 'roster.cfg.json')) as f:
        roster = json.load(f)
    issuer = bytes(root.verify_key).hex()
    group = roster['group_uuid']
    if len(str(group)) != 36:          # the fixture's group is a MagicMock
        group = '3c4d5e6f-7081-4293-a4b5-c6d7e8f90a1b'
    idents = {str(i.uuid): (name, i) for name, i in
              (('owner', node.owner), ('ver', node.ver), ('ver2', node.ver2),
               ('obs', node.obs))}
    members = []
    for uid in sorted(roster['members']):
        if uid not in idents or idents[uid][0] in leave_out:
            continue
        name, ident = idents[uid]
        key = roster['members'][uid]['pubkey']
        consent = ident.sign(anchor.consent_message(issuer, group, uid, key)) \
            .signature.decode('ascii')
        members.append({'at_uuid': uid, 'pubkey': key, 'tier': tiers.get(name, 0),
                        'consent': consent})
    body = json.dumps({'v': 1, 'typename': 'stele-group-anchor',
                       'polity': 'did:key:zForeignPolity', 'issuer': issuer, 'seq': seq,
                       'group_uuid': group, 'members': members,
                       'checkpoints': [{k: c[k] for k in ('group_uuid', 'epoch', 'root',
                                                          'first_index', 'count')}
                                       for c in roster['checkpoints']]},
                      separators=(',', ':'))
    return json.dumps({'body': body,
                       'sig': root.sign(anchor.ANCHOR_DOMAIN + body.encode()).signature.hex()})


def _bundle(node, anchors=()):
    def load(*parts):
        out = []
        for path in sorted(glob.glob(os.path.join(str(node.root), 'etc', *parts, '*.json'))):
            with open(path) as f:
                out.append(json.load(f))
        return out
    return {'schema': 'stele-bundle-1', 'url': URL, 'ads': load('stele', 'ads'),
            'attestations': load('stele', 'attestations'),
            'records': load('at', 'attested'), 'anchors': list(anchors)}


@pytest.fixture
def groups(tmp_path, monkeypatch):
    """(the other group's node, its anchor text, the reader's home node)."""
    other = Node(tmp_path / 'other', monkeypatch)
    _confirmed_finding(other)
    text = _mint(other, {'ver': 3, 'ver2': 3, 'obs': 3, 'owner': 2})
    home = Node(tmp_path / 'home', monkeypatch)   # its own group, its own roster
    return other, text, home


def test_another_groups_records_verify_only_under_a_followed_anchor(groups):
    other, text, home = groups
    view = home.view()
    got = view.add_bundle(_bundle(other))
    assert got['verified'] == 0                    # no keys of that group here
    st = view.standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'unknown' and 'anchored_by' not in st

    stele_anchors.follow(str(home.root), text)
    view = home.view()
    assert view.add_bundle(_bundle(other))['verified'] == 2
    st = view.standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'failing'
    assert st['anchored_by']['polity'] == 'did:key:zForeignPolity'
    assert st['anchored_by']['tiers'] == 'tiers as did:key:zForeignPolity reads them'
    check = st['checks'][0]
    assert check['agreement'] == 2 and all(c.get('via') for c in st['checks'])
    assert st['checkpoints']['listed'] >= st['checkpoints']['with_records'] >= 1


def test_the_tiers_are_the_anchors(groups, monkeypatch):
    other, _text, home = groups
    low = _mint(other, {'ver': 1, 'ver2': 1, 'obs': 3, 'owner': 2})
    stele_anchors.follow(str(home.root), low)
    view = home.view()
    view.add_bundle(_bundle(other))
    st = view.standing_by_url(URL, now=NOW + 60)
    # Both verifiers sit below the profile's tier as the polity reads them:
    # the finding blocks green, unconfirmed.
    assert st['state'] == 'failing-unconfirmed'
    assert not any(v['counted'] for v in st['checks'][0]['verifiers'])


def test_an_unfollowed_anchor_or_one_without_the_subject_vouches_for_nothing(groups):
    other, text, home = groups
    # The polity's anchor rides in the bundle, but this reader never followed
    # it: a bundle cannot introduce the keys it is verified with.
    assert home.view().add_bundle(_bundle(other, anchors=[text]))['verified'] == 0
    # A followed polity that lists the group but not the owner the records are
    # about vouches for nothing about that owner.
    stele_anchors.follow(str(home.root), _mint(other, {'ver': 3, 'ver2': 3, 'obs': 3},
                                               leave_out=('owner',)))
    assert home.view().add_bundle(_bundle(other))['verified'] == 0
    # Another polity whose anchor the same nodes consented to does vouch: the
    # consents, not the root alone, are what bind a node to an anchor.
    stele_anchors.follow(str(home.root), _mint(other, {'ver': 3, 'ver2': 3, 'obs': 3,
                                                       'owner': 2}, root=OTHER_ROOT))
    assert home.view().add_bundle(_bundle(other))['verified'] == 2


def test_a_newer_anchor_in_a_bundle_is_taken_for_that_answer_only(groups):
    other, text, home = groups
    stele_anchors.follow(str(home.root), _mint(other, {'ver': 1, 'ver2': 1}, seq=1))
    newer = _mint(other, {'ver': 3, 'ver2': 3, 'obs': 3, 'owner': 2}, seq=2)
    view = home.view()
    view.add_bundle(_bundle(other, anchors=[newer]))
    assert view.standing_by_url(URL, now=NOW + 60)['state'] == 'failing'
    assert stele_anchors.followed(str(home.root))[bytes(ROOT.verify_key).hex()][0]['seq'] == 1


def test_a_relay_answer_is_folded_beside_what_the_reader_verified(groups):
    other, text, home = groups
    stele_anchors.follow(str(home.root), text)
    owner = str(other.owner.uuid)
    word = {'findings': 0, 'clean': 5, 'verifiers': 2,
            'anchor_issuer': bytes(ROOT.verify_key).hex()}
    search = {'query': 'demo', 'complete': True, 'relays': [
        {'relay': '10.0.0.9:27790', 'answer': {'op': 'stl_results', 'results': [
            {'repo': {'owner': owner, 'name': 'demo', 'url': URL}, 'relay': word},
            {'repo': {'owner': 'ffffffff-0000-4000-8000-000000000001', 'name': 'solo',
                      'url': 'http://f/solo.git'},
             'relay': {'findings': 0, 'clean': 1, 'verifiers': 1, 'anchor_issuer': None}}]}}]}
    view = home.view()
    out = view.relay_search(search, now=NOW + 60)
    assert [e['reason'] for e in out['results']] == ['fetch to verify', 'group not followed']
    assert out['results'][0]['relays'][0]['clean'] == 5         # the relay's own word

    fetch = {'query': URL, 'complete': True, 'relays': [
        {'relay': '10.0.0.9:27790', 'answer': {'op': 'stl_bundle', 'bundle': _bundle(other)}}]}
    st = view.relay_standing(fetch, URL, now=NOW + 60)
    # The relay said clean; the records it handed over say otherwise.
    assert st['standing']['state'] == 'failing' and 'reason' not in st
    assert st['relays'][0]['verified'] == 2
    after = view.relay_search(search, now=NOW + 60)
    assert after['results'][0]['verified']['state'] == 'failing'


def test_a_search_folds_in_what_the_node_already_fetched(groups):
    other, text, home = groups
    stele_anchors.follow(str(home.root), text)
    import hashlib
    rid = hashlib.sha256(('fetch|%s' % URL).encode()).hexdigest()[:16]
    d = os.path.join(str(home.root), 'etc', 'stele', 'relay')
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'fetch-%s.json' % rid), 'w') as f:
        json.dump({'query': URL, 'complete': True, 'relays': [
            {'relay': 'r:1', 'answer': {'op': 'stl_bundle', 'bundle': _bundle(other)}}]}, f)
    search = {'query': 'demo', 'relays': [{'relay': 'r:1', 'answer': {'results': [
        {'repo': {'owner': str(other.owner.uuid), 'name': 'demo', 'url': URL},
         'relay': {'findings': 0, 'clean': 3, 'verifiers': 1, 'anchor_issuer': None}}]}}]}
    out = home.view().relay_search(search, now=NOW + 60)
    assert out['results'][0]['verified']['state'] == 'failing'
