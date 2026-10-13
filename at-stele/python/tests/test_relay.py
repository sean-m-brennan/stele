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
"""The discovery relay's store, the Python half (twin of
c/stele/test/stele_relay_test.c)."""
import hashlib

from autonomous_trust.stele import codec, relay

from test_anchor import PINNED

OWNER = '0f1e2d3c-4b5a-4968-8776-655443322110'
VERIFIER = '1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9'
COMMIT = '0123456789abcdef0123456789abcdef01234567'
URL = 'http://forge.local/alice/demo.git'
SIG = '00' * 64
ISSUER = 'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c'


def _ad():
    ad = {'owner': OWNER, 'name': 'demo', 'url': URL, 'ref': 'main', 'commit': COMMIT,
          'seq': 1, 'ts': 1790000000, 'v': 2, 'description': 'a library for demos',
          'topics': 'go,demo', 'sbom_digest': '', 'sbom_path': '', 'claim_verdict': 'none'}
    return codec.repo_ad_id(ad), dict(ad, sig=SIG)


def _attestation(ad_id, verdict):
    at = {'verifier': VERIFIER, 'repo_ad_id': ad_id, 'commit': COMMIT,
          'scanner': 'osv-scanner', 'scanner_version': '2.6.0', 'db_digest': 'c' * 64,
          'findings_digest': 'e' * 64, 'verdict': verdict,
          'count': 2 if verdict == 'vuln' else 0,
          'max_severity': 'HIGH' if verdict == 'vuln' else '', 'ts': 1790000100}
    return codec.attestation_id(at), dict(at, sig=SIG)


def _publish(s, items):
    return s.serve(VERIFIER, 'stl_publish', {'op': 'stl_publish', 'items': items})


def test_a_publish_files_each_kind_and_refuses_the_malformed():
    s = relay.RelayStore()
    ad_id, ad = _ad()
    at_id, at = _attestation(ad_id, 'vuln')
    r = _publish(s, [
        {'kind': 'ad', 'item': ad}, {'kind': 'attestation', 'item': at},
        {'kind': 'record', 'item': {'schema': '1', 'entry': {'evidence_digest': at_id},
                                    'checkpoint': {'epoch': 3, 'root': 'a' * 64}}},
        {'kind': 'anchor', 'item': PINNED},
        {'kind': 'sbom', 'item': {'digest': hashlib.sha256(b'{}').hexdigest(), 'text': '{}'}},
        {'kind': 'ad', 'item': {'owner': 'nobody'}},
        {'kind': 'sbom', 'item': {'digest': hashlib.sha256(b'{}').hexdigest(), 'text': '[]'}},
        {'kind': 'rumour', 'item': 'x'}])
    assert r['op'] == 'stl_published' and r['accepted'] == 5
    assert [x['reason'] for x in r['refused']] == ['malformed', 'malformed', 'unknown_kind']
    assert s.size() == 5
    assert _publish(s, [{'kind': 'ad', 'item': ad}])['accepted'] == 1
    assert s.size() == 5


def test_a_search_and_a_fetch_hand_back_the_claims_and_the_relays_word():
    s = relay.RelayStore()
    ad_id, ad = _ad()
    _at_id, at = _attestation(ad_id, 'vuln')
    _publish(s, [{'kind': 'ad', 'item': ad}, {'kind': 'attestation', 'item': at},
                 {'kind': 'anchor', 'item': PINNED}])
    r = s.serve(OWNER, 'stl_search', {'q': 'demos', 'rid': 'r1'})
    assert r['rid'] == 'r1' and len(r['results']) == 1
    hit = r['results'][0]
    assert hit['repo']['owner'] == OWNER
    assert hit['relay'] == {'findings': 1, 'clean': 0, 'verifiers': 1, 'anchor_issuer': ISSUER}
    assert s.serve(OWNER, 'stl_search', {'q': 'nothing-like-it'})['results'] == []
    b = s.serve(OWNER, 'stl_fetch', {'url': URL})['bundle']
    assert b['schema'] == 'stele-bundle-1'
    assert (len(b['ads']), len(b['attestations']), len(b['anchors'])) == (1, 1, 1)


def test_the_rate_and_the_unknown_are_refused():
    now = [1790000000]
    s = relay.RelayStore(rate=3, clock=lambda: now[0])
    for _ in range(3):
        assert s.serve(OWNER, 'stl_search', {'q': ''})['op'] == 'stl_results'
    assert s.serve(OWNER, 'stl_search', {'q': ''})['op'] == 'stl_limited'
    assert s.serve(VERIFIER, 'stl_search', {'q': ''})['op'] == 'stl_results'
    now[0] += 60
    assert s.serve(OWNER, 'stl_search', {'q': ''})['op'] == 'stl_results'
    assert s.serve(OWNER, 'stl_forget', {})['reason'] == 'unknown_op'
    assert relay.serve(None, OWNER, 'stl_search', {})['reason'] == 'not_stele_relay'


def test_an_anchor_is_replaced_only_by_a_higher_seq():
    s = relay.RelayStore()
    assert _publish(s, [{'kind': 'anchor', 'item': PINNED}])['accepted'] == 1
    assert _publish(s, [{'kind': 'anchor', 'item': PINNED}])['accepted'] == 1   # the same file
    import json
    from test_anchor import mint, MEMBERS, CKS
    older = mint(MEMBERS, CKS, seq=3)
    assert json.loads(json.loads(older)['body'])['seq'] == 3
    assert _publish(s, [{'kind': 'anchor', 'item': older}])['refused'][0]['reason'] == 'stale'
    assert _publish(s, [{'kind': 'anchor', 'item': mint(MEMBERS, CKS, seq=5)}])['accepted'] == 1
