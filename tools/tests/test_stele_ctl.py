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
"""stele_ctl's `verify` and osv summary, against a synthetic evidence document
built with AutonomousTrust's own writer (the C node writes the same schema)."""
import json
import os
import sys
from uuid import uuid4

import nacl.signing

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import stele_ctl  # noqa: E402

from autonomous_trust.core.reputation.reputation import (  # noqa: E402
    AttestedScore, Checkpoint, SignedCheckpoint, TransactionHistory,
    evidence_to_dict)


def _node():
    sk = nacl.signing.SigningKey.generate()
    return str(uuid4()), sk


def _sig(sk, msg):
    return sk.sign(msg).signature.hex()


def _doc(owner, ver, obs, cosign=True, subject_signs=False):
    h = TransactionHistory()
    t = uuid4()
    h.update(t, ver[0], 0.9)
    h.update(t, owner[0], 0.9)
    att = AttestedScore(verifier_uuid=ver[0], subject_uuid=owner[0], score=0.3,
                        evidence_digest='ab' * 32)
    cert = {ver[0]: _sig(ver[1], att.designation)}
    if cosign:
        cert[obs[0]] = _sig(obs[1], att.designation)
    if subject_signs:
        cert[owner[0]] = _sig(owner[1], att.designation)
    assert h.append_attested(att.to_transaction(), cert)
    root = TransactionHistory._mth([x.entry_hash() for x in h])
    ck = Checkpoint(proposer_uuid=obs[0], root=root, epoch=1, first_index=0,
                    count=len(h))
    sigs = {n[0]: _sig(n[1], ck.designation) for n in (ver, obs)}
    return evidence_to_dict(h, SignedCheckpoint(checkpoint=ck, sigs=sigs),
                            h.attest_certs)


def _keys(*nodes):
    return {n[0]: n[1].verify_key.encode().hex() for n in nodes}


def test_a_certified_attestation_verifies():
    owner, ver, obs = _node(), _node(), _node()
    r = stele_ctl.verify(_doc(owner, ver, obs), owner[0], _keys(owner, ver, obs))
    assert r['ok'], r
    assert r['attested'][0]['score'] == 0.3


def test_the_subjects_signature_does_not_certify():
    owner, ver, obs = _node(), _node(), _node()
    r = stele_ctl.verify(_doc(owner, ver, obs, cosign=False, subject_signs=True),
                         owner[0], _keys(owner, ver, obs))
    assert not r['ok'] and not r['attested'][0]['certified']


def test_a_tampered_chain_fails():
    owner, ver, obs = _node(), _node(), _node()
    doc = _doc(owner, ver, obs)
    doc['chain'][0]['p1_score'] = 0.1
    assert not stele_ctl.verify(doc, owner[0], _keys(owner, ver, obs))['ok']


def test_osv_summary_uses_the_alias_merged_groups():
    report = {'results': [{'packages': [{
        'groups': [{'ids': ['GO-1', 'GHSA-1'], 'max_severity': '5.3'},
                   {'ids': ['GO-2'], 'max_severity': '7.5'}],
        'vulnerabilities': [{'id': 'GO-1'}, {'id': 'GHSA-1'}, {'id': 'GO-2'}]}]}]}
    assert stele_ctl.summarize_osv(report)[:3] == ('vuln', 2, '7.5')


def test_osv_summary():
    clean = stele_ctl.summarize_osv({'results': []})
    assert clean[:3] == ('clean', 0, '')
    report = {'results': [{'packages': [{'vulnerabilities': [
        {'id': 'GHSA-1', 'database_specific': {'severity': 'MODERATE'}},
        {'id': 'GO-2', 'database_specific': {'severity': 'HIGH'}}]}]}]}
    v = stele_ctl.summarize_osv(report)
    assert v[:3] == ('vuln', 2, 'HIGH') and len(v[3]) == 64


FIXTURE = os.path.normpath(os.path.join(
    os.path.dirname(__file__), '..', '..', '..', '..', 'lib', 'autonomous_trust', 'src',
    'autonomous-trust', 'tests', 'a_unit', 'fixtures', 'attested_record_from_c.json'))


ROSTER = os.path.join(os.path.dirname(FIXTURE), 'roster_from_c.json')


def _archived(tmp_path, record, roster=True):
    """A node root holding `record`, and the C node's roster beside it."""
    adir = tmp_path / 'etc' / 'at' / 'attested'
    adir.mkdir(parents=True, exist_ok=True)
    (adir / 'task.json').write_text(json.dumps(record))
    if roster:
        with open(ROSTER) as f:
            (tmp_path / 'etc' / 'at' / 'roster.cfg.json').write_text(f.read())
    return str(tmp_path)


def test_an_archived_record_written_by_a_c_node_verifies_without_keys(tmp_path):
    with open(FIXTURE) as f:
        record = json.load(f)
    subject = record['entry']['subject_id']
    r = stele_ctl.verify_records(_archived(tmp_path, record), subject)
    assert r['ok'] and r['records'][0]['verified']
    assert r['records'][0]['channel'] == 'probe'
    assert not stele_ctl.verify_records(str(tmp_path), str(uuid4()))['ok']


def test_a_tampered_archived_record_does_not_verify(tmp_path):
    with open(FIXTURE) as f:
        record = json.load(f)
    record['entry']['p1_score'] = 0.8
    r = stele_ctl.verify_records(_archived(tmp_path, record),
                                 record['entry']['subject_id'])
    assert not r['ok'] and r['unverified'] == 1 and r['records'][0]['reasons']


def test_standing_of_an_unheard_repository_is_unknown(tmp_path, capsys):
    assert stele_ctl.cmd_standing(str(tmp_path), 'http://f/a/b.git') == 1
    assert json.loads(capsys.readouterr().out) == {'state': 'unknown', 'heard': False}
    assert stele_ctl.cmd_search(str(tmp_path), 'b') == 0


def test_without_the_roster_nothing_verifies(tmp_path):
    with open(FIXTURE) as f:
        record = json.load(f)
    r = stele_ctl.verify_records(_archived(tmp_path, record, roster=False),
                                 record['entry']['subject_id'])
    assert not r['ok'] and not r['anchored']
    assert 'no roster' in r['records'][0]['reasons'][0]


def test_a_bundle_verifies_against_the_viewers_roster_only(tmp_path):
    """Handed over in a bundle, the C node's record verifies at a viewer holding
    the same roster; a viewer of another group refuses it."""
    with open(FIXTURE) as f:
        record = json.load(f)
    subject = record['entry']['subject_id']
    viewer = tmp_path / 'viewer'
    (viewer / 'etc' / 'at').mkdir(parents=True)
    with open(ROSTER) as f:
        roster = json.load(f)
    (viewer / 'etc' / 'at' / 'roster.cfg.json').write_text(json.dumps(roster))
    r = stele_ctl.verify_records(str(viewer), subject, {'records': [record]})
    assert r['ok'] and r['records'][0]['source'] == 'bundle'
    roster['members'] = {str(uuid4()): m for m in roster['members'].values()}
    (viewer / 'etc' / 'at' / 'roster.cfg.json').write_text(json.dumps(roster))
    assert not stele_ctl.verify_records(str(viewer), subject,
                                        {'records': [record]})['ok']


def test_the_bundle_command_exports_what_the_node_holds(tmp_path, capsys):
    root = tmp_path
    ads = root / 'etc' / 'stele' / 'ads'
    ats = root / 'etc' / 'stele' / 'attestations'
    ads.mkdir(parents=True)
    ats.mkdir(parents=True)
    (ads / 'a1.json').write_text(json.dumps({'url': 'http://f/x.git'}))
    (ads / 'a2.json').write_text(json.dumps({'url': 'http://f/other.git'}))
    (ats / 't1.json').write_text(json.dumps({'repo_ad_id': 'a1'}))
    (ats / 't2.json').write_text(json.dumps({'repo_ad_id': 'a2'}))
    adir = root / 'etc' / 'at' / 'attested'
    adir.mkdir(parents=True)
    (adir / 'r1.json').write_text(json.dumps({'entry': {'evidence_digest': 't1'}}))
    (adir / 'r2.json').write_text(json.dumps({'entry': {'evidence_digest': 't2'}}))
    assert stele_ctl.cmd_bundle(str(root), 'http://f/x.git') == 0
    b = json.loads(capsys.readouterr().out)
    assert b['schema'] == 'stele-bundle-1'
    assert [r['entry']['evidence_digest'] for r in b['records']] == ['t1']
    assert b['attestations'] == [{'repo_ad_id': 'a1'}]
    assert b['ads'] == [{'url': 'http://f/x.git'}]
