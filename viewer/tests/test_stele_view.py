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
"""The standing a viewer's node folds, from records AutonomousTrust itself
archives (its _archive_attested and verify_attested_record) and the Stele
artifacts the node keeps."""
import json
import os
import queue
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
import stele_view  # noqa: E402

from autonomous_trust.core.config import Configuration  # noqa: E402
from autonomous_trust.core.identity import Identity  # noqa: E402
from autonomous_trust.core.processes import ProcessTracker  # noqa: E402
from autonomous_trust.core.reputation.repprocess import ReputationProcess  # noqa: E402
from autonomous_trust.core.reputation.reputation import (  # noqa: E402
    AttestedScore, Checkpoint)
from autonomous_trust.core.system import CfgIds  # noqa: E402
from autonomous_trust.stele import codec  # noqa: E402

DAY = 86400.0
URL = 'http://forge.local/alice/demo.git'
C1 = '1' * 40
C2 = '2' * 40


class Node:
    """An observer node's root: its reputation process archives attested
    records under etc/at/attested and writes its roster (the viewer's anchor)
    beside them, and its Stele store sits alongside. Two verifiers, both at
    tier 3 in the observer's view, and a shill at tier 1."""

    def __init__(self, root, monkeypatch):
        self.root = root
        monkeypatch.setattr(Configuration, 'get_cfg_dir',
                            staticmethod(lambda: str(root / 'etc' / 'at')))
        (root / 'etc' / 'at').mkdir(parents=True)
        self.owner = Identity.initialize('owner', 'owner', '10.0.9.1')
        self.ver = Identity.initialize('ver', 'ver', '10.0.9.2')
        self.obs = Identity.initialize('obs', 'obs', '10.0.9.3')
        self.ver2 = Identity.initialize('ver2', 'ver2', '10.0.9.4')
        self.shill = Identity.initialize('shill', 'shill', '10.0.9.5')
        procs = []
        for name in (CfgIds.network, CfgIds.identity, CfgIds.negotiation,
                     CfgIds.reputation):
            p = MagicMock()
            p.name = name
            procs.append(p)
        self.rp = ReputationProcess(
            {'processes': procs, CfgIds.identity: self.obs,
             CfgIds.peers: MagicMock(), CfgIds.group: MagicMock()},
            ProcessTracker(), queue.Queue(), suppress_log=True)
        self.rp.protocol.peers = SimpleNamespace(
            all=[self.owner, self.ver, self.ver2, self.shill])
        self.rp.peer_tiers.update({str(self.ver.uuid): 3, str(self.ver2.uuid): 3,
                                   str(self.shill.uuid): 1,
                                   str(self.owner.uuid): 2})
        self.epoch = 0

    def _store(self, kind, item_id, item):
        d = self.root / 'etc' / 'stele' / kind
        d.mkdir(parents=True, exist_ok=True)
        (d / (item_id + '.json')).write_text(json.dumps(item))

    def advertise(self, commit, seq, **v2):
        ad = {'owner': str(self.owner.uuid), 'name': 'demo', 'url': URL, 'ref': 'main',
              'commit': commit, 'seq': seq, 'ts': 1790000000 + seq}
        if v2:
            ad.update({'v': 2, 'description': '', 'topics': '', 'sbom_digest': '',
                       'sbom_path': '', 'claim_verdict': 'none'}, **v2)
        ad_id = codec.repo_ad_id(ad)
        self._store('ads', ad_id, dict(ad, sig='00' * 64))
        return ad_id, ad

    def attest(self, ad_id, ad, verdict, ts, scanner='osv-scanner', archive=True,
               by=None, digest=None, replicates=None):
        """A Stele attestation by ``by`` (default the first verifier), and the
        certified AT entry that names it, archived under a quorum-signed
        checkpoint. ``replicates`` makes it a replication of that id."""
        by = by or self.ver
        at = {'verifier': str(by.uuid), 'repo_ad_id': ad_id,
              'commit': ad['commit'], 'scanner': scanner, 'scanner_version': '1',
              'db_digest': 'cd' * 32,
              'findings_digest': digest or ('ef' * 32 if verdict == 'vuln'
                                            else '00' * 32),
              'verdict': verdict, 'count': 2 if verdict == 'vuln' else 0,
              'max_severity': '7.5' if verdict == 'vuln' else '', 'ts': int(ts),
              'v': 2, 'channel': 'probe',
              'scope': codec.scope(ad['owner'], ad['name'], ad['commit'], scanner)}
        if replicates:
            at.update(v=3, channel='replication', replicates=replicates)
        at_id = codec.attestation_id(at)
        self._store('attestations', at_id, dict(at, sig='00' * 64))
        if archive:
            att = AttestedScore(verifier_uuid=str(by.uuid),
                                subject_uuid=str(self.owner.uuid),
                                score=0.3 if verdict == 'vuln' else 0.8,
                                channel=at['channel'],
                                evidence_digest=at_id, attest_scope=at['scope'])
            sig = ReputationProcess._detached_sig
            assert self.rp.history.append_attested(
                att.to_transaction(),
                {str(by.uuid): sig(by, att.designation),
                 str(self.obs.uuid): sig(self.obs, att.designation),
                 str(self.ver2.uuid if by is not self.ver2 else self.ver.uuid):
                 sig(self.ver2 if by is not self.ver2 else self.ver,
                     att.designation)})
            window = self.rp.history._indexed_window()
            self.epoch += 1
            ck = Checkpoint(proposer_uuid=self.obs.uuid,
                            root=self.rp.history.window_root(), epoch=self.epoch,
                            first_index=window[0].index, count=len(window))
            self.rp._store_checkpoint(ck, {
                str(i.uuid): sig(i, ck.designation)
                for i in (self.obs, self.ver, self.ver2, self.owner)})
        return at_id

    def rebut(self, at_id, text):
        rb = {'owner': str(self.owner.uuid), 'attestation_id': at_id, 'text': text,
              'ts': 1790000300}
        self._store('rebuttals', codec.rebuttal_id(rb), dict(rb, sig='00' * 64))

    def view(self, **kw):
        return stele_view.NodeView(str(self.root), **kw)


@pytest.fixture
def node(tmp_path, monkeypatch):
    return Node(tmp_path / 'viewer', monkeypatch)


NOW = 1790000000.0


def test_a_confirmed_finding_is_failing_with_its_reason(node):
    ad_id, ad = node.advertise(C1, 1)
    first = node.attest(ad_id, ad, 'vuln', NOW)
    node.attest(ad_id, ad, 'vuln', NOW + 5, by=node.ver2, replicates=first)
    st = node.view().standing_by_url(URL, now=NOW + 365 * DAY)
    assert st['state'] == 'failing'
    assert st['score'] == pytest.approx(0.3)          # never fades
    check = st['checks'][0]
    assert check['state'] == 'confirmed-finding' and check['agreement'] == 2
    assert check['channel'] == 'probe'                # filed under the original
    assert 'osv-scanner on probe: vuln (2 findings, worst 7.5), 2 of 2' in \
        check['reason']
    assert check['linked']


def test_one_verifiers_finding_blocks_green_unconfirmed(node):
    ad_id, ad = node.advertise(C1, 1)
    node.attest(ad_id, ad, 'vuln', NOW)
    st = node.view().standing_by_url(URL, now=NOW)
    assert st['state'] == 'failing-unconfirmed'
    assert st['checks'][0]['agreement'] == 1


def test_one_clean_scan_is_single_source_and_two_are_safe(node):
    ad_id, ad = node.advertise(C1, 1)
    node.attest(ad_id, ad, 'clean', NOW)
    assert node.view().standing_by_url(URL, now=NOW + 60)['state'] == 'single-source'
    node.attest(ad_id, ad, 'clean', NOW + 30, by=node.ver2)
    v = node.view()
    assert v.standing_by_url(URL, now=NOW + 3600)['state'] == 'verified-safe'
    assert v.standing_by_url(URL, now=NOW + 1 + 31 * DAY)['state'] == 'aging'
    assert v.standing_by_url(URL, now=NOW + 1 + 180 * DAY)['state'] == 'unknown'
    assert node.view(replicas=3).standing_by_url(URL, now=NOW + 60)['state'] \
        == 'single-source'


def test_verifiers_that_disagree_dispute_the_check(node):
    ad_id, ad = node.advertise(C1, 1)
    node.attest(ad_id, ad, 'vuln', NOW)
    node.attest(ad_id, ad, 'clean', NOW + 5, by=node.ver2)
    st = node.view().standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'disputed'
    assert st['checks'][0]['state'] == 'disputed'


def test_findings_that_differ_in_detail_are_unconfirmed_not_disputed(node):
    ad_id, ad = node.advertise(C1, 1)
    node.attest(ad_id, ad, 'vuln', NOW)
    node.attest(ad_id, ad, 'vuln', NOW + 5, by=node.ver2, digest='ab' * 32)
    assert node.view().standing_by_url(URL, now=NOW + 60)['state'] == \
        'failing-unconfirmed'


def test_a_shill_below_the_tier_neither_disputes_nor_confirms(node):
    ad_id, ad = node.advertise(C1, 1)
    node.attest(ad_id, ad, 'vuln', NOW)
    node.attest(ad_id, ad, 'clean', NOW + 5, by=node.shill)
    st = node.view().standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'failing-unconfirmed'       # not disputed
    shill = [v for v in st['checks'][0]['verifiers']
             if v['verifier'] == str(node.shill.uuid)]
    assert shill and not shill[0]['counted']


def test_a_fresh_scan_of_a_newer_commit_answers_a_finding(node):
    ad_id, ad = node.advertise(C1, 1)
    node.attest(ad_id, ad, 'vuln', NOW)
    ad2_id, ad2 = node.advertise(C2, 2)
    st = node.view().standing_by_url(URL, now=NOW)
    assert st['state'] == 'unknown'                   # newest commit not scanned yet
    assert st['earlier_commits'][0]['verdict'] == 'vuln'
    node.attest(ad2_id, ad2, 'clean', NOW + 60)
    node.attest(ad2_id, ad2, 'clean', NOW + 61, by=node.ver2)
    st = node.view().standing_by_url(URL, now=NOW + 120)
    assert st['state'] == 'verified-safe'
    assert st['repo']['commit'] == C2


def test_only_a_verified_record_counts(node):
    ad_id, ad = node.advertise(C1, 1)
    node.attest(ad_id, ad, 'vuln', NOW, archive=False)   # held, never certified
    assert node.view().standing_by_url(URL, now=NOW)['state'] == 'unknown'
    node.attest(ad_id, ad, 'vuln', NOW, scanner='gitleaks')
    rec_path = next((node.root / 'etc' / 'at' / 'attested').glob('*.json'))
    rec = json.loads(rec_path.read_text())
    rec['entry']['p1_score'] = 0.8                     # tampered on disk
    rec_path.write_text(json.dumps(rec))
    v = node.view()
    assert v.unverified == 1
    assert v.standing_by_url(URL, now=NOW)['state'] == 'unknown'


def test_without_a_roster_nothing_verifies(node):
    ad_id, ad = node.advertise(C1, 1)
    node.attest(ad_id, ad, 'vuln', NOW)
    (node.root / 'etc' / 'at' / 'roster.cfg.json').unlink()
    v = node.view()
    st = v.standing_by_url(URL, now=NOW)
    assert st['state'] == 'unknown' and not st['anchored']
    assert 'no roster' in v.unverified_reasons[0]['reasons'][0]


def test_the_owners_rebuttal_is_shown_beside_the_finding(node):
    ad_id, ad = node.advertise(C1, 1)
    at_id = node.attest(ad_id, ad, 'vuln', NOW)
    node.rebut(at_id, 'the module is vendored and never built')
    st = node.view().standing_by_url(URL, now=NOW)
    assert st['state'] == 'failing-unconfirmed'       # shown, never scored
    assert st['checks'][0]['rebuttal'] == 'the module is vendored and never built'


def test_search_ranks_by_standing_then_match(node, monkeypatch):
    a_id, a = node.advertise(C1, 1, description='a web server', topics='go,http')
    node.attest(a_id, a, 'vuln', NOW)
    other = {'owner': str(uuid4()), 'name': 'httpkit', 'url': 'http://forge.local/b.git',
             'ref': 'main', 'commit': C2, 'seq': 1, 'ts': 1790000000}
    node._store('ads', codec.repo_ad_id(other), dict(other, sig='00' * 64))
    names = [r['repo']['name'] for r in node.view().search('http', now=NOW)]
    assert names == ['httpkit', 'demo']               # unknown above failing
    assert node.view().search('nothing-like-it', now=NOW) == []


def _bundle_of(root):
    """What an owner publishes as .stele/standing.json: records + artifacts."""
    def load(kind):
        return [json.loads(p.read_text())
                for p in sorted((root / 'etc' / kind[0] / kind[1]).glob('*.json'))]
    return {'schema': stele_view.BUNDLE_SCHEMA,
            'records': load(('at', 'attested')),
            'attestations': load(('stele', 'attestations')),
            'ads': load(('stele', 'ads'))}


def _fresh_viewer(tmp_path, node, name='viewer2'):
    """Another node of the same group: the same roster, nothing archived, no
    Stele artifacts of its own."""
    root = tmp_path / name
    (root / 'etc' / 'at').mkdir(parents=True)
    (root / 'etc' / 'at' / 'roster.cfg.json').write_text(
        (node.root / 'etc' / 'at' / 'roster.cfg.json').read_text())
    return root


def test_a_bundle_is_believed_only_through_the_anchor(node, tmp_path):
    ad_id, ad = node.advertise(C1, 1)
    first = node.attest(ad_id, ad, 'vuln', NOW)
    node.attest(ad_id, ad, 'vuln', NOW + 5, by=node.ver2, replicates=first)
    bundle = _bundle_of(node.root)
    v = stele_view.NodeView(str(_fresh_viewer(tmp_path, node)))
    assert v.standing_by_url(URL, now=NOW) is None    # never heard of it
    got = v.add_bundle(bundle)
    assert got['verified'] == 2 and got['unverified'] == []
    assert v.standing_by_url(URL, now=NOW + 60)['state'] == 'failing'


def test_a_forged_bundle_stays_unverified(node, tmp_path):
    """The owner serves its own 'clean' record: a key it made and a group of
    one. It verifies on its own, and not against the viewer's roster."""
    from autonomous_trust.core.reputation.reputation import verify_attested_record
    ad_id, ad = node.advertise(C1, 1)
    node.attest(ad_id, ad, 'vuln', NOW)
    with pytest.MonkeyPatch.context() as mp:
        forger = Node(tmp_path / 'forger', mp)
        forger.owner = node.owner                     # the same repo...
        f_ad_id, f_ad = forger.advertise(C1, 1)
        forger.attest(f_ad_id, f_ad, 'clean', NOW + 10)   # ...its own group's word
        forger.attest(f_ad_id, f_ad, 'clean', NOW + 11, by=forger.ver2)
        forged = _bundle_of(forger.root)
    for rec in forged['records']:
        assert verify_attested_record(rec)[0]         # fine on its own terms
    viewer = stele_view.NodeView(str(_fresh_viewer(tmp_path, node)))
    viewer.add_bundle(_bundle_of(node.root))
    got = viewer.add_bundle(forged)
    assert got['verified'] == 0 and len(got['unverified']) == 2
    st = viewer.standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'failing-unconfirmed'


def test_a_tampered_bundle_record_is_refused(node, tmp_path):
    ad_id, ad = node.advertise(C1, 1)
    node.attest(ad_id, ad, 'vuln', NOW)
    bundle = _bundle_of(node.root)
    bundle['records'][0]['entry']['p1_channel'] = 'first_person'
    viewer = stele_view.NodeView(str(_fresh_viewer(tmp_path, node)))
    assert viewer.add_bundle(bundle)['verified'] == 0
