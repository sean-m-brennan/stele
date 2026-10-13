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

    def advertise(self, commit, seq, name='demo', url=URL, ref='main', **v2):
        ad = {'owner': str(self.owner.uuid), 'name': name, 'url': url, 'ref': ref,
              'commit': commit, 'seq': seq, 'ts': 1790000000 + seq}
        if v2:
            ad.update({'v': 2, 'description': '', 'topics': '', 'sbom_digest': '',
                       'sbom_path': '', 'claim_verdict': 'none'}, **v2)
        if 'provides' in v2:   # a v4 ad, solo
            ad.update(v=4, polity='', release_auth='')
        ad_id = codec.repo_ad_id(ad)
        self._store('ads', ad_id, dict(ad, sig='00' * 64))
        return ad_id, ad

    def attest(self, ad_id, ad, verdict, ts, scanner='osv-scanner', archive=True,
               by=None, digest=None, replicates=None, severity=None,
               channel='probe'):
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
              'max_severity': (severity if severity is not None else '7.5')
              if verdict == 'vuln' else '', 'ts': int(ts),
              'v': 2, 'channel': channel,
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
    assert 'osv-scanner on probe: vuln (2 findings, worst 7.5), 2 verifiers agree (2 needed)' in \
        check['reason']
    assert check['linked']


def test_one_verifiers_finding_blocks_green_unconfirmed(node):
    ad_id, ad = node.advertise(C1, 1)
    node.attest(ad_id, ad, 'vuln', NOW)
    st = node.view().standing_by_url(URL, now=NOW)
    assert st['state'] == 'failing-unconfirmed'
    assert st['checks'][0]['agreement'] == 1
    assert '1 verifier agrees (2 needed)' in st['checks'][0]['reason']


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


# ---------------------------------------------------------------------------
# Teams (Phase 3)
# ---------------------------------------------------------------------------

import nacl.signing  # noqa: E402
from autonomous_trust.stele import team as stele_team  # noqa: E402

ROOT_KEY = nacl.signing.SigningKey(bytes([7]) * 32)
ISSUER = bytes(ROOT_KEY.verify_key).hex()


def _pub(ident):
    return bytes(ident.signature.public).hex()


def _signed(domain, body, key):
    text = json.dumps(body, separators=(',', ':'))
    return json.dumps({'body': text, 'sig': key.sign(domain + text.encode()).signature.hex()})


def _roster(node, members, officers=('owner',), guardians=(), seq=1, consent_by=None):
    """A team roster over the node's identities, by attribute name."""
    consent_by = consent_by or {}
    listed = []
    for name in members:
        me = getattr(node, name)
        signer = getattr(node, consent_by.get(name, name))
        msg = stele_team.consent_message(ISSUER, 'did:key:z' + name, str(me.uuid))
        listed.append({'did': 'did:key:z' + name, 'key': _pub(me), 'at_uuid': str(me.uuid),
                       'consent': signer.signature.private.sign(msg).signature.hex()})
    body = {'v': 1, 'typename': 'stele-team', 'polity': 'did:key:zteam', 'issuer': ISSUER,
            'seq': seq, 'members': listed,
            'release_officers': ['did:key:z' + o for o in officers],
            'guardians': [{'machine': 'did:key:z' + m, 'guardian': 'did:key:z' + g}
                          for m, g in guardians]}
    return _signed(stele_team.TEAM_DOMAIN, body, ROOT_KEY)


def _hold_roster(node, text):
    node._store('teams', ISSUER, {'roster': text})


def _team_ad(node, commit, seq, name='demo', url=URL, signer='owner', built_by=None):
    """A v3 ad by the owner, its release signed by ``signer``."""
    who = getattr(node, signer)
    body = {'v': 1, 'typename': 'stele-release', 'polity': 'did:key:zteam',
            'issuer': ISSUER, 'officer': 'did:key:z' + signer, 'officer_key': _pub(who),
            'repo': name, 'url': url, 'commit': commit}
    if built_by:
        body['built_by'] = 'did:key:z' + built_by
    body['authorized_at'] = 1790000000
    ad = {'owner': str(node.owner.uuid), 'name': name, 'url': url, 'ref': 'main',
          'commit': commit, 'seq': seq, 'ts': 1790000000 + seq, 'v': 3,
          'description': '', 'topics': '', 'sbom_digest': '', 'sbom_path': '',
          'claim_verdict': 'none', 'polity': ISSUER,
          'release_auth': _signed(stele_team.RELEASE_DOMAIN, body, who.signature.private)}
    ad_id = codec.repo_ad_id(ad)
    node._store('ads', ad_id, dict(ad, sig='00' * 64))
    return ad_id, ad


def test_a_team_release_is_the_teams_and_its_finding_fails_the_team(node):
    _hold_roster(node, _roster(node, ['owner', 'shill']))
    ad_id, ad = _team_ad(node, C1, 1)
    first = node.attest(ad_id, ad, 'vuln', NOW)
    node.attest(ad_id, ad, 'vuln', NOW + 5, by=node.ver2, replicates=first)
    view = node.view()
    st = view.standing_by_url(URL, now=NOW + DAY)
    assert st['state'] == 'failing'
    assert st['team']['polity'] == ISSUER and st['team']['officer'] == 'did:key:zowner'
    assert st['team']['state'] == 'failing'
    ts = view.team_standing(ISSUER, now=NOW + DAY)
    assert ts['state'] == 'failing'
    assert [r['repo']['name'] for r in ts['repos']] == ['demo']
    assert ts['concerns'] and ts['concerns'][0]['verdict'] == 'vuln'


def test_the_team_is_the_worst_of_its_repositories(node):
    """User decision 2026-10-07: worst-of. A verified-safe repository does not
    lift the team above a failing one."""
    _hold_roster(node, _roster(node, ['owner', 'shill']))
    a_id, a = _team_ad(node, C1, 1, name='good', url=URL + '-good')
    for by in (node.ver, node.ver2):
        node.attest(a_id, a, 'clean', NOW, by=by)
    b_id, b = _team_ad(node, C2, 2, name='bad', url=URL + '-bad')
    first = node.attest(b_id, b, 'vuln', NOW)
    node.attest(b_id, b, 'vuln', NOW + 5, by=node.ver2, replicates=first)
    view = node.view()
    states = {r['repo']['name']: r['state'] for r in view.team_standing(ISSUER, NOW + DAY)['repos']}
    assert states == {'good': 'verified-safe', 'bad': 'failing'}
    assert view.team_standing(ISSUER, NOW + DAY)['state'] == 'failing'
    assert stele_view.worst_state(['verified-safe', 'single-source', 'aging']) == 'single-source'


def test_a_roster_claiming_an_unconsenting_node_is_not_held(node):
    """The root cannot list an outsider: the auditor (ver) never consented, so
    the roster is refused and ver's signatures keep counting."""
    _hold_roster(node, _roster(node, ['owner', 'ver'], consent_by={'ver': 'owner'}))
    ad_id, ad = _team_ad(node, C1, 1)
    first = node.attest(ad_id, ad, 'vuln', NOW)
    node.attest(ad_id, ad, 'vuln', NOW + 5, by=node.ver2, replicates=first)
    view = node.view()
    assert view.teams == {}
    st = view.standing_by_url(URL, now=NOW + DAY)
    assert st['state'] == 'failing' and 'team' not in st
    assert view.team_standing(ISSUER) is None


def test_a_release_not_signed_by_an_officer_is_not_the_teams(node):
    _hold_roster(node, _roster(node, ['owner', 'shill']))
    ad_id, ad = _team_ad(node, C1, 1, signer='shill')
    node.attest(ad_id, ad, 'clean', NOW)
    view = node.view()
    assert ISSUER in view.teams, 'the roster itself is held'
    assert 'team' not in view.standing_by_url(URL, now=NOW)


def test_teammates_do_not_certify_about_their_team(node):
    """AT ISSUES §2.54, re-checked by the viewer from its own roster: with obs
    and ver2 on the owner's team, a record signed by ver, obs and ver2 carries
    one outsider, and does not verify."""
    _hold_roster(node, _roster(node, ['owner', 'obs', 'ver2']))
    ad_id, ad = _team_ad(node, C1, 1)
    node.attest(ad_id, ad, 'vuln', NOW)
    view = node.view()
    assert view.verified == {}
    assert any('attestation short of a quorum' in r['reasons']
               for r in view.unverified_reasons)


def test_a_guardian_finding_is_a_concern_of_the_team(node):
    """A v4 attestation lands the finding on the builder's guardian (shill
    guards the machine ver2... here a listed member named by its DID)."""
    _hold_roster(node, _roster(node, ['owner', 'shill', 'obs'],
                               guardians=[('obs', 'shill')]))
    ad_id, ad = _team_ad(node, C1, 1, built_by='obs')
    first = node.attest(ad_id, ad, 'vuln', NOW)
    view = node.view()
    attr = view.attributions[ad_id]
    assert attr['guardian'] == 'did:key:zshill' and attr['guardian_uuid'] == str(node.shill.uuid)
    # The guardian attestation and its certified entry about the guardian.
    orig = view.attestations[first]
    at = {k: orig[k] for k in codec.ATTEST_KEYS}
    at.update(verifier=str(node.ver.uuid), ts=int(NOW) + 9, v=4, channel='probe',
              scope=codec.scope(str(node.shill.uuid), 'demo', C1, 'osv-scanner'),
              attributes=first, guardian_of='did:key:zobs')
    at_id = codec.attestation_id(at)
    node._store('attestations', at_id, dict(at, sig='00' * 64))
    att = AttestedScore(verifier_uuid=str(node.ver.uuid), subject_uuid=str(node.shill.uuid),
                        score=0.45, channel='probe', evidence_digest=at_id,
                        attest_scope=at['scope'])
    sig = ReputationProcess._detached_sig
    assert node.rp.history.append_attested(att.to_transaction(), {
        str(i.uuid): sig(i, att.designation) for i in (node.ver, node.ver2, node.owner)})
    window = node.rp.history._indexed_window()
    node.epoch += 1
    ck = Checkpoint(proposer_uuid=node.obs.uuid, root=node.rp.history.window_root(),
                    epoch=node.epoch, first_index=window[0].index, count=len(window))
    node.rp._store_checkpoint(ck, {str(i.uuid): sig(i, ck.designation)
                                   for i in (node.obs, node.ver, node.ver2, node.owner)})
    view = node.view()
    assert at_id in view.verified
    ts = view.team_standing(ISSUER, now=NOW + DAY)
    assert any(c['channel'] == 'guardian' and 'did:key:zshill' in c['reason']
               for c in ts['concerns'])
    # Not part of the repository's own checks: the repo's fold is the owner's.
    st = view.standing_by_url(URL, now=NOW + DAY)
    assert all(c['attestation_id'] != at_id for c in st['checks'])


def test_teams_are_discovered_separately_from_repositories(node):
    _hold_roster(node, _roster(node, ['owner', 'shill']))
    ad_id, ad = _team_ad(node, C1, 1)
    node.attest(ad_id, ad, 'clean', NOW)   # the node's roster is written then
    view = node.view()
    assert [t['team']['issuer'] for t in view.search_teams('team')] == [ISSUER]
    assert [t['team']['issuer'] for t in view.search_teams('demo')] == [ISSUER]
    assert view.search_teams('nothing-like-it') == []
    assert all('team' not in r or 'repo' in r for r in view.search('demo'))


def test_a_shorter_roster_does_not_make_a_former_teammate_an_outsider(node):
    """The node's history (etc/stele/conflicts.json) keeps every node a team
    ever listed. Here obs and ver2 were the owner's teammates and the newest
    roster drops them: their signatures still do not count (host run
    tm-1965582, where the shrink re-judged two-signature certificates)."""
    _hold_roster(node, _roster(node, ['owner'], seq=2))
    (node.root / 'etc' / 'stele' / 'conflicts.json').write_text(json.dumps(
        {ISSUER: [str(node.owner.uuid), str(node.obs.uuid), str(node.ver2.uuid)]}))
    ad_id, ad = _team_ad(node, C1, 1)
    node.attest(ad_id, ad, 'vuln', NOW)        # signed by ver, obs and ver2
    view = node.view()
    assert view.teammates(str(node.owner.uuid)) == {str(node.obs.uuid), str(node.ver2.uuid)}
    assert view.verified == {}


# ---------------------------------------------------------------------------
# Phase 4: profiles. The same facts, read under another reading
# (stele_profile.py; CODE_SHARING_PLAN §9 Q4, Ethne D42).
# ---------------------------------------------------------------------------

import stele_profile  # noqa: E402

PROFILE_KEY = nacl.signing.SigningKey(bytes([9]) * 32)


def _local(node, name, **fields):
    """The node operator's own profile, ``etc/stele/profiles/<name>.json``."""
    node._store('profiles', name, dict(fields, name=name))


def _signed_profile(seq, key=PROFILE_KEY, **fields):
    """A polity's signed profile file, in Ethne's border format (#11)."""
    p = stele_profile.parse(dict(fields, name=fields.get('name', 'acme')))
    body = {'v': 1, 'typename': 'stele-profile', 'polity': 'did:key:zacme',
            'issuer': bytes(key.verify_key).hex(), 'seq': seq, 'set_by': 'bafy',
            'profile': {k: p[k] for k in stele_profile.FIELDS}}
    return _signed(stele_profile.PROFILE_DOMAIN, body, key)


def _two_clean(node, ad_id, ad, scanner='osv-scanner', ts=NOW):
    for by in (node.ver, node.ver2):
        node.attest(ad_id, ad, 'clean', ts, scanner=scanner, by=by)


def _confirmed_finding(node, ad_id, ad, severity, scanner='osv-scanner'):
    first = node.attest(ad_id, ad, 'vuln', NOW, scanner=scanner, severity=severity)
    node.attest(ad_id, ad, 'vuln', NOW + 5, scanner=scanner, by=node.ver2,
                replicates=first, severity=severity)


def test_every_answer_names_the_default_profile_and_counts_every_check(node):
    ad_id, ad = node.advertise(C1, 1)
    _two_clean(node, ad_id, ad)
    st = node.view().standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'verified-safe'
    assert st['profile'] == {'name': 'stele-default', 'source': 'builtin'}
    assert [(c['counted'], c['set_aside']) for c in st['checks']] == [(True, None)]
    assert 'missing_required' not in st and 'capped_by_team' not in st


def test_strict_needs_its_required_checks_present(node):
    ad_id, ad = node.advertise(C1, 1)
    _two_clean(node, ad_id, ad)
    st = node.view(profile='stele-strict').standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'unknown' and st['score'] is None
    assert st['missing_required'] == ['gitleaks:probe', 'license:probe']
    assert st['profile']['name'] == 'stele-strict' and st['replicas'] == 3


def test_a_local_profile_may_take_one_verifier(node):
    ad_id, ad = node.advertise(C1, 1)
    node.attest(ad_id, ad, 'clean', NOW)
    assert node.view().standing_by_url(URL, now=NOW + 60)['state'] == 'single-source'
    _local(node, 'internal', replicas=1)
    st = node.view(profile='internal').standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'verified-safe'
    assert st['profile'] == {'name': 'internal', 'source': 'local'}


def test_a_finding_below_the_severity_floor_is_set_aside_and_shown(node):
    ad_id, ad = node.advertise(C1, 1)
    _confirmed_finding(node, ad_id, ad, '5.0')
    _two_clean(node, ad_id, ad, scanner='gitleaks')
    assert node.view().standing_by_url(URL, now=NOW + 60)['state'] == 'failing'
    _local(node, 'tolerant', severity_floor='high')
    st = node.view(profile='tolerant').standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'verified-safe'
    osv = next(c for c in st['checks'] if c['scanner'] == 'osv-scanner')
    assert osv['state'] == 'confirmed-finding' and not osv['counted']
    assert osv['set_aside'] == 'below the high severity floor of tolerant'


def test_a_critical_or_unrated_finding_counts_under_every_floor(node):
    ad_id, ad = node.advertise(C1, 1)
    _confirmed_finding(node, ad_id, ad, '9.8')
    _local(node, 'tolerant', severity_floor='high')
    assert node.view(profile='tolerant').standing_by_url(URL, now=NOW + 60)['state'] \
        == 'failing'
    ad2, a2 = node.advertise(C2, 2)
    node.attest(ad2, a2, 'vuln', NOW, scanner='gitleaks', severity='SECRET')
    assert node.view(profile='tolerant').standing_by_url(URL, now=NOW + 60)['state'] \
        == 'failing-unconfirmed'


def test_ignoring_a_scanner_never_sets_aside_its_critical_finding(node):
    ad_id, ad = node.advertise(C1, 1)
    _confirmed_finding(node, ad_id, ad, 'CRITICAL', scanner='semgrep')
    _two_clean(node, ad_id, ad)
    _local(node, 'no-semgrep', ignore=['semgrep:probe'])
    st = node.view(profile='no-semgrep').standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'failing'
    sg = next(c for c in st['checks'] if c['scanner'] == 'semgrep')
    assert sg['counted'] and sg['set_aside'] is None


def test_an_ignored_check_is_shown_and_ignoring_everything_is_unknown(node):
    ad_id, ad = node.advertise(C1, 1)
    _confirmed_finding(node, ad_id, ad, '7.5', scanner='semgrep')
    _two_clean(node, ad_id, ad)
    _local(node, 'no-semgrep', ignore=['semgrep:probe'])
    st = node.view(profile='no-semgrep').standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'verified-safe'
    sg = next(c for c in st['checks'] if c['scanner'] == 'semgrep')
    assert sg['set_aside'] == 'ignored by no-semgrep' and sg['verdict'] == 'vuln'
    _local(node, 'nothing', ignore=['semgrep:probe', 'osv-scanner:probe'])
    st = node.view(profile='nothing').standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'unknown' and len(st['checks']) == 2
    assert 'earlier_commits' not in st


def test_a_profile_sets_how_fast_a_clean_reading_fades(node):
    ad_id, ad = node.advertise(C1, 1)
    _two_clean(node, ad_id, ad)
    later = NOW + 3 * DAY
    assert node.view().standing_by_url(URL, now=later)['state'] == 'verified-safe'
    _local(node, 'fresh', onset_days=0, half_life_days=1)
    st = node.view(profile='fresh').standing_by_url(URL, now=later)
    assert st['state'] == 'unknown' and st['score'] < 0.3


def test_a_profile_may_hold_a_repository_to_its_team(node):
    _hold_roster(node, _roster(node, ['owner', 'shill']))
    a_id, a = _team_ad(node, C1, 1, name='good', url=URL + '-good')
    _two_clean(node, a_id, a)
    b_id, b = _team_ad(node, C2, 2, name='bad', url=URL + '-bad')
    _confirmed_finding(node, b_id, b, '7.5')
    shown = node.view().standing_by_url(URL + '-good', now=NOW + 60)
    assert shown['state'] == 'verified-safe' and shown['team']['state'] == 'failing'
    capped = node.view(profile='stele-strict', replicas=2).standing_by_url(
        URL + '-good', now=NOW + 60)
    # strict's required checks are absent anyway; the team still caps it.
    assert capped['state'] == 'failing' and capped['capped_by_team']
    _local(node, 'team-bound', team='worst')
    capped = node.view(profile='team-bound').standing_by_url(URL + '-good', now=NOW + 60)
    assert capped['state'] == 'failing' and capped['capped_by_team']
    ts = node.view(profile='team-bound').team_standing(ISSUER, NOW + 60)
    assert ts['profile']['name'] == 'team-bound'


def test_the_operators_override_is_inside_the_floors_and_named(node):
    ad_id, ad = node.advertise(C1, 1)
    node.attest(ad_id, ad, 'clean', NOW)
    st = node.view(replicas=1).standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'verified-safe'
    assert st['profile']['overrides'] == {'replicas': 1}
    with pytest.raises(stele_profile.ProfileError):
        node.view(replicas=0)


def test_a_profile_outside_the_floors_is_refused_not_clamped(node):
    for bad in ({'replicas': 0}, {'tier': 5}, {'severity_floor': 'critical'},
                {'half_life_days': 0}, {'onset_days': 31}, {'surprise': 1},
                {'require': ['osv-scanner:probe'], 'ignore': ['osv-scanner:probe']}):
        _local(node, 'bad', **bad)
        with pytest.raises(stele_profile.ProfileError):
            node.view(profile='bad')
    with pytest.raises(stele_profile.ProfileError):
        node.view(profile='missing')
    with pytest.raises(stele_profile.ProfileError):
        node.view(profile='followed')


def test_a_followed_profile_is_read_and_a_bundle_may_bring_its_newer_seq(node):
    ad_id, ad = node.advertise(C1, 1)
    node.attest(ad_id, ad, 'clean', NOW)
    stele_profile.follow(str(node.root), _signed_profile(1, replicas=2))
    stele_profile.use(str(node.root), 'followed')
    v = node.view()
    st = v.standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'single-source'
    assert st['profile']['source'] == 'followed' and st['profile']['seq'] == 1
    assert st['profile']['issuer'] == bytes(PROFILE_KEY.verify_key).hex()
    # A newer profile from the followed polity, in a bundle: taken for this
    # answer only. One from another key is ignored.
    other = nacl.signing.SigningKey(bytes([10]) * 32)
    v = node.view()
    v.add_bundle({'profile': _signed_profile(5, key=other, replicas=1)})
    assert v.standing_by_url(URL, now=NOW + 60)['state'] == 'single-source'
    v.add_bundle({'profile': _signed_profile(2, replicas=1)})
    st = v.standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'verified-safe'
    assert st['profile']['seq'] == 2 and st['profile']['via'] == 'bundle'
    assert node.view().standing_by_url(URL, now=NOW + 60)['profile']['seq'] == 1
