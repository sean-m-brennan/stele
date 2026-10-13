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


def test_a_nodes_consent_verifies_under_its_own_key_and_matches_steles_message(tmp_path):
    """Phase 3: `consent` is the node's AT key signing exactly the message the
    team code (C stele_team.c, Python team.py, Ethne) verifies."""
    sk = nacl.signing.SigningKey.generate()
    uid = str(uuid4())
    (tmp_path / 'etc' / 'at').mkdir(parents=True)
    (tmp_path / 'etc' / 'at' / 'identity.cfg.json').write_text(json.dumps(
        {'uuid': uid, 'signature': {'hex_seed': bytes(sk).hex()}}))
    from autonomous_trust.stele import team
    issuer = 'ab' * 32
    out = stele_ctl.consent(str(tmp_path), issuer, 'did:key:zme')
    assert out['at_uuid'] == uid and out['did'] == 'did:key:zme'
    sk.verify_key.verify(team.consent_message(issuer, 'did:key:zme', uid),
                         bytes.fromhex(out['consent']))


# ---------------------------------------------------------------------------
# Phase 4: profiles, from the command line.
# ---------------------------------------------------------------------------

def _signed_profile(key, seq, **fields):
    viewer = os.path.join(os.path.dirname(__file__), '..', '..', 'viewer')
    sys.path.insert(0, os.path.normpath(viewer))
    import stele_profile
    p = stele_profile.parse(dict(fields, name=fields.get('name', 'acme')))
    body = json.dumps({'v': 1, 'typename': 'stele-profile', 'polity': 'did:key:zacme',
                       'issuer': bytes(key.verify_key).hex(), 'seq': seq, 'set_by': 'b',
                       'profile': {k: p[k] for k in stele_profile.FIELDS}},
                      separators=(',', ':'))
    return json.dumps({'body': body, 'sig': key.sign(b'stele-profile-v1|' + body.encode())
                       .signature.hex()})


def test_profile_commands_follow_show_use_and_unfollow(tmp_path, capsys):
    root = str(tmp_path)
    key = nacl.signing.SigningKey.generate()
    f = tmp_path / 'acme.profile'
    f.write_text(_signed_profile(key, 2, replicas=3))
    assert stele_ctl.main(['x', 'profile-follow', root, str(f)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out['following'] == bytes(key.verify_key).hex() and out['seq'] == 2
    assert stele_ctl.main(['x', 'profile-use', root, 'followed']) == 0
    assert json.loads(capsys.readouterr().out)['meta']['source'] == 'followed'
    assert stele_ctl.main(['x', 'profile-show', root]) == 0
    assert json.loads(capsys.readouterr().out)['profile']['replicas'] == 3
    # Another polity is refused without --replace, with exit 2.
    g = tmp_path / 'other.profile'
    g.write_text(_signed_profile(nacl.signing.SigningKey.generate(), 9))
    assert stele_ctl.main(['x', 'profile-follow', root, str(g)]) == 2
    assert 'already following' in capsys.readouterr().err
    assert stele_ctl.main(['x', 'profile-unfollow', root]) == 0
    capsys.readouterr()
    # The node still prefers `followed`, which no longer loads: every reading
    # command refuses with exit 2 rather than answer under another profile.
    assert stele_ctl.main(['x', 'standing', root, 'http://f/x.git']) == 2
    assert stele_ctl.main(['x', 'profile-use', root, 'stele-strict']) == 0
    capsys.readouterr()
    assert stele_ctl.main(['x', 'standing', root, 'http://f/x.git']) == 1
    assert stele_ctl.main(['x', 'search', root, 'x', '--profile', 'nope']) == 2


def test_the_bundle_command_attaches_a_signed_profile(tmp_path, capsys):
    key = nacl.signing.SigningKey.generate()
    f = tmp_path / 'p'
    f.write_text(_signed_profile(key, 1))
    assert stele_ctl.cmd_bundle(str(tmp_path), 'http://f/x.git', '--profile', str(f)) == 1
    assert json.loads(capsys.readouterr().out)['profile'] == f.read_text()


def test_a_bundle_carries_the_sbom_its_ad_pins(tmp_path, capsys):
    root = tmp_path
    sbom = tmp_path / 'sbom.cdx.json'
    sbom.write_bytes(b'{"bomFormat": "CycloneDX", "components": []}')
    assert stele_ctl.cmd_sbom_add(str(root), str(sbom)) == 0
    digest = json.loads(capsys.readouterr().out)['kept']
    ads = root / 'etc' / 'stele' / 'ads'
    ads.mkdir(parents=True)
    (ads / 'a1.json').write_text(json.dumps({'url': 'http://f/x.git',
                                             'sbom_digest': digest}))
    stele_ctl.cmd_bundle(str(root), 'http://f/x.git')
    b = json.loads(capsys.readouterr().out)
    assert b['sboms'] == {digest: sbom.read_text()}
    not_json = tmp_path / 'x.txt'
    not_json.write_text('not an sbom')
    assert stele_ctl.cmd_sbom_add(str(root), str(not_json)) == 1


def test_the_forge_serves_an_sbom_at_its_raw_path():
    ad = {'url': 'http://forge.local/alice/demo.git', 'commit': 'ab' * 20,
          'sbom_path': 'sbom.cdx.json'}
    assert stele_ctl.raw_sbom_url(ad) == \
        'http://forge.local/alice/demo/raw/commit/' + 'ab' * 20 + '/sbom.cdx.json'


def test_deps_pin_and_unpin(tmp_path, capsys):
    root = str(tmp_path)
    assert stele_ctl.cmd_deps_pin(root, 'pkg:golang/x.org/net@v1.0.0', 'http://f/a.git') == 0
    assert stele_ctl.cmd_deps_pin(root, 'pkg:golang/x.org/net', 'http://f/b.git') == 0
    assert stele_ctl._deps_module().load_map(root) == {
        'pkg:golang/x.org/net': ['http://f/a.git', 'http://f/b.git']}
    stele_ctl.cmd_deps_unpin(root, 'pkg:golang/x.org/net', 'http://f/a.git')
    assert stele_ctl._deps_module().load_map(root) == {
        'pkg:golang/x.org/net': ['http://f/b.git']}
    stele_ctl.cmd_deps_unpin(root, 'pkg:golang/x.org/net')
    assert stele_ctl._deps_module().load_map(root) == {}
    assert stele_ctl.cmd_deps_pin(root, 'left-pad', 'http://f/a.git') == 1


def test_anchor_consent_follow_and_only_a_newer_seq_replaces(tmp_path, capsys):
    import nacl.signing as ns
    from autonomous_trust.stele import anchor
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import stele_team
    sys.path.insert(0, os.path.dirname(__file__))
    from test_stele_team import _anchor_spec
    spec, path, uids = _anchor_spec(tmp_path)
    node = spec['members']['m0']
    issuer = bytes(stele_team.root_key(spec).verify_key).hex()
    got = stele_ctl.anchor_consent(node, issuer, 'g' * 8)
    ns.VerifyKey(bytes.fromhex(got['pubkey'])).verify(
        anchor.consent_message(issuer, 'g' * 8, got['at_uuid'], got['pubkey']),
        bytes.fromhex(got['consent']))

    viewer = str(tmp_path / 'viewer')
    out5 = str(tmp_path / 'a5')
    assert stele_team.main(['x', 'anchor', path, out5, '--builtin']) == 0
    assert stele_ctl.cmd_anchor_follow(viewer, out5) == 0
    assert stele_ctl.cmd_anchor_follow(viewer, out5) == 1          # not newer
    spec['anchor_seq'] = 6
    open(path, 'w').write(json.dumps(spec))
    out6 = str(tmp_path / 'a6')
    assert stele_team.main(['x', 'anchor', path, out6, '--builtin']) == 0
    assert stele_ctl.cmd_anchor_follow(viewer, out6) == 0
    capsys.readouterr()
    assert stele_ctl.cmd_anchor_show(viewer) == 0
    shown = json.loads(capsys.readouterr().out)['followed']
    assert [(s['issuer'], s['seq'], s['members']) for s in shown] == [(issuer, 6, 2)]
    stele_ctl.cmd_anchor_unfollow(viewer, issuer)
    capsys.readouterr()
    stele_ctl.cmd_anchor_show(viewer)
    assert json.loads(capsys.readouterr().out)['followed'] == []
    bad = str(tmp_path / 'bad')
    text = open(out6).read()
    assert '\\"tier\\":3' in text                  # the body is an escaped string
    open(bad, 'w').write(text.replace('\\"tier\\":3', '\\"tier\\":4', 1))
    assert stele_ctl.cmd_anchor_follow(viewer, bad) == 1


def test_a_relay_answer_is_filed_where_the_node_writes_it(tmp_path):
    import hashlib
    # The node's rid (stele_relay_net.c _rid_of): sha256("kind|query"), 16 hex.
    assert stele_ctl.relay_rid('search', 'demo lib') == \
        hashlib.sha256(b'search|demo lib').hexdigest()[:16]
    assert stele_ctl.relay_result_path(str(tmp_path), 'fetch', 'http://f/x.git').endswith(
        'etc/stele/relay/fetch-%s.json' % stele_ctl.relay_rid('fetch', 'http://f/x.git'))


def test_anchor_publish_keeps_the_polity_anchor_for_the_relays(tmp_path, capsys):
    sys.path.insert(0, os.path.dirname(__file__))
    from test_stele_team import _anchor_spec
    import stele_team
    spec, path, _uids = _anchor_spec(tmp_path)
    out = str(tmp_path / 'a')
    assert stele_team.main(['x', 'anchor', path, out, '--builtin']) == 0
    node = str(tmp_path / 'node')
    assert stele_ctl.cmd_anchor_publish(node, out) == 0
    issuer = bytes(stele_team.root_key(spec).verify_key).hex()
    kept = json.load(open(os.path.join(node, 'etc', 'stele', 'published-anchors',
                                       issuer + '.json')))
    assert kept['text'] == open(out).read().strip()
