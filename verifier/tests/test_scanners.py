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
"""The verifier's scanner battery, from fixture reports (the tools themselves
are host-only), and the hook's flow with the tools and the attest verb
stubbed."""
import hashlib
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
import scanners  # noqa: E402
import stele_hook  # noqa: E402

PURL_NET = 'pkg:golang/golang.org/x/net@v0.1.0'
PURL_TEXT = 'pkg:golang/golang.org/x/text@v0.3.7'


def _sbom(*purls, licenses=None):
    comps = [{'type': 'library', 'name': p.split('/')[-1], 'purl': p} for p in purls]
    for c, lic in zip(comps, licenses or []):
        c['licenses'] = [{'license': {'id': lic}}]
    return {'bomFormat': 'CycloneDX', 'components': comps}


def test_gitleaks_counts_each_secret():
    assert scanners.summarize_gitleaks([])[:3] == ('clean', 0, '')
    v = scanners.summarize_gitleaks([{'RuleID': 'aws-access-key'}, {'RuleID': 'jwt'}])
    assert v[:3] == ('vuln', 2, 'SECRET')
    assert len(v[3]) == 64


def test_semgrep_reports_the_worst_severity():
    report = {'results': [{'extra': {'severity': 'INFO'}},
                          {'extra': {'severity': 'WARNING'}}]}
    assert scanners.summarize_semgrep(report)[:3] == ('vuln', 2, 'WARNING')
    assert scanners.summarize_semgrep({'results': []})[:3] == ('clean', 0, '')


def test_the_license_policy_is_the_verifiers():
    own = _sbom(PURL_NET, PURL_TEXT, licenses=['BSD-3-Clause', 'AGPL-3.0-only'])
    report = scanners.check_licenses(own, scanners.DEFAULT_LICENSE_DENY)
    assert scanners.summarize_license(report)[:2] == ('vuln', 1)
    assert scanners.summarize_license(scanners.check_licenses(own, ['GPL-2.0-only']))[0] \
        == 'clean'


def _write(tmp_path, rel, data):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_an_sbom_that_matches_its_claim_and_lists_everything_is_clean(tmp_path):
    digest = _write(tmp_path, 'sbom.cdx.json', _sbom(PURL_NET, PURL_TEXT))
    report = scanners.check_sbom(str(tmp_path), 'sbom.cdx.json', digest,
                                 _sbom(PURL_NET, PURL_TEXT))
    assert scanners.summarize_sbom(report)[:2] == ('clean', 0)


def test_an_sbom_that_omits_a_component_or_misses_its_digest_is_a_finding(tmp_path):
    digest = _write(tmp_path, 'sbom.cdx.json', _sbom(PURL_TEXT))
    incomplete = scanners.check_sbom(str(tmp_path), 'sbom.cdx.json', digest,
                                     _sbom(PURL_NET, PURL_TEXT))
    assert incomplete['missing'] == [PURL_NET]
    assert scanners.summarize_sbom(incomplete)[:3] == ('vuln', 1, 'INCOMPLETE')
    wrong = scanners.check_sbom(str(tmp_path), 'sbom.cdx.json', 'ab' * 32,
                                _sbom(PURL_TEXT))
    assert scanners.summarize_sbom(wrong)[:3] == ('vuln', 1, 'MISMATCH')
    absent = scanners.check_sbom(str(tmp_path), 'nope.json', digest, _sbom(PURL_TEXT))
    assert scanners.summarize_sbom(absent)[0] == 'vuln'


def test_an_sbom_path_cannot_leave_the_clone(tmp_path):
    src = tmp_path / 'src'
    src.mkdir()
    digest = _write(tmp_path, 'outside.json', _sbom(PURL_NET))
    report = scanners.check_sbom(str(src), '../outside.json', digest, _sbom(PURL_NET))
    assert not report['digest_ok']


def test_a_clean_claim_is_contradicted_only_by_a_finding():
    probes = [('osv-scanner', 'vuln', 2, 'aa' * 32), ('gitleaks', 'clean', 0, 'bb' * 32)]
    report = scanners.check_claim('clean', probes)
    assert scanners.summarize_claim(report)[:2] == ('vuln', 2)
    assert scanners.check_claim('none', probes)['contradicted_by'] == []
    assert scanners.check_claim('clean', [probes[1]])['contradicted_by'] == []


def test_each_manifest_names_the_package_its_repo_publishes_as(tmp_path):
    (tmp_path / 'go.mod').write_text('// x\nmodule forge.local/alice/demo\n\ngo 1.22\n')
    (tmp_path / 'package.json').write_text(json.dumps({'name': '@alice/demo'}))
    (tmp_path / 'Cargo.toml').write_text('[package]\nname = "demo"\n')
    (tmp_path / 'pyproject.toml').write_text('[project]\nname = "Demo_Tool"\n')
    found = dict(scanners.manifest_packages(str(tmp_path)))
    assert found == {'pkg:golang/forge.local/alice/demo': 'go.mod',
                     'pkg:npm/%40alice/demo': 'package.json',
                     'pkg:cargo/demo': 'Cargo.toml',
                     'pkg:pypi/demo-tool': 'pyproject.toml'}
    report = scanners.check_provides(str(tmp_path), 'pkg:cargo/demo')
    assert scanners.summarize_provides(report)[:3] == ('clean', 0, '')


def test_a_package_no_manifest_names_is_a_finding(tmp_path):
    (tmp_path / 'go.mod').write_text('module forge.local/alice/demo\n')
    stolen = scanners.check_provides(str(tmp_path), 'pkg:golang/golang.org/x/net')
    assert scanners.summarize_provides(stolen)[:3] == ('vuln', 1, 'UNCLAIMED')
    assert stolen['found'] == ['pkg:golang/forge.local/alice/demo']
    bare = tmp_path / 'bare'
    bare.mkdir()
    (bare / 'Cargo.toml').write_text('not [toml')
    nothing = scanners.check_provides(str(bare), 'pkg:cargo/demo')
    assert nothing['found'] == [] and scanners.summarize_provides(nothing)[0] == 'vuln'


@pytest.fixture
def repo(tmp_path):
    """A one-commit git repository with a committed SBOM."""
    src = tmp_path / 'origin'
    src.mkdir()
    sbom = json.dumps(_sbom(PURL_TEXT)).encode()
    (src / 'sbom.cdx.json').write_bytes(sbom)
    (src / 'main.go').write_text('package main\n')
    env = dict(os.environ, GIT_AUTHOR_NAME='a', GIT_AUTHOR_EMAIL='a@x',
               GIT_COMMITTER_NAME='a', GIT_COMMITTER_EMAIL='a@x')
    for argv in (['git', 'init', '-q'], ['git', 'add', '.'],
                 ['git', 'commit', '-q', '-m', 'seed']):
        subprocess.run(argv, cwd=src, check=True, env=env)
    commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=src, check=True,
                            capture_output=True, text=True).stdout.strip()
    return f'file://{src}', commit, hashlib.sha256(sbom).hexdigest()


def test_the_hook_runs_the_battery_and_checks_the_owners_claims(repo, tmp_path,
                                                                 monkeypatch):
    url, commit, sbom_digest = repo
    root = tmp_path / 'verifier'
    ads = root / 'etc' / 'stele' / 'ads'
    ads.mkdir(parents=True)
    owner = '00000000-0000-4000-8000-000000000001'
    (ads / ('ad' * 32 + '.json')).write_text(json.dumps({
        'owner': owner, 'url': url, 'commit': commit, 'seq': 1, 'v': 2,
        'sbom_digest': sbom_digest, 'sbom_path': 'sbom.cdx.json',
        'claim_verdict': 'clean'}))
    ad = stele_hook.find_ad(str(root), url, commit)
    assert ad['owner'] == owner

    monkeypatch.setattr(scanners, 'run_osv', lambda src, cfg: {'results': [
        {'packages': [{'groups': [{'max_severity': '7.5'}]}]}]})
    monkeypatch.setattr(scanners, 'run_gitleaks', lambda src, cfg: [])
    monkeypatch.setattr(scanners, 'own_sbom',
                        lambda src, cfg: _sbom(PURL_NET, PURL_TEXT))
    calls = []
    monkeypatch.setattr(stele_hook, 'attest',
                        lambda root_, owner_, commit_, report, cfg, scanner, url_:
                        calls.append((scanner, scanners.CHANNELS[scanner], url_)) or 0)
    cfg = {'scanners': ['osv-scanner', 'gitleaks', 'semgrep']}   # semgrep absent
    logged = []
    done = stele_hook.scan_and_attest(str(root), url, commit, owner, ad, cfg,
                                      log=logged.append)
    assert [c[0] for c in calls] == ['osv-scanner', 'gitleaks', 'sbom', 'claim']
    assert dict((c[0], c[1]) for c in calls) == {
        'osv-scanner': 'probe', 'gitleaks': 'probe', 'sbom': 'certificate',
        'claim': 'self_consistency'}
    assert all(c[2] == url for c in calls)
    assert done['sbom'][:2] == ('vuln', 1)            # the SBOM omits x/net
    assert done['claim'][:2] == ('vuln', 1)           # osv found one
    assert any('semgrep' in m for m in logged)        # one tool failing is logged
    # The owner's SBOM matched its digest, so its exact bytes are kept for
    # a dependent's reader to join through.
    import stele_deps
    assert stele_deps.held_sbom(str(root), sbom_digest) == _sbom(PURL_TEXT)


def test_a_v4_ad_has_its_package_checked(repo, tmp_path, monkeypatch):
    url, commit, _ = repo
    root = tmp_path / 'verifier'
    owner = '00000000-0000-4000-8000-000000000001'
    ad = {'owner': owner, 'url': url, 'commit': commit, 'seq': 1, 'v': 4,
          'sbom_digest': '', 'sbom_path': '', 'claim_verdict': 'none',
          'polity': '', 'release_auth': '', 'provides': 'pkg:golang/golang.org/x/net'}
    monkeypatch.setattr(scanners, 'run_osv', lambda src, cfg: {'results': []})
    calls = []
    monkeypatch.setattr(stele_hook, 'attest',
                        lambda root_, owner_, commit_, report, cfg, scanner, url_:
                        calls.append((scanner, scanners.CHANNELS[scanner], report)) or 0)
    done = stele_hook.scan_and_attest(str(root), url, commit, owner, ad, {}, log=print)
    assert [c[:2] for c in calls] == [('osv-scanner', 'probe'),
                                      ('provides', 'certificate')]
    assert done['provides'][:2] == ('vuln', 1)        # the clone has no go.mod
    assert calls[1][2]['claimed'] == 'pkg:golang/golang.org/x/net'


def test_replication_re_runs_other_verifiers_probes_it_can_reproduce(
        repo, tmp_path, monkeypatch):
    """A verifier replicates a held probe by ANOTHER verifier when its own
    scanner version and database are the ones the probe named; it skips its
    own probes, ones it already replicated, and ones it cannot reproduce,
    and does not try any of them twice."""
    url, commit, _ = repo
    root = tmp_path / 'verifier'
    me, them = ('00000000-0000-4000-8000-00000000000%d' % i for i in (2, 3))
    owner = '00000000-0000-4000-8000-000000000001'
    (root / 'etc' / 'at').mkdir(parents=True)
    (root / 'etc' / 'at' / 'identity.cfg.json').write_text(json.dumps({'uuid': me}))
    ads = root / 'etc' / 'stele' / 'ads'
    ats = root / 'etc' / 'stele' / 'attestations'
    ads.mkdir(parents=True)
    ats.mkdir(parents=True)
    ad_id = 'ad' * 32
    (ads / (ad_id + '.json')).write_text(json.dumps({
        'owner': owner, 'url': url, 'commit': commit, 'seq': 1}))

    def held(at_id, verifier, db, **more):
        (ats / (at_id + '.json')).write_text(json.dumps(dict({
            'verifier': verifier, 'repo_ad_id': ad_id, 'commit': commit,
            'scanner': 'osv-scanner', 'scanner_version': '2.6.0',
            'db_digest': db, 'verdict': 'vuln', 'count': 1, 'ts': 1}, **more)))
    held('01' * 32, them, 'cd' * 32)                  # replicable
    held('02' * 32, them, '11' * 32)                  # another database
    held('03' * 32, me, 'cd' * 32)                    # my own
    held('04' * 32, them, 'cd' * 32, ts=2)            # already replicated...
    held('05' * 32, me, 'cd' * 32, v=3, channel='replication',
         replicates='04' * 32)                        # ...by this
    held('06' * 32, them, 'cd' * 32, v=2, channel='certificate',
         scanner='sbom')                              # not a probe

    monkeypatch.setattr(scanners, 'version_of', lambda name, cfg: '2.6.0')
    monkeypatch.setattr(scanners, 'db_digest_of', lambda name, cfg: 'cd' * 32)
    monkeypatch.setattr(scanners, 'run_osv', lambda src, cfg: {'results': [
        {'packages': [{'groups': [{'max_severity': '7.5'}]}]}]})
    calls = []
    monkeypatch.setattr(stele_hook, 'attest',
                        lambda root_, owner_, commit_, report, cfg, scanner, url_,
                        replicates=None: calls.append((owner_, scanner, url_,
                                                       replicates)) or 0)
    done = set()
    out = stele_hook.replicate_once(str(root), {'scanners': ['osv-scanner']}, done,
                                    log=lambda m: None)
    assert calls == [(owner, 'osv-scanner', url, '01' * 32)]
    assert out['01' * 32] == 'vuln'
    assert out['02' * 32].startswith('skipped')
    assert set(out) == {'01' * 32, '02' * 32}
    calls.clear()
    assert stele_hook.replicate_once(str(root), {'scanners': ['osv-scanner']}, done,
                                     log=lambda m: None) == {}
    assert calls == []


def test_reports_from_two_checkouts_of_the_same_tree_digest_the_same():
    """Two verifiers clone into their own temporary directories; the path is
    not a finding (red-team run rt-1487736 disagreed on it alone)."""
    def report(src):
        return {'results': [{'source': {'path': src + '/go.mod', 'type': 'lockfile'},
                             'packages': [{'package': {'name': 'golang.org/x/net'}}]}],
                'root': src}
    a = scanners.relative_paths(report('/tmp/stele-scan-npvc2kz6/src'),
                                '/tmp/stele-scan-npvc2kz6/src')
    b = scanners.relative_paths(report('/tmp/stele-repl-yfj37i18/src'),
                                '/tmp/stele-repl-yfj37i18/src/')
    assert a['results'][0]['source']['path'] == 'go.mod' and a['root'] == '.'
    assert scanners.report_digest(a) == scanners.report_digest(b)
    assert scanners.relative_paths({'p': '/tmp/other/go.mod'}, '/tmp/o') == \
        {'p': '/tmp/other/go.mod'}


def test_a_confirmed_team_finding_is_landed_on_the_guardian_once(tmp_path, monkeypatch):
    """Phase 3: a probe finding about a team release built by a guarded machine
    is landed on the guardian once a second verifier's replication agrees on
    its findings digest, and only once. An unconfirmed, a disputed, a clean
    and an unguarded one are not; nor is one the node already landed."""
    root = tmp_path / 'verifier'
    me, them, other = ('00000000-0000-4000-8000-00000000000%d' % i for i in (2, 3, 4))
    guardian = '00000000-0000-4000-8000-000000000009'
    (root / 'etc' / 'at').mkdir(parents=True)
    (root / 'etc' / 'at' / 'identity.cfg.json').write_text(json.dumps({'uuid': me}))
    ats = root / 'etc' / 'stele' / 'attestations'
    attrs = root / 'etc' / 'stele' / 'attributions'
    ats.mkdir(parents=True)
    attrs.mkdir(parents=True)
    team_ad, plain_ad = 'ad' * 32, 'ae' * 32
    (attrs / (team_ad + '.json')).write_text(json.dumps({
        'polity': 'ab' * 32, 'officer': 'did:key:zo', 'built_by': 'did:key:zci',
        'guardian': 'did:key:zg', 'guardian_uuid': guardian}))

    def held(at_id, verifier, **more):
        (ats / (at_id + '.json')).write_text(json.dumps(dict({
            'verifier': verifier, 'repo_ad_id': team_ad, 'commit': 'c' * 40,
            'scanner': 'osv-scanner', 'verdict': 'vuln', 'findings_digest': 'f1' * 32,
            'ts': 1}, **more)))
    held('01' * 32, them)                                     # confirmed below
    held('11' * 32, other, v=3, channel='replication', replicates='01' * 32)
    held('02' * 32, them, ts=2)                               # unconfirmed
    held('03' * 32, them, ts=3)                               # disputed below
    held('13' * 32, other, v=3, channel='replication', replicates='03' * 32,
         findings_digest='f2' * 32)
    held('04' * 32, them, repo_ad_id=plain_ad)                # not a team release
    held('14' * 32, other, v=3, channel='replication', replicates='04' * 32,
         repo_ad_id=plain_ad)
    held('05' * 32, them, ts=5)                               # already landed...
    held('15' * 32, other, v=3, channel='replication', replicates='05' * 32)
    held('25' * 32, me, v=4, attributes='05' * 32)            # ...by this

    assert [i for i, _ in stele_hook.pending_guardians(str(root))] == ['01' * 32]
    calls = []
    monkeypatch.setattr(stele_hook.subprocess, 'run',
                        lambda argv: calls.append(argv[2:]) or
                        type('R', (), {'returncode': 0})())
    done = set()
    assert stele_hook.guardian_once(str(root), done, log=lambda m: None) == {'01' * 32: 0}
    assert calls == [['guardian', str(root), '01' * 32]]
    assert stele_hook.guardian_once(str(root), done, log=lambda m: None) == {}
    # The guardian does not land a finding on itself.
    (root / 'etc' / 'at' / 'identity.cfg.json').write_text(json.dumps({'uuid': guardian}))
    assert stele_hook.pending_guardians(str(root)) == []
