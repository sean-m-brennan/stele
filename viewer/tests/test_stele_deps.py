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
"""The supply-chain view (Phase 4): a repository's dependencies, read from the
SBOM its ad pins and resolved to the repositories that publish them, against
real AT records archived the way test_stele_view's observer archives them."""
import hashlib
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from test_stele_view import NOW, URL, C1, C2, Node, _local  # noqa: E402

import stele_deps  # noqa: E402

LIB = 'pkg:golang/forge.local/alice/lib'
LIB_URL = 'http://forge.local/alice/lib.git'
EVIL_URL = 'http://forge.local/mallory/lib.git'
C3 = '3' * 40
C4 = '4' * 40


@pytest.fixture
def node(tmp_path, monkeypatch):
    return Node(tmp_path / 'viewer', monkeypatch)


def _sbom(*purls):
    return json.dumps({'bomFormat': 'CycloneDX', 'components': [
        {'type': 'library', 'name': p, 'purl': p} for p in purls]}).encode()


def _with_sbom(node, *purls):
    raw = _sbom(*purls)
    assert stele_deps.keep_sbom(str(node.root), raw)
    return hashlib.sha256(raw).hexdigest()


def _two(node, ad_id, ad, verdict='clean', scanner='osv-scanner', channel='probe'):
    first = node.attest(ad_id, ad, verdict, NOW, scanner=scanner, channel=channel)
    node.attest(ad_id, ad, verdict, NOW + 5, scanner=scanner, channel=channel,
                by=node.ver2)
    return first


def _lib(node, verdict='clean', name='lib', url=LIB_URL, commit=C3, ref='v1.0.0',
         confirm_claim=True):
    """A repository that publishes LIB, its claim confirmed by both verifiers,
    with one osv check of `verdict`."""
    ad_id, ad = node.advertise(commit, 1, name=name, url=url, ref=ref, provides=LIB)
    if confirm_claim:
        _two(node, ad_id, ad, scanner='provides', channel='certificate')
    _two(node, ad_id, ad, verdict)
    return ad_id, ad


def _app(node, *purls, seq=1):
    digest = _with_sbom(node, *purls)
    ad_id, ad = node.advertise(C1, seq, sbom_digest=digest, sbom_path='sbom.cdx.json')
    _two(node, ad_id, ad)
    return ad_id, ad


def _dep(st, purl):
    return next(i for i in st['deps']['items'] if i['purl'] == purl)


# ---------------- purls ----------------

@pytest.mark.parametrize('purl,base,version', [
    ('pkg:golang/golang.org/x/net@v0.1.0', 'pkg:golang/golang.org/x/net', 'v0.1.0'),
    ('pkg:npm/%40alice/demo@1.2.0?x=1#lib', 'pkg:npm/%40alice/demo', '1.2.0'),
    ('pkg:cargo/demo', 'pkg:cargo/demo', ''),
    ('left-pad@1.0.0', 'left-pad@1.0.0', '')])
def test_a_purl_splits_into_its_package_and_version(purl, base, version):
    assert stele_deps.purl_base(purl) == base
    assert stele_deps.purl_version(purl) == version


def test_a_release_is_named_by_its_tag_or_by_its_commit():
    assert stele_deps.version_matches('refs/tags/v1.2.0', '1.2.0')
    assert stele_deps.version_matches('v1.2.0', 'v1.2.0')
    assert not stele_deps.version_matches('main', 'v1.2.0')
    assert not stele_deps.version_matches('v1.2.0', '')
    pseudo = 'v0.0.0-20241001120000-0123456789ab'
    assert stele_deps.version_matches('main', pseudo, '0123456789ab' + 'c' * 28)
    assert not stele_deps.version_matches('main', pseudo, 'f' * 40)


def test_the_store_takes_only_bytes_that_hash_to_their_name(tmp_path):
    root = str(tmp_path)
    digest = stele_deps.keep_sbom(root, _sbom(LIB + '@v1.0.0'))
    assert stele_deps.components(stele_deps.held_sbom(root, digest)) == [LIB + '@v1.0.0']
    path = os.path.join(root, 'etc', 'stele', 'sboms', digest + '.json')
    with open(path, 'wb') as f:
        f.write(_sbom('pkg:npm/other@1'))
    assert stele_deps.held_sbom(root, digest) is None
    assert stele_deps.keep_sbom(root, b'[1, 2]') is None
    assert stele_deps.held_sbom(root, '../x') is None


# ---------------- the fold ----------------

def test_a_dependency_resolves_to_the_repository_that_publishes_it(node):
    _lib(node, 'vuln')
    _app(node, LIB + '@v1.0.0', 'pkg:golang/golang.org/x/net@v0.1.0')
    st = node.view().standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'verified-safe'          # stele-default shows, never caps
    assert 'capped_by_deps' not in st
    d = st['deps']
    assert d['sbom'] == 'held' and d['resolved'] == 1 and d['unresolved'] == 1
    assert d['state'] == 'failing'
    lib = _dep(st, LIB + '@v1.0.0')
    assert lib['status'] == 'resolved' and lib['state'] == 'failing'
    assert lib['claimants'][0]['url'] == LIB_URL and lib['claimants'][0]['via'] == 'provides'
    net = _dep(st, 'pkg:golang/golang.org/x/net@v0.1.0')
    assert net['status'] == 'not-on-stele' and net['state'] is None


def test_a_profile_may_hold_a_repository_to_its_worst_dependency(node):
    _lib(node, 'vuln')
    _app(node, LIB + '@v1.0.0')
    _local(node, 'deps-worst', deps='worst')
    st = node.view(profile='deps-worst').standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'failing' and st['capped_by_deps']
    assert st['profile']['name'] == 'deps-worst'


def test_an_unconfirmed_claim_is_shown_and_never_folded(node):
    _lib(node, 'vuln', confirm_claim=False)
    _app(node, LIB + '@v1.0.0')
    _local(node, 'deps-worst', deps='worst')
    st = node.view(profile='deps-worst').standing_by_url(URL, now=NOW + 60)
    assert st['state'] == 'verified-safe' and 'capped_by_deps' not in st
    lib = _dep(st, LIB + '@v1.0.0')
    assert lib['status'] == 'claim-unconfirmed' and st['deps']['state'] is None


def test_a_claim_the_verifiers_refuted_does_not_count(node):
    ad_id, ad = node.advertise(C3, 1, name='lib', url=LIB_URL, ref='v1.0.0', provides=LIB)
    _two(node, ad_id, ad, 'vuln', scanner='provides', channel='certificate')
    _app(node, LIB + '@v1.0.0')
    st = node.view().standing_by_url(URL, now=NOW + 60)
    assert _dep(st, LIB + '@v1.0.0')['status'] == 'claim-unconfirmed'


def test_a_version_no_held_ad_names_is_not_read(node):
    _lib(node, 'vuln')
    _app(node, LIB + '@v2.0.0')
    st = node.view().standing_by_url(URL, now=NOW + 60)
    assert _dep(st, LIB + '@v2.0.0')['status'] == 'version-not-held'
    assert st['deps']['state'] is None


def test_several_claimants_stand_at_the_worst_of_them(node):
    """A squatter who publishes the same package can only lower it."""
    _lib(node, 'clean')
    _lib(node, 'vuln', name='lib-fork', url=EVIL_URL, commit=C4)
    _app(node, LIB + '@v1.0.0')
    st = node.view().standing_by_url(URL, now=NOW + 60)
    lib = _dep(st, LIB + '@v1.0.0')
    assert len(lib['claimants']) == 2 and lib['state'] == 'failing'


def test_a_pin_replaces_every_claimant(node):
    _lib(node, 'clean')
    _lib(node, 'vuln', name='lib-fork', url=EVIL_URL, commit=C4)
    _app(node, LIB + '@v1.0.0')
    stele_deps.pin(str(node.root), LIB, LIB_URL)
    st = node.view().standing_by_url(URL, now=NOW + 60)
    lib = _dep(st, LIB + '@v1.0.0')
    assert [c['url'] for c in lib['claimants']] == [LIB_URL]
    assert lib['claimants'][0]['via'] == 'pin' and lib['state'] == 'verified-safe'


def test_a_pin_needs_no_claim(node):
    ad_id, ad = node.advertise(C3, 1, name='lib', url=LIB_URL, ref='v1.0.0')
    _two(node, ad_id, ad)
    _app(node, LIB + '@v1.0.0')
    assert _dep(node.view().standing_by_url(URL, now=NOW + 60),
                LIB + '@v1.0.0')['status'] == 'not-on-stele'
    stele_deps.pin(str(node.root), LIB, LIB_URL)
    assert _dep(node.view().standing_by_url(URL, now=NOW + 60),
                LIB + '@v1.0.0')['state'] == 'verified-safe'


def test_a_dependency_stands_with_its_own_dependencies_under_worst(node):
    """app -> lib -> base: base's finding caps lib, and lib caps app."""
    base = 'pkg:golang/forge.local/alice/base'
    b_id, b_ad = node.advertise(C4, 1, name='base', url='http://forge.local/alice/base.git',
                                ref='v0.1.0', provides=base)
    _two(node, b_id, b_ad, scanner='provides', channel='certificate')
    _two(node, b_id, b_ad, 'vuln')
    digest = _with_sbom(node, base + '@v0.1.0')
    l_id, l_ad = node.advertise(C3, 1, name='lib', url=LIB_URL, ref='v1.0.0',
                                provides=LIB, sbom_digest=digest, sbom_path='sbom.json')
    _two(node, l_id, l_ad, scanner='provides', channel='certificate')
    _two(node, l_id, l_ad)
    _app(node, LIB + '@v1.0.0')
    _local(node, 'deps-worst', deps='worst')
    st = node.view(profile='deps-worst').standing_by_url(URL, now=NOW + 60)
    lib = _dep(st, LIB + '@v1.0.0')
    assert lib['state'] == 'failing' and lib['claimants'][0]['capped_by_deps']
    assert st['state'] == 'failing' and st['capped_by_deps']
    shown = node.view().standing_by_url(URL, now=NOW + 60)
    assert _dep(shown, LIB + '@v1.0.0')['state'] == 'verified-safe'   # show: lib's own


def test_a_cycle_is_named_and_never_followed(node):
    """app depends on lib and lib on app: the loop is read once."""
    app = 'pkg:golang/forge.local/alice/demo'
    digest = _with_sbom(node, app + '@main')
    l_id, l_ad = node.advertise(C3, 1, name='lib', url=LIB_URL, ref='v1.0.0',
                                provides=LIB, sbom_digest=digest, sbom_path='sbom.json')
    _two(node, l_id, l_ad, scanner='provides', channel='certificate')
    _two(node, l_id, l_ad)
    a_digest = _with_sbom(node, LIB + '@v1.0.0')
    a_id, a_ad = node.advertise(C1, 1, sbom_digest=a_digest, sbom_path='sbom.json',
                                provides=app)
    _two(node, a_id, a_ad, scanner='provides', channel='certificate')
    _two(node, a_id, a_ad)
    st = node.view().standing_by_url(URL, now=NOW + 60)
    lib = _dep(st, LIB + '@v1.0.0')
    assert lib['status'] == 'resolved' and lib['claimants'][0].get('partial')
    view = node.view()
    lib_st = view._standing_of(l_id, l_ad, NOW + 60, seen=(a_id,))
    assert _dep(lib_st, app + '@main')['claimants'][0]['status'] == 'cycle'


def test_an_sbom_the_node_does_not_hold_lists_nothing(node):
    ad_id, ad = node.advertise(C1, 1, sbom_digest='ab' * 32, sbom_path='sbom.json')
    _two(node, ad_id, ad)
    st = node.view().standing_by_url(URL, now=NOW + 60)
    assert st['deps']['sbom'] == 'not-held' and st['deps']['items'] == []
    ad_id, ad = node.advertise(C2, 2)
    _two(node, ad_id, ad)
    assert node.view().standing_by_url(URL, now=NOW + 60)['deps']['sbom'] == 'none'


def test_a_bundle_may_carry_the_sbom(node):
    _lib(node, 'vuln')
    raw = _sbom(LIB + '@v1.0.0')
    digest = hashlib.sha256(raw).hexdigest()
    ad_id, ad = node.advertise(C1, 1, sbom_digest=digest, sbom_path='sbom.json')
    _two(node, ad_id, ad)
    view = node.view()
    assert view.standing_by_url(URL, now=NOW + 60)['deps']['sbom'] == 'not-held'
    view.add_bundle({'sboms': {digest: raw.decode(), 'ab' * 32: raw.decode()}})
    st = view.standing_by_url(URL, now=NOW + 60)
    assert st['deps']['sbom'] == 'held' and st['deps']['state'] == 'failing'
    assert 'ab' * 32 not in view.sboms                 # text that does not hash to its name
    assert not os.path.isdir(os.path.join(str(node.root), 'etc', 'stele', 'sboms'))


def test_team_standing_reads_no_dependencies(node):
    _lib(node, 'vuln')
    _app(node, LIB + '@v1.0.0')
    view = node.view()
    st = view.standing(str(node.owner.uuid), 'demo', NOW + 60, with_deps=False)
    assert 'deps' not in st
