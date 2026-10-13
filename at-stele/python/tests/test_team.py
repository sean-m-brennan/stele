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
"""Stele Phase 3: the team roster and the release authorization, verified
against the byte-pinned vectors Ethne emits (en-uplift stele.rs,
the_files_are_byte_pinned), and the v3 ad and v4 attestation forms. Twin of
c/stele/test/stele_team_test.c."""
import json

import nacl.signing

from autonomous_trust.stele import codec, team

TEAM = '{"body":"{\\"v\\":1,\\"typename\\":\\"stele-team\\",\\"polity\\":\\"did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z\\",\\"issuer\\":\\"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c\\",\\"seq\\":3,\\"members\\":[{\\"did\\":\\"did:key:z6MkfDSNRs2i9S6LZ5vd4RbpZ6754H7R3btDqRTeHhamqvuJ\\",\\"key\\":\\"0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d\\",\\"at_uuid\\":\\"2b3c4d5e-6f70-4182-93a4-b5c6d7e8f90a\\",\\"consent\\":\\"2aa71ad84c1bbe33f052af7053b75d920692743172936c9bf55ce38b181476689e6ab00381999f08ce4390d0c7500079fb10adf6a2e4e057a84ddf0a368f2f00\\"},{\\"did\\":\\"did:key:z6Mkj1MDZKcfx9AX5CeXHdysiGkRLzBbALyFuShD6wNeY1E3\\",\\"key\\":\\"43a72e714401762df66b68c26dfbdf2682aaec9f2474eca4613e424a0fbafd3c\\",\\"at_uuid\\":\\"0f1e2d3c-4b5a-4968-8776-655443322110\\",\\"consent\\":\\"9d50d0c830b505725bb63884dfa17d999d435dfdd7b8059bbad94bd9cf8ed45b3b5413172c6417b5a4bd8f0cd49598788664562ed9a7ac6530d45be974e6ac07\\"},{\\"did\\":\\"did:key:z6MkmNL6xksdEJENGk9Z1qqGsY5njKQdjU1UhnUEUvWyQUVX\\",\\"key\\":\\"66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a\\",\\"at_uuid\\":\\"1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9\\",\\"consent\\":\\"b782515541bd3a0abb36bf41ff2d59ff3d17a85b63c312fe6fc2a35639a0ead8f490444496e4499c3675e8aae902ff2763434908542e138a9dacca6efed19f09\\"}],\\"release_officers\\":[\\"did:key:z6Mkj1MDZKcfx9AX5CeXHdysiGkRLzBbALyFuShD6wNeY1E3\\"],\\"guardians\\":[{\\"machine\\":\\"did:key:z6MkfDSNRs2i9S6LZ5vd4RbpZ6754H7R3btDqRTeHhamqvuJ\\",\\"guardian\\":\\"did:key:z6MkmNL6xksdEJENGk9Z1qqGsY5njKQdjU1UhnUEUvWyQUVX\\"}]}","sig":"1a3ffdfc52410608b4cfff8a3e242b2ae9086b07808ca210aec56fea53e6b6975276aa4dddc360d39cad16e6357b74bf0815e45fa938b3d84461eeb73c985404"}'
RELEASE = '{"body":"{\\"v\\":1,\\"typename\\":\\"stele-release\\",\\"polity\\":\\"did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z\\",\\"issuer\\":\\"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c\\",\\"officer\\":\\"did:key:z6Mkj1MDZKcfx9AX5CeXHdysiGkRLzBbALyFuShD6wNeY1E3\\",\\"officer_key\\":\\"43a72e714401762df66b68c26dfbdf2682aaec9f2474eca4613e424a0fbafd3c\\",\\"repo\\":\\"demo\\",\\"url\\":\\"http://localhost:3000/stele/demo.git\\",\\"commit\\":\\"c3cd66ac5a89e0d1f2a3b4c5d6e7f8091a2b3c4d\\",\\"built_by\\":\\"did:key:z6MkfDSNRs2i9S6LZ5vd4RbpZ6754H7R3btDqRTeHhamqvuJ\\",\\"authorized_at\\":400}","sig":"2d7e4af1f0f40f43f3251996825ecd749a90d3a0d879e7ecd23e64d8dcef98b9bcdc62f8b599aae6635804603f06801c48486bb7b1a90bb9bc2f8b352327d400"}'
UUID_A = '0f1e2d3c-4b5a-4968-8776-655443322110'
UUID_B = '1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9'
UUID_C = '2b3c4d5e-6f70-4182-93a4-b5c6d7e8f90a'
NODES = {UUID_A: 'acdb0e29743f0ccb8686d0a104cb96e05abefec1538765e7595869f7dc8c49aa', UUID_B: '43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de', UUID_C: '4ed32f63bf35f0eeefcb25f28a2e1fbdc873ae2835671b0c9460f5f12e4556a8'}
ISSUER = 'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c'
COMMIT = 'c3cd66ac5a89e0d1f2a3b4c5d6e7f8091a2b3c4d'


def test_the_pinned_roster_verifies_with_consents():
    t = team.parse_team(TEAM)
    assert t is not None
    assert t['issuer'] == ISSUER and t['seq'] == 3 and len(t['members']) == 3
    (officer,) = t['officers']
    assert team.member(t, did=officer)['at_uuid'] == UUID_A
    (edge,) = t['guardians']
    assert team.member(t, did=edge['machine'])['at_uuid'] == UUID_C
    assert team.member(t, did=team.guardian_of(t, edge['machine']))['at_uuid'] == UUID_B
    assert team.consents_ok(t, NODES.get) == (True, None)
    # A node this one holds no key for has not consented, as far as it knows.
    assert team.consents_ok(t, lambda u: None if u == UUID_B else NODES[u]) == (False, UUID_B)


def test_a_tampered_roster_or_a_borrowed_consent_fails():
    assert team.parse_team(TEAM.replace('\\"seq\\":3', '\\"seq\\":4', 1)) is None
    assert team.parse_team(RELEASE) is None
    t = team.parse_team(TEAM)
    t['members'][0]['consent'] = t['members'][1]['consent']
    assert team.consents_ok(t, NODES.get)[0] is False


def test_the_pinned_release_verifies_under_its_officer():
    r = team.parse_release(RELEASE)
    assert r is not None
    assert (r['issuer'], r['repo'], r['url'], r['commit'], r['authorized_at']) == (
        ISSUER, 'demo', 'http://localhost:3000/stele/demo.git', COMMIT, 400)
    t = team.parse_team(TEAM)
    assert r['officer'] in t['officers']
    assert team.member(t, did=r['officer'])['key'] == r['officer_key']
    assert team.member(t, did=r['built_by'])['at_uuid'] == UUID_C
    assert team.parse_release(RELEASE.replace('c3cd66ac5a89', 'c3cd66ac5a8a', 1)) is None
    assert team.parse_release(TEAM) is None


def test_the_consent_message_is_ethnes():
    assert team.consent_message(ISSUER, 'did:key:z6Mkabc', UUID_A) == (
        'stele-team-member-v1|%s|did:key:z6Mkabc|%s' % (ISSUER, UUID_A)).encode()


def _ad3():
    return {'owner': UUID_A, 'name': 'demo', 'url': 'http://localhost:3000/stele/demo.git',
            'ref': 'main', 'commit': COMMIT, 'seq': 1, 'ts': 1790000000, 'v': 3,
            'description': '', 'topics': '', 'sbom_digest': '', 'sbom_path': '',
            'claim_verdict': 'none', 'polity': ISSUER, 'release_auth': RELEASE}


def test_a_v3_ad_binds_its_release_by_digest():
    ad = _ad3()
    canon = codec.repo_ad_canonical(ad)
    assert canon.startswith(b'STELE-REPO3\x00')
    assert canon.endswith(('|%s|%s' % (ISSUER, codec.release_digest(RELEASE))).encode())
    # Another release under the same ad is another ad.
    other = dict(ad, release_auth=RELEASE.replace('"sig":"2d', '"sig":"3d', 1))
    assert codec.repo_ad_id(other) != codec.repo_ad_id(ad)
    # The envelope round-trips, with the release text in it.
    env = dict(ad, sig='00' * 64)
    parsed = codec.from_envelope(json.loads(json.dumps(env)), codec.AD_KEYS)
    assert parsed is not None and parsed[0] == ad
    assert not codec.repo_ad_valid(dict(ad, polity='nothex'))
    assert not codec.repo_ad_valid(dict(ad, release_auth=''))


def test_a_v4_attestation_names_the_finding_and_the_machine():
    at = {'verifier': UUID_B, 'repo_ad_id': 'ab' * 32, 'commit': COMMIT,
          'scanner': 'osv-scanner', 'scanner_version': '2.6.0', 'db_digest': 'cd' * 32,
          'findings_digest': 'ef' * 32, 'verdict': 'vuln', 'count': 3,
          'max_severity': '7.5', 'ts': 1790000000, 'v': 4, 'channel': 'probe',
          'scope': '12' * 32, 'attributes': '34' * 32,
          'guardian_of': 'did:key:z6MkfDSNRs2i9S6LZ5vd4RbpZ6754H7R3btDqRTeHhamqvuJ'}
    canon = codec.attestation_canonical(at)
    assert canon.startswith(b'STELE-ATTEST4\x00')
    assert canon.endswith(('|%s|%s' % ('34' * 32, at['guardian_of'])).encode())
    # Only a finding, only on probe, only a did:key machine.
    assert not codec.attestation_valid(dict(at, verdict='clean', count=0))
    assert not codec.attestation_valid(dict(at, channel='replication'))
    assert not codec.attestation_valid(dict(at, guardian_of='machine|x'))
    parsed = codec.from_envelope(dict(at, sig='00' * 64), codec.ATTEST_KEYS)
    assert parsed is not None and parsed[0] == at
