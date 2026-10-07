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
"""Stele's codec, the Python half. The fixed vectors are the cross-language
pin: c/stele/test/stele_codec_test.c holds the same two ids."""
import nacl.signing

from autonomous_trust.stele import codec

AD = {'owner': '00000000-0000-4000-8000-000000000001', 'name': 'demo',
      'url': 'http://forge.local/alice/demo.git', 'ref': 'main',
      'commit': '0123456789abcdef0123456789abcdef01234567', 'seq': 1,
      'ts': 1790000000}


def _at(ad_id):
    return {'verifier': '00000000-0000-4000-8000-000000000002',
            'repo_ad_id': ad_id, 'commit': AD['commit'], 'scanner': 'osv-scanner',
            'scanner_version': '2.6.0', 'db_digest': 'cd' * 32,
            'findings_digest': 'ef' * 32, 'verdict': 'vuln', 'count': 2,
            'max_severity': 'HIGH', 'ts': 1790000100}


def test_fixed_vectors():
    ad_id = codec.repo_ad_id(AD)
    assert ad_id == 'b7743ddb9be9a22fcde814ebc1ef49874f37d9bce617f0f6146b21011101b185'
    assert codec.attestation_id(_at(ad_id)) == \
        'bf31aacaa9a976e8ff224835433738bd82583a3029da8ff23319d2b85cd7aa4f'


def test_sign_verify_and_tamper():
    sk = nacl.signing.SigningKey.generate()
    canon = codec.repo_ad_canonical(AD)
    sig = codec.sign(sk, canon)
    assert codec.verify(sk.verify_key, canon, sig)
    assert not codec.verify(sk.verify_key,
                            codec.repo_ad_canonical(dict(AD, seq=2)), sig)


def test_field_rules():
    assert not codec.repo_ad_valid(dict(AD, name='a|b'))
    assert not codec.repo_ad_valid(dict(AD, commit='ABCDEF'))
    at = _at('ab' * 32)
    assert codec.attestation_valid(at)
    assert not codec.attestation_valid(dict(at, count=0))
    assert codec.attestation_valid(dict(at, verdict='clean', count=0))
    assert not codec.attestation_valid(dict(at, verdict='maybe'))


AD2 = dict(AD, v=2, description='a demo repo', topics='go,demo',
           sbom_digest='ab' * 32, sbom_path='sbom.cdx.json', claim_verdict='clean')


def test_v2_fixed_vectors():
    """Version 2 under its own tags (c/stele/test/stele_codec_test.c holds the
    same ids), and v1 unchanged beside it."""
    ad_id = codec.repo_ad_id(AD2)
    assert ad_id == '272c0cc3307694e5eca75b6415d11b1d71dc1e5f7690f0be0ee9b61c2d563b89'
    sc = codec.scope(AD['owner'], 'demo', AD['commit'], 'osv-scanner')
    assert sc == '7f198d461dddd03608116142875b6cfcabbd06e5d4336bd76444aee2d82372e4'
    at = dict(_at(ad_id), v=2, channel='self_consistency', scope=sc)
    at_id = codec.attestation_id(at)
    assert at_id == 'ae530d953d26c613153103de30b8aca1aa17bc5a30833d03011aa3f105ada506'
    rb = {'owner': AD['owner'], 'attestation_id': at_id,
          'text': 'fixed in the next release', 'ts': 1790000200}
    assert codec.rebuttal_id(rb) == \
        '32472c5b8ecda607b2e84ec404bf3973f021990ec7beab33e6cedbfac1d6e8ce'


def test_v2_envelopes_round_trip_and_v1_still_parses():
    env = dict(AD2, sig='00' * 64)
    ad, _ = codec.from_envelope(env, codec.AD_KEYS)
    assert ad['v'] == 2 and codec.repo_ad_id(ad) == codec.repo_ad_id(AD2)
    v1, _ = codec.from_envelope(dict(AD, sig='00' * 64), codec.AD_KEYS)
    assert 'v' not in v1 and codec.repo_ad_id(v1) == codec.repo_ad_id(AD)
    missing = dict(env)
    del missing['claim_verdict']
    assert codec.from_envelope(missing, codec.AD_KEYS) is None


def test_v2_field_rules():
    assert codec.repo_ad_valid(AD2)
    assert not codec.repo_ad_valid(dict(AD2, claim_verdict='maybe'))
    assert not codec.repo_ad_valid(dict(AD2, sbom_path=''))      # digest without path
    assert codec.repo_ad_valid(dict(AD2, sbom_digest='', sbom_path=''))
    at = dict(_at(codec.repo_ad_id(AD2)), v=2, channel='replication', scope='aa' * 32)
    assert not codec.attestation_valid(at)          # replication is v3 only
    assert codec.attestation_valid(dict(at, channel='certificate'))
    assert not codec.rebuttal_valid({'owner': AD['owner'], 'attestation_id': 'aa' * 32,
                                     'text': 'a|b', 'ts': 1})


def test_v3_fixed_vectors():
    """A replication names the attestation it re-ran, under STELE-ATTEST3
    (c/stele/test/stele_codec_test.c holds the same id)."""
    ad_id = codec.repo_ad_id(AD2)
    sc = codec.scope(AD['owner'], 'demo', AD['commit'], 'osv-scanner')
    orig = codec.attestation_id(dict(_at(ad_id), v=2, channel='self_consistency',
                                     scope=sc))
    at = dict(_at(ad_id), v=3, channel='replication', scope=sc, replicates=orig)
    assert codec.attestation_canonical(at).startswith(b'STELE-ATTEST3\x00')
    assert codec.attestation_id(at) == \
        'd0af362981b137e5cc47219e63f164689e33ba54dba1c6c1858907418f0406b3'


def test_v3_field_rules_and_envelope():
    sc = 'aa' * 32
    at = dict(_at(codec.repo_ad_id(AD2)), v=3, channel='replication', scope=sc,
              replicates='bb' * 32)
    assert codec.attestation_valid(at)
    assert not codec.attestation_valid(dict(at, replicates=''))
    assert not codec.attestation_valid(dict(at, replicates='BB' * 32))
    assert codec.attestation_valid(dict(at, channel='probe', replicates=''))
    assert not codec.attestation_valid(dict(at, channel='probe'))
    back, sig = codec.from_envelope(dict(at, sig='00' * 64), codec.ATTEST_KEYS)
    assert back == at and sig == '00' * 64
    missing = dict(at, sig='00' * 64)
    del missing['replicates']
    assert codec.from_envelope(missing, codec.ATTEST_KEYS) is None
    assert codec.from_envelope(dict(at, v=4, sig='00' * 64), codec.ATTEST_KEYS) is None
    assert codec.from_envelope(dict(AD2, v=3, sig='00' * 64), codec.AD_KEYS) is None
