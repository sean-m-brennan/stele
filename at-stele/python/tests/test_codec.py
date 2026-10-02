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
