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
"""Profiles (Phase 4): parsing inside the floors, severities, the signed file
Ethne emits (border artifact #11), and what following a polity means."""
import json
import os
import sys

import nacl.signing
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
import stele_profile as sp  # noqa: E402

#: en-uplift's PINNED_PROFILE_VECTOR (stele.rs, the_profile_file_is_byte_pinned):
#: root seed 7, seq 2, acme-strict. A change on either side is a wire change.
PINNED = r"""{"body":"{\"v\":1,\"typename\":\"stele-profile\",\"polity\":\"did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z\",\"issuer\":\"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c\",\"seq\":2,\"set_by\":\"b3:992882019a31d7694845b120d9592b7135e9f4876c5a09556cc316fd51858e38\",\"profile\":{\"name\":\"acme-strict\",\"replicas\":3,\"tier\":3,\"require\":[\"gitleaks:probe\",\"osv-scanner:probe\"],\"ignore\":[\"semgrep:probe\"],\"severity_floor\":\"medium\",\"onset_days\":1,\"half_life_days\":14,\"team\":\"worst\"}}","sig":"06104175233204cb6e45c503287ccf40dc3ab17c9f5c950c942cab30a7a78b390c7c56f939fea92a28e33481fc461dcdf2d90b8400f65a127a022860315a1708"}"""
PINNED_ISSUER = 'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c'

KEY = nacl.signing.SigningKey(bytes([3]) * 32)


def signed(seq, key=KEY, **fields):
    p = sp.parse(dict(fields, name=fields.get('name', 'acme')))
    body = json.dumps({'v': 1, 'typename': 'stele-profile', 'polity': 'did:key:zacme',
                       'issuer': bytes(key.verify_key).hex(), 'seq': seq,
                       'set_by': 'bafy', 'profile': {k: p[k] for k in sp.FIELDS}},
                      separators=(',', ':'))
    return json.dumps({'body': body, 'sig': key.sign(sp.PROFILE_DOMAIN + body.encode())
                       .signature.hex()})


def test_ethnes_pinned_profile_verifies_here():
    got = sp.verify_signed(PINNED)
    assert got['issuer'] == PINNED_ISSUER and got['seq'] == 2
    assert got['profile'] == {
        'name': 'acme-strict', 'replicas': 3, 'tier': 3,
        'require': ['gitleaks:probe', 'osv-scanner:probe'], 'ignore': ['semgrep:probe'],
        'severity_floor': 'medium', 'onset_days': 1, 'half_life_days': 14,
        'team': 'worst',
        'deps': 'show'}   # signed before the supply-chain view: absent reads as show


def test_a_forged_or_misdirected_profile_is_refused():
    outer = json.loads(PINNED)
    tampered = dict(outer, body=outer['body'].replace('"replicas":3', '"replicas":1'))
    with pytest.raises(sp.ProfileError, match='does not verify'):
        sp.verify_signed(json.dumps(tampered))
    # The same body under the team roster's domain is not a profile signature.
    body = json.loads(signed(1))['body']
    other = json.dumps({'body': body, 'sig': KEY.sign(b'stele-team-v1|' + body.encode())
                        .signature.hex()})
    with pytest.raises(sp.ProfileError):
        sp.verify_signed(other)
    with pytest.raises(sp.ProfileError):
        sp.verify_signed('{"body": "{}", "sig": "00"}')


def test_the_builtins_are_inside_their_own_floors():
    assert sp.parse(sp.STELE_DEFAULT) == sp.STELE_DEFAULT
    strict = sp.parse(sp.STELE_STRICT)
    assert strict['replicas'] == 3 and strict['team'] == 'worst'
    assert strict['deps'] == 'worst' and sp.STELE_DEFAULT['deps'] == 'show'


@pytest.mark.parametrize('bad', [
    {'replicas': 0}, {'replicas': 17}, {'replicas': True}, {'tier': 0}, {'tier': 5},
    {'onset_days': 31}, {'half_life_days': 0}, {'half_life_days': 366},
    {'severity_floor': 'critical'}, {'team': 'best'}, {'deps': 'best'},
    {'deps': None}, {'name': 'Has Caps'},
    {'require': ['osv-scanner']}, {'require': ['osv-scanner:replication']},
    {'ignore': ['s%d:probe' % i for i in range(17)]},
    {'require': ['a:probe'], 'ignore': ['a:probe']}, {'whatever': 1}])
def test_a_profile_outside_the_floors_is_refused(bad):
    with pytest.raises(sp.ProfileError):
        sp.parse(dict({'name': 'x'}, **bad))


def test_a_signed_body_must_be_complete():
    with pytest.raises(sp.ProfileError, match='missing'):
        sp.parse({'name': 'x', 'replicas': 3}, complete=True)


def test_a_signed_body_signed_before_deps_reads_it_as_show():
    """Ethne writes ``deps`` only when it is ``worst``, so a D42 body signed
    before the supply-chain view, or one that keeps ``show``, leaves it out."""
    body = {k: v for k, v in sp.STELE_DEFAULT.items() if k != 'deps'}
    assert sp.parse(dict(body, name='x'), complete=True)['deps'] == 'show'
    assert sp.parse(dict(body, name='x', deps='worst'), complete=True)['deps'] == 'worst'


@pytest.mark.parametrize('sev,rank', [
    ('9.8', 3), ('9.0', 3), ('8.9', 2), ('7.0', 2), ('6.9', 1), ('4.0', 1), ('3.9', 0),
    ('0.0', 0), ('CRITICAL', 3), ('high', 2), ('MODERATE', 1), ('MEDIUM', 1),
    ('LOW', 0), ('ERROR', 2), ('WARNING', 1), ('INFO', 0), ('SECRET', None),
    ('MISMATCH', None), ('CONTRADICTED', None), ('GPL-3.0', None), ('', None),
    (None, None), ('nan', None)])
def test_severities_land_on_one_scale(sev, rank):
    assert sp.severity_rank(sev) == rank


def test_the_floor_sets_aside_only_rated_findings_below_it():
    high = sp.parse({'name': 'x', 'severity_floor': 'high'})
    assert not sp.counts_finding(high, '6.5')
    assert sp.counts_finding(high, '7.5') and sp.counts_finding(high, 'CRITICAL')
    assert sp.counts_finding(high, 'SECRET'), 'an unrated finding always counts'
    assert sp.counts_finding(sp.STELE_DEFAULT, '0.1')


def test_following_pins_the_issuer_and_only_a_newer_seq_replaces(tmp_path):
    root = str(tmp_path)
    assert sp.follow(root, signed(2, replicas=3))['seq'] == 2
    assert sp.follow(root, signed(2, replicas=3))['seq'] == 2       # the same, idempotent
    with pytest.raises(sp.ProfileError, match='older'):
        sp.follow(root, signed(1, replicas=3))
    other = nacl.signing.SigningKey(bytes([4]) * 32)
    with pytest.raises(sp.ProfileError, match='already following'):
        sp.follow(root, signed(9, key=other))
    assert sp.follow(root, signed(3, replicas=4))['profile']['replicas'] == 4
    assert sp.follow(root, signed(1, key=other), replace=True)['issuer'] == \
        bytes(other.verify_key).hex()
    assert sp.unfollow(root) and not sp.unfollow(root)


def test_which_profile_applies(tmp_path):
    root = str(tmp_path)
    assert sp.load(root)[1] == {'name': 'stele-default', 'source': 'builtin'}
    os.makedirs(os.path.join(root, 'etc', 'stele', 'profiles'))
    with open(os.path.join(root, 'etc', 'stele', 'profiles', 'mine.json'), 'w') as f:
        json.dump({'name': 'mine', 'replicas': 1}, f)
    sp.use(root, 'mine')
    assert sp.load(root)[1] == {'name': 'mine', 'source': 'local'}
    assert sp.load(root, 'stele-strict')[1]['name'] == 'stele-strict', 'a choice wins'
    with pytest.raises(sp.ProfileError):
        sp.use(root, 'followed')                  # nothing followed: never written
    assert sp.load(root)[1]['name'] == 'mine'
    sp.follow(root, signed(1))
    sp.use(root, 'followed')
    profile, meta = sp.load(root)
    assert meta['source'] == 'followed' and meta['seq'] == 1 and profile['name'] == 'acme'


def test_a_local_profile_cannot_take_a_builtin_name_or_another_name(tmp_path):
    root = str(tmp_path)
    d = os.path.join(root, 'etc', 'stele', 'profiles')
    os.makedirs(d)
    for fname, body in (('stele-default', {'name': 'stele-default', 'replicas': 1}),
                        ('alias', {'name': 'other'})):
        with open(os.path.join(d, fname + '.json'), 'w') as f:
            json.dump(body, f)
    assert sp.load(root, 'stele-default')[0]['replicas'] == 2, 'the builtin, not the file'
    with pytest.raises(sp.ProfileError):
        sp.local(root, 'stele-default')
    with pytest.raises(sp.ProfileError):
        sp.load(root, 'alias')


def test_a_bundle_offer_applies_only_to_the_followed_issuer_and_only_newer():
    meta = {'name': 'acme', 'source': 'followed', 'issuer': bytes(KEY.verify_key).hex(),
            'seq': 2}
    assert sp.offer(meta, signed(2)) is None
    assert sp.offer(meta, signed(3, replicas=4))[0]['replicas'] == 4
    other = nacl.signing.SigningKey(bytes([4]) * 32)
    assert sp.offer(meta, signed(9, key=other)) is None
    assert sp.offer({'name': 'mine', 'source': 'local'}, signed(9)) is None
    assert sp.offer(meta, 'not a profile') is None
