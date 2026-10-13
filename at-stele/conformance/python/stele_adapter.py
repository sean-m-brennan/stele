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
"""Conformance adapter for the stele extension: the identity adapter plus
Stele's fixtures, inbound builders, trigger and expected-state keys, attached
through the identity adapter's extension points. Twin of c/stele_adapter.c.

Steps:
  `stele repo`    the sender multicasts a repo ad {name, url, ref, commit, seq,
                  ts}; `owner: <pid>` names another owner (a relay) and
                  `forged_by: <pid>` signs it with another participant's key.
  `stele attest`  likewise for an attestation; `ad_owner: <pid>` plus the ad
                  fields name the ad it is about.
  `stele rebut`   the sender multicasts a rebuttal {text, ts} of the
                  attestation `about` names (a `stele_attestations` entry);
                  `owner` and `forged_by` as above.
  `trigger_stele_attest`  the step's `to` participant runs the attest verb
                  ({owner: <pid>, commit, scanner, ..., channel, url}), or,
                  with `attributes: <about spec>`, the guardian attestation.
  `stele team`    the sender multicasts the scenario's team roster
                  (`fixtures.stele_team`, overridden by the payload).
  `trigger_stele_relay`  the step's `to` participant's discovery relay store
                  (Phase 4, made at its first trigger, `rate` its rate) answers
                  {op, req} from registrant `as` (default: itself). A publish
                  item `{kind: ad|attestation, about: <about spec>}` is built
                  from the spec; any other item is passed through. Expected
                  `stele_relay_replies: [{<dotted path>: <value>}, ...]`, one per
                  trigger in order; a `#` segment is a size.
Teams (Phase 3): `stele_team: {members: [<pid>], officers: [<pid>], guardians:
[{machine, guardian}], seq, consent_by: {<pid>: <pid>}}` describes the one team
a scenario speaks of. Its root key is fixed (seed 0x07 * 32), a member's DID is
`did:key:z<pid>` and its key and node are the participant's own; `consent_by`
signs a member's consent with another participant's key (a forgery).
`stele_teams_held: [<pid>]` stages the roster as held. An ad spec with
`team: true` is a v3 ad whose release authorization is signed by
`release_signer` (default: the first officer), naming `built_by` if given.
Fixtures: `stele_ads: {<pid>: [{owner: <pid>, name, url, ref, commit, seq, ts}]}`
stages ads as held (`v: 2` adds description, topics, sbom_digest, sbom_path and
claim_verdict); `stele_attestations: {<pid>: [{verifier: <pid>, ad_owner: <pid>,
<ad fields>, verdict, count, ...}]}` stages attestations, and their ads, as
held. Expected state: `stele_ads_held`, `stele_attestations_held`,
`stele_rebuttals_held`, `stele_teams_held`, `stele_team_ads` (counts),
`stele_scores` ([{subject: <pid>, score}]).
"""
from __future__ import annotations

import json
from typing import Any

import nacl.signing

from autonomous_trust.core.config import to_json_string, from_json_string
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.network import Message
from autonomous_trust.stele import codec, team as stele_team
from autonomous_trust.stele import handlers as stele_handlers
from autonomous_trust.stele import relay as stele_relay
from autonomous_trust.stele.protocol import SteleProtocol

from conformance.harness.python.adapters.identity import IdentityAdapter, _Participant

_TRIGGER_ATTEST = 'trigger_stele_attest'
_TRIGGER_RELAY = 'trigger_stele_relay'
_RELAY_SIG = '00' * 64
#: The scenario team's root key, fixed. Mirrors the C adapter's TEAM_ROOT_SEED.
_TEAM_ROOT = nacl.signing.SigningKey(bytes([7]) * 32)
_TEAM_ISSUER = bytes(_TEAM_ROOT.verify_key).hex()
_RELEASE_AT = 1790000000
#: The scenario's team spec, set per case from `fixtures.stele_team`.
_TEAM_SPEC: dict = {}


def _did(pid):
    return 'did:key:z' + pid


def _signed(domain: bytes, body: dict, key) -> str:
    """{"body", "sig"}: a compact JSON body signed under domain."""
    text = json.dumps(body, separators=(',', ':'))
    return json.dumps({'body': text,
                       'sig': key.sign(domain + text.encode('utf-8')).signature.hex()},
                      separators=(',', ':'))


def _team_text(ident, overrides=None) -> str:
    """The scenario team's roster file; `ident(pid)` gives a participant's
    Identity. Mirrors the C adapter's _team_text."""
    spec = dict(_TEAM_SPEC, **(overrides or {}))
    consent_by = spec.get('consent_by') or {}
    members = []
    for pid in spec.get('members', []):
        me, signer = ident(pid), ident(consent_by.get(pid, pid))
        msg = stele_team.consent_message(_TEAM_ISSUER, _did(pid), str(me.uuid))
        members.append({'did': _did(pid), 'key': bytes(me.signature.public).hex(),
                        'at_uuid': str(me.uuid),
                        'consent': signer.signature.private.sign(msg).signature.hex()})
    body = {'v': 1, 'typename': 'stele-team', 'polity': 'did:key:zteam',
            'issuer': _TEAM_ISSUER, 'seq': int(spec.get('seq', 1)),
            'members': members,
            'release_officers': [_did(p) for p in spec.get('officers', [])],
            'guardians': [{'machine': _did(g['machine']), 'guardian': _did(g['guardian'])}
                          for g in spec.get('guardians', [])]}
    return _signed(stele_team.TEAM_DOMAIN, body, _TEAM_ROOT)


def _team_ad(ident, ad, spec):
    """`ad` made a v3 team ad when `spec` says `team: true`: the release
    authorization signed by `release_signer` (default the first officer).
    Mirrors the C adapter's _team_ad."""
    if not spec.get('team'):
        return ad
    signer = spec.get('release_signer') or (_TEAM_SPEC.get('officers') or [None])[0]
    who = ident(signer)
    body = {'v': 1, 'typename': 'stele-release', 'polity': 'did:key:zteam',
            'issuer': _TEAM_ISSUER, 'officer': _did(signer),
            'officer_key': bytes(who.signature.public).hex(), 'repo': ad['name'],
            'url': ad['url'], 'commit': ad['commit']}
    if spec.get('built_by'):
        body['built_by'] = _did(spec['built_by'])
    body['authorized_at'] = _RELEASE_AT
    out = dict(ad, v=3, polity=_TEAM_ISSUER,
               release_auth=_signed(stele_team.RELEASE_DOMAIN, body,
                                    who.signature.private))
    for k, dflt in (('description', ''), ('topics', ''), ('sbom_digest', ''),
                    ('sbom_path', ''), ('claim_verdict', 'none')):
        out.setdefault(k, spec.get(k, dflt))
    return out


def _uuid_of(participants, pid):
    return str(participants[pid].impl.identity.uuid)


def _ad_from(participants, spec, default_owner):
    owner = spec.get('owner')
    ad = {'owner': _uuid_of(participants, owner) if owner else default_owner,
          'name': spec.get('name', 'demo'),
          'url': spec.get('url', 'http://forge.local/demo.git'),
          'ref': spec.get('ref', 'main'),
          'commit': spec.get('commit', '0123456789abcdef0123456789abcdef01234567'),
          'seq': int(spec.get('seq', 1)), 'ts': int(spec.get('ts', 1790000000))}
    if spec.get('v') in (2, 4):
        ad.update({'v': 2, 'description': spec.get('description', ''),
                   'topics': spec.get('topics', ''),
                   'sbom_digest': spec.get('sbom_digest', ''),
                   'sbom_path': spec.get('sbom_path', ''),
                   'claim_verdict': spec.get('claim_verdict', 'none')})
    if spec.get('v') == 4:   # a solo release naming the package it publishes as
        ad.update({'v': 4, 'polity': '', 'release_auth': '',
                   'provides': spec.get('provides', '')})
    return ad


def _attestation_from(spec, ad, verifier_uuid):
    """A (v1) attestation of `ad` by `verifier_uuid`, the rest from `spec`.
    Mirrors the C adapter's _attestation_from."""
    return {'verifier': verifier_uuid, 'repo_ad_id': codec.repo_ad_id(ad),
            'commit': ad['commit'],
            'scanner': spec.get('scanner', 'osv-scanner'),
            'scanner_version': spec.get('scanner_version', '2.6.0'),
            'db_digest': spec.get('db_digest', 'cd' * 32),
            'findings_digest': spec.get('findings_digest', 'ef' * 32),
            'verdict': spec.get('verdict', 'vuln'),
            'count': int(spec.get('count', 1)),
            'max_severity': spec.get('max_severity', 'HIGH'),
            'ts': int(spec.get('ts', 1790000100))}


def _signer(participants, payload, sender_identity):
    forger = payload.get('forged_by')
    return participants[forger].impl.identity if forger else sender_identity


def _build_repo(self, participants, sender, sender_identity, *, from_id, to_id,
                function, payload):
    payload = payload if isinstance(payload, dict) else {}
    ad = _ad_from(participants, payload, str(sender_identity.uuid))
    ad = _team_ad(lambda pid: participants[pid].impl.identity, ad, payload)
    sig = codec.sign(_signer(participants, payload, sender_identity).signature.private,
                     codec.repo_ad_canonical(ad))
    return to_json_string(dict(ad, sig=sig))


def _build_team(self, participants, sender, sender_identity, *, from_id, to_id,
                function, payload):
    payload = payload if isinstance(payload, dict) else {}
    return to_json_string({'roster': _team_text(
        lambda pid: participants[pid].impl.identity, payload)})


def _build_attest(self, participants, sender, sender_identity, *, from_id, to_id,
                  function, payload):
    payload = payload if isinstance(payload, dict) else {}
    ad_owner = payload.get('ad_owner', to_id)
    ad = _ad_from(participants, dict(payload, owner=ad_owner), None)
    verifier = payload.get('verifier')
    at = _attestation_from(payload, ad, _uuid_of(participants, verifier) if verifier
                           else str(sender_identity.uuid))
    sig = codec.sign(_signer(participants, payload, sender_identity).signature.private,
                     codec.attestation_canonical(at))
    return to_json_string(dict(at, sig=sig))


def _attested_id(participants, about):
    """The id of the attestation an `about` spec (a stele_attestations fixture
    entry: verifier, ad_owner and ad fields) names."""
    ad = _ad_from(participants, dict(about, owner=about.get('ad_owner')), None)
    return codec.attestation_id(_attestation_from(
        about, ad, _uuid_of(participants, about['verifier'])))


def _build_rebut(self, participants, sender, sender_identity, *, from_id, to_id,
                 function, payload):
    payload = payload if isinstance(payload, dict) else {}
    owner = payload.get('owner')
    rb = {'owner': _uuid_of(participants, owner) if owner
          else str(sender_identity.uuid),
          'attestation_id': _attested_id(participants, payload.get('about', {})),
          'text': payload.get('text', 'a false positive'),
          'ts': int(payload.get('ts', 1790000200))}
    sig = codec.sign(_signer(participants, payload, sender_identity).signature.private,
                     codec.rebuttal_canonical(rb))
    return to_json_string(dict(rb, sig=sig))


def _build_app_attest(self, participants, sender, sender_identity, *, from_id,
                      to_id, function, payload):
    # A WIRE frame named like the app verb (the refusal case): the owner pid
    # resolved, the rest passed through.
    payload = dict(payload) if isinstance(payload, dict) else {}
    if payload.get('owner') in participants:
        payload['owner'] = _uuid_of(participants, payload['owner'])
    return to_json_string(payload)


def _fixtures(self, participant: _Participant, pid: str, fixtures: dict[str, Any],
              identities: dict[str, Identity]) -> None:
    global _TEAM_SPEC
    _TEAM_SPEC = dict(fixtures.get('stele_team') or {})
    ident = identities.__getitem__
    if pid in (fixtures.get('stele_teams_held') or []):
        t = stele_team.parse_team(_team_text(ident))
        participant.process.stele.teams[t['issuer']] = t
    for spec in (fixtures.get('stele_ads', {}) or {}).get(pid, []):
        owner = spec.get('owner')
        if owner not in identities:
            continue
        ad = _ad_from({}, dict(spec, owner=None), str(identities[owner].uuid))
        ad = _team_ad(ident, ad, spec)
        participant.process.stele.ads[codec.repo_ad_id(ad)] = ad
    for spec in (fixtures.get('stele_attestations', {}) or {}).get(pid, []):
        owner, verifier = spec.get('ad_owner'), spec.get('verifier')
        if owner not in identities or verifier not in identities:
            continue
        ad = _ad_from({}, dict(spec, owner=None), str(identities[owner].uuid))
        ad = _team_ad(ident, ad, spec)
        participant.process.stele.ads.setdefault(codec.repo_ad_id(ad), ad)
        at = _attestation_from(spec, ad, str(identities[verifier].uuid))
        participant.process.stele.attestations[codec.attestation_id(at)] = at
    stele_handlers._attribute_held(participant.process)


def _about_id(participant, about):
    """The id of the attestation an `about` spec names, its ad made a team ad
    when the spec says so."""
    ident = lambda pid: participant.peers_by_pid[pid].identity  # noqa: E731
    ad = _ad_from({}, dict(about, owner=None),
                  str(participant._uuid_for_pid(about['ad_owner'])))
    ad = _team_ad(ident, ad, about)
    return codec.attestation_id(_attestation_from(
        about, ad, str(participant._uuid_for_pid(about['verifier']))))


def _trigger_attest(self, participant: _Participant, inbound: Message):
    spec = from_json_string(inbound.obj) if inbound.obj else {}
    if isinstance(spec.get('attributes'), dict):
        stele_handlers.attest_guardian(participant.process, participant.queues,
                                       _about_id(participant, spec['attributes']))
        return participant.drain_outbox()
    owner = spec.get('owner')
    owner_uuid = participant._uuid_for_pid(owner) if owner else ''
    # `replicates`: an `about` spec (a stele_attestations fixture entry) naming
    # the attestation this one re-ran, resolved to its id. Mirrors the C
    # adapter's _stele_trigger.
    about = spec.get('replicates')
    replicates = None
    if isinstance(about, dict):
        ad = _ad_from({}, dict(about, owner=None),
                      str(participant._uuid_for_pid(about['ad_owner'])))
        replicates = codec.attestation_id(_attestation_from(
            about, ad, str(participant._uuid_for_pid(about['verifier']))))
    stele_handlers.attest(
        participant.process, participant.queues, str(owner_uuid),
        spec.get('commit', '0123456789abcdef0123456789abcdef01234567'),
        spec.get('scanner', 'osv-scanner'), spec.get('scanner_version', '2.6.0'),
        spec.get('db_digest', 'cd' * 32), spec.get('findings_digest', 'ef' * 32),
        spec.get('verdict', 'vuln'), int(spec.get('count', 1)),
        spec.get('max_severity', 'HIGH'), spec.get('channel', 'probe'),
        spec.get('url'), replicates)
    return participant.drain_outbox()


def _relay_item(participant, spec):
    """A publish item from its scenario spec. Mirrors the C adapter's
    _relay_item."""
    about = spec.get('about') if isinstance(spec, dict) else None
    if isinstance(about, dict) and spec.get('kind') in ('ad', 'attestation'):
        owner = str(participant._uuid_for_pid(about['ad_owner']))
        ad = _ad_from({}, dict(about, owner=None), owner)
        if spec['kind'] == 'ad':
            item = dict(ad, sig=_RELAY_SIG)
        else:
            item = dict(_attestation_from(about, ad,
                                          str(participant._uuid_for_pid(about['verifier']))),
                        sig=_RELAY_SIG)
        return {'kind': spec['kind'], 'item': item}
    return json.loads(json.dumps(spec))


def _trigger_relay(self, participant: _Participant, inbound: Message):
    spec = from_json_string(inbound.obj) if inbound.obj else {}
    store = getattr(participant, '_stele_relay', None)
    if store is None:
        store = participant._stele_relay = stele_relay.RelayStore(rate=spec.get('rate'))
        participant._stele_relay_replies = []
    req = json.loads(json.dumps(spec.get('req') or {}))
    if isinstance(req.get('items'), list):
        req['items'] = [_relay_item(participant, e) for e in req['items']]
    who = spec.get('as') or participant.id
    reply = store.serve(str(participant._uuid_for_pid(who)), spec.get('op', ''), req)
    participant._stele_relay_replies.append(reply)
    return participant.drain_outbox()


def _at_path(root, path):
    cur = root
    for seg in path.split('.'):
        if seg == '#':
            return len(cur) if isinstance(cur, (list, dict)) else None
        if isinstance(cur, list) and seg.lstrip('-').isdigit():
            i = int(seg)
            cur = cur[i] if -len(cur) <= i < len(cur) else None
        elif isinstance(cur, dict):
            cur = cur.get(seg)
        else:
            return None
    return cur


def _check_relay_replies(self: _Participant, key: str, expected: Any) -> None:
    got = getattr(self, '_stele_relay_replies', [])
    if len(got) != len(expected):
        raise AssertionError(f'{self.id}: {len(got)} relay repl(ies), expected {len(expected)}')
    for i, want in enumerate(expected):
        for path, value in want.items():
            if _at_path(got[i], path) != value:
                raise AssertionError(f'{self.id}: relay reply {i}: {path} = '
                                     f'{_at_path(got[i], path)!r}, expected {value!r}')


def _check_ads_held(self: _Participant, key: str, expected: Any) -> None:
    actual = len(self.process.stele.ads)
    if actual != int(expected):
        raise AssertionError(f'{self.id}: stele_ads_held={actual}, '
                             f'expected {int(expected)}')


def _check_attestations_held(self: _Participant, key: str, expected: Any) -> None:
    actual = len(self.process.stele.attestations)
    if actual != int(expected):
        raise AssertionError(f'{self.id}: stele_attestations_held={actual}, '
                             f'expected {int(expected)}')


def _check_rebuttals_held(self: _Participant, key: str, expected: Any) -> None:
    actual = len(self.process.stele.rebuttals)
    if actual != int(expected):
        raise AssertionError(f'{self.id}: stele_rebuttals_held={actual}, '
                             f'expected {int(expected)}')


def _check_teams_held(self: _Participant, key: str, expected: Any) -> None:
    actual = len(self.process.stele.teams)
    if actual != int(expected):
        raise AssertionError(f'{self.id}: stele_teams_held={actual}, '
                             f'expected {int(expected)}')


def _check_team_ads(self: _Participant, key: str, expected: Any) -> None:
    actual = len(self.process.stele.attributions)
    if actual != int(expected):
        raise AssertionError(f'{self.id}: stele_team_ads={actual}, '
                             f'expected {int(expected)}')


def _check_scores(self: _Participant, key: str, expected: Any) -> None:
    want = [(str(self._uuid_for_pid(e['subject'])), float(e['score']))
            for e in expected]
    got = [(s['subject'], float(s['score'])) for s in self.process.stele.scores_sent]
    if got != want:
        raise AssertionError(f'{self.id}: stele_scores={got}, expected {want}')


class SteleAdapter(IdentityAdapter):
    FIXTURE_HOOKS = IdentityAdapter.FIXTURE_HOOKS + (_fixtures,)
    TRIGGERS = {**IdentityAdapter.TRIGGERS, _TRIGGER_ATTEST: _trigger_attest,
                _TRIGGER_RELAY: _trigger_relay}
    INBOUND_BUILDERS = {**IdentityAdapter.INBOUND_BUILDERS,
                        SteleProtocol.repo: _build_repo,
                        SteleProtocol.attest: _build_attest,
                        SteleProtocol.rebut: _build_rebut,
                        SteleProtocol.team: _build_team,
                        SteleProtocol.app_attest: _build_app_attest}
    STATE_CHECKS = {**IdentityAdapter.STATE_CHECKS,
                    'stele_ads_held': _check_ads_held,
                    'stele_attestations_held': _check_attestations_held,
                    'stele_rebuttals_held': _check_rebuttals_held,
                    'stele_teams_held': _check_teams_held,
                    'stele_team_ads': _check_team_ads,
                    'stele_scores': _check_scores,
                    'stele_relay_replies': _check_relay_replies}
