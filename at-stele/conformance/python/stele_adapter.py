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
                  ({owner: <pid>, commit, scanner, ..., channel, url}).
Fixtures: `stele_ads: {<pid>: [{owner: <pid>, name, url, ref, commit, seq, ts}]}`
stages ads as held (`v: 2` adds description, topics, sbom_digest, sbom_path and
claim_verdict); `stele_attestations: {<pid>: [{verifier: <pid>, ad_owner: <pid>,
<ad fields>, verdict, count, ...}]}` stages attestations, and their ads, as
held. Expected state: `stele_ads_held`, `stele_attestations_held`,
`stele_rebuttals_held` (counts), `stele_scores` ([{subject: <pid>, score}]).
"""
from __future__ import annotations

from typing import Any

from autonomous_trust.core.config import to_json_string, from_json_string
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.network import Message
from autonomous_trust.stele import codec
from autonomous_trust.stele import handlers as stele_handlers
from autonomous_trust.stele.protocol import SteleProtocol

from conformance.harness.python.adapters.identity import IdentityAdapter, _Participant

_TRIGGER_ATTEST = 'trigger_stele_attest'


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
    if spec.get('v') == 2:
        ad.update({'v': 2, 'description': spec.get('description', ''),
                   'topics': spec.get('topics', ''),
                   'sbom_digest': spec.get('sbom_digest', ''),
                   'sbom_path': spec.get('sbom_path', ''),
                   'claim_verdict': spec.get('claim_verdict', 'none')})
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
    sig = codec.sign(_signer(participants, payload, sender_identity).signature.private,
                     codec.repo_ad_canonical(ad))
    return to_json_string(dict(ad, sig=sig))


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
    for spec in (fixtures.get('stele_ads', {}) or {}).get(pid, []):
        owner = spec.get('owner')
        if owner not in identities:
            continue
        ad = _ad_from({}, dict(spec, owner=None), str(identities[owner].uuid))
        participant.process.stele.ads[codec.repo_ad_id(ad)] = ad
    for spec in (fixtures.get('stele_attestations', {}) or {}).get(pid, []):
        owner, verifier = spec.get('ad_owner'), spec.get('verifier')
        if owner not in identities or verifier not in identities:
            continue
        ad = _ad_from({}, dict(spec, owner=None), str(identities[owner].uuid))
        participant.process.stele.ads.setdefault(codec.repo_ad_id(ad), ad)
        at = _attestation_from(spec, ad, str(identities[verifier].uuid))
        participant.process.stele.attestations[codec.attestation_id(at)] = at


def _trigger_attest(self, participant: _Participant, inbound: Message):
    spec = from_json_string(inbound.obj) if inbound.obj else {}
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


def _check_scores(self: _Participant, key: str, expected: Any) -> None:
    want = [(str(self._uuid_for_pid(e['subject'])), float(e['score']))
            for e in expected]
    got = [(s['subject'], float(s['score'])) for s in self.process.stele.scores_sent]
    if got != want:
        raise AssertionError(f'{self.id}: stele_scores={got}, expected {want}')


class SteleAdapter(IdentityAdapter):
    FIXTURE_HOOKS = IdentityAdapter.FIXTURE_HOOKS + (_fixtures,)
    TRIGGERS = {**IdentityAdapter.TRIGGERS, _TRIGGER_ATTEST: _trigger_attest}
    INBOUND_BUILDERS = {**IdentityAdapter.INBOUND_BUILDERS,
                        SteleProtocol.repo: _build_repo,
                        SteleProtocol.attest: _build_attest,
                        SteleProtocol.rebut: _build_rebut,
                        SteleProtocol.app_attest: _build_app_attest}
    STATE_CHECKS = {**IdentityAdapter.STATE_CHECKS,
                    'stele_ads_held': _check_ads_held,
                    'stele_attestations_held': _check_attestations_held,
                    'stele_rebuttals_held': _check_rebuttals_held,
                    'stele_scores': _check_scores}
