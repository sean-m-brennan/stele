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
"""Stele's identity handlers and app verbs. Twin of at-stele/c/stele/id_stele.c:
a repo ad is accepted only from its owner and an attestation only from its
verifier, each signature checked against the sender's own key; nothing is
relayed. Attesting submits a verifier-attested score about the AD'S OWNER to
the reputation process (AT doc/architecture/reputation.md, "Verifier-attested
scores")."""
import time
from queue import Full

from autonomous_trust.core._python.config import to_json_string, from_json_string
from autonomous_trust.core._python.network import Message
from autonomous_trust.core._python.system import CfgIds
from autonomous_trust.core._python.app_verbs import (is_local_app_verb,
                                                     refuse_remote_app_verb)
from autonomous_trust.core.reputation.reputation import AttestedScore

from . import codec
from .protocol import SteleProtocol
from .state import ADS_CAP, ATTEST_CAP, SCORES_CAP


def _body(message):
    try:
        body = from_json_string(message.obj) if isinstance(message.obj, str) \
            else message.obj
    except (ValueError, TypeError):
        return None
    return body if isinstance(body, dict) else None


def _sender(message):
    who = getattr(message, 'from_whom', None)
    return who if getattr(who, 'uuid', None) is not None else None


def _multicast(proc, queues, function, env, what):
    try:
        out = Message(proc.name, function, to_json_string(env),
                      to_whom=proc.group, from_whom=proc.identity)
        queues[CfgIds.network].put(out, block=True, timeout=proc.q_cadence)
    except Full:
        proc.logger.error('stele: network queue full sending %s', what)


def handle_repo(proc, queues, message):
    if message.function != SteleProtocol.repo:
        return False
    parsed = codec.from_envelope(_body(message), codec.AD_KEYS)
    sender = _sender(message)
    if parsed is None or not codec.repo_ad_valid(parsed[0]) or sender is None:
        proc.logger.warning('stele repo ad malformed, refusing')
        return True
    ad, sig = parsed
    if ad['owner'] != str(sender.uuid):
        proc.logger.warning('stele repo ad names another owner; ads are never '
                            'relayed, refusing')
        return True
    canon = codec.repo_ad_canonical(ad)
    if not codec.verify(sender.signature.public, canon, sig):
        proc.logger.warning('stele repo ad: BAD SIGNATURE, dropping')
        return True
    ad_id = codec.repo_ad_id(ad)
    with proc.lock:
        new = proc.stele.hold(proc.stele.ads, ad_id, ad, ADS_CAP)
    if new:
        proc.logger.info('stele repo %s@%s (ad %s)', ad['name'],
                         ad['commit'][:12], ad_id[:12])
    return True


def handle_attest(proc, queues, message):
    if message.function != SteleProtocol.attest:
        return False
    parsed = codec.from_envelope(_body(message), codec.ATTEST_KEYS)
    sender = _sender(message)
    if parsed is None or not codec.attestation_valid(parsed[0]) or sender is None:
        proc.logger.warning('stele attestation malformed, refusing')
        return True
    at, sig = parsed
    if at['verifier'] != str(sender.uuid) or not codec.verify(
            sender.signature.public, codec.attestation_canonical(at), sig):
        proc.logger.warning("stele attestation is not its verifier's, refusing")
        return True
    digest = codec.attestation_id(at)
    with proc.lock:
        proc.stele.hold(proc.stele.attestations, digest, at, ATTEST_CAP)
    return True


def advertise_repo(proc, queues, name, url, ref, commit, seq=None):
    """The AT_APP_STELE_ADVERTISE_REPO verb: sign and multicast an ad."""
    with proc.lock:
        if seq is None:
            proc.stele.ad_seq += 1
            seq = proc.stele.ad_seq
    ad = {'owner': str(proc.identity.uuid), 'name': name, 'url': url,
          'ref': ref, 'commit': commit, 'seq': int(seq), 'ts': int(time.time())}
    if not codec.repo_ad_valid(ad):
        proc.logger.warning('stele advertise_repo malformed, refusing')
        return None
    canon = codec.repo_ad_canonical(ad)
    sig = codec.sign(proc.identity.signature.private, canon)
    ad_id = codec.repo_ad_id(ad)
    with proc.lock:
        proc.stele.hold(proc.stele.ads, ad_id, ad, ADS_CAP)
    _multicast(proc, queues, SteleProtocol.repo, dict(ad, sig=sig), 'a repo ad')
    return ad_id


def attest(proc, queues, owner, commit, scanner, scanner_version, db_digest,
           findings_digest, verdict, count, max_severity=''):
    """The AT_APP_STELE_ATTEST verb. Refuses unless a verified ad from `owner`
    at `commit` is held; the subject of the score is that ad's owner."""
    with proc.lock:
        held = [(i, a) for i, a in proc.stele.ads.items()
                if a['owner'] == str(owner) and a['commit'] == commit]
    if not held:
        proc.logger.warning('stele attest: no verified ad from %s at %s, '
                            'refusing', str(owner)[:8], str(commit)[:12])
        return None
    ad_id, ad = max(held, key=lambda ia: ia[1]['seq'])
    at = {'verifier': str(proc.identity.uuid), 'repo_ad_id': ad_id,
          'commit': commit, 'scanner': scanner, 'scanner_version': scanner_version,
          'db_digest': db_digest, 'findings_digest': findings_digest,
          'verdict': verdict, 'count': int(count),
          'max_severity': max_severity or '', 'ts': int(time.time())}
    if not codec.attestation_valid(at):
        proc.logger.warning('stele attest invalid, refusing')
        return None
    sig = codec.sign(proc.identity.signature.private,
                     codec.attestation_canonical(at))
    digest = codec.attestation_id(at)
    with proc.lock:
        proc.stele.hold(proc.stele.attestations, digest, at, ATTEST_CAP)
    _multicast(proc, queues, SteleProtocol.attest, dict(at, sig=sig),
               'an attestation')
    score = codec.SCORE_FINDING if verdict == codec.VERDICT_VULN \
        else codec.SCORE_CLEAN
    try:
        queues[CfgIds.reputation].put(
            AttestedScore(subject_uuid=ad['owner'], score=score,
                          channel='probe', evidence_digest=digest),
            block=True, timeout=proc.q_cadence)
    except (Full, KeyError):
        proc.logger.warning('stele attest: could not submit the attested score')
    with proc.lock:
        if len(proc.stele.scores_sent) < SCORES_CAP:
            proc.stele.scores_sent.append(
                {'subject': ad['owner'], 'score': score, 'digest': digest})
    return digest


def handle_app_advertise_repo(proc, queues, message):
    if message.function != SteleProtocol.app_advertise_repo:
        return False
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, message.function)
    b = _body(message) or {}
    advertise_repo(proc, queues, b.get('name'), b.get('url'), b.get('ref'),
                   b.get('commit'), b.get('seq'))
    return True


def handle_app_attest(proc, queues, message):
    if message.function != SteleProtocol.app_attest:
        return False
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, message.function)
    b = _body(message) or {}
    attest(proc, queues, b.get('owner'), b.get('commit'), b.get('scanner'),
           b.get('scanner_version'), b.get('db_digest'), b.get('findings_digest'),
           b.get('verdict'), b.get('count', -1), b.get('max_severity', ''))
    return True
