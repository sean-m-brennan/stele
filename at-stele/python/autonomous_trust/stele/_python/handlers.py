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
a repo ad is accepted only from its owner, an attestation only from its
verifier, and a rebuttal only from the owner of the repo the attestation it
answers is about, each signature checked against the sender's own key; nothing
is relayed. Attesting submits a verifier-attested score about the AD'S OWNER to
the reputation process (AT doc/architecture/reputation.md, "Verifier-attested
scores"), on the channel the verifier names and in the scope of its commit.
Everything held is kept under <root>/etc/stele/ and announced to the app."""
import json
import os
import time
from dataclasses import dataclass, field
from queue import Full

from autonomous_trust.core._python.config import to_json_string, from_json_string
from autonomous_trust.core._python.network import Message
from autonomous_trust.core._python.system import CfgIds
from autonomous_trust.core._python.app_verbs import (is_local_app_verb,
                                                     refuse_remote_app_verb)
from autonomous_trust.core.reputation.reputation import AttestedScore
from autonomous_trust.core._python.app_verbs import AppEvent
from autonomous_trust.core._python.config import Configuration

from . import codec
from .protocol import SteleProtocol
from .state import ADS_CAP, ATTEST_CAP, REBUT_CAP, SCORES_CAP

#: A clean claim the owner signed and a scan contradicts. Mirrors
#: STELE_SCORE_CONTRADICTED.
SCORE_CONTRADICTED = 0.1

#: The app event kinds (at_stele.h).
EVENT_AD_HELD, EVENT_ATTESTATION_HELD, EVENT_REBUTTAL_HELD = 1110, 1111, 1112


@dataclass
class SteleEvent(AppEvent):
    """A newly held artifact, for the app. Twin of at_app_stele_t."""
    kind: int
    id: str
    owner: str = ''
    verifier: str = ''
    name: str = ''
    commit: str = ''
    verdict: str = ''
    channel: str = ''
    subject_id: str = ''
    ts: int = 0


def _store_dir(kind):
    """<root>/etc/stele/<kind>, beside AT's own etc/at. Mirrors _store_path."""
    return os.path.join(os.path.dirname(Configuration.get_cfg_dir()), 'stele', kind)


def _store(kind, item_id, env):
    """Keep a signed envelope as <kind>/<id>.json, once and atomically; failure
    costs only durability. Mirrors _store."""
    try:
        d = _store_dir(kind)
        path = os.path.join(d, '%s.json' % item_id)
        if os.path.exists(path):
            return
        os.makedirs(d, exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(env, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except (OSError, TypeError, ValueError):
        pass


def load_store(proc):
    """Reload what an earlier run kept. The files are this node's own record of
    envelopes it verified on arrival, so they are not re-verified. Mirrors
    _load_kind."""
    for kind, keys, table, cap, ident in (
            ('ads', codec.AD_KEYS, proc.stele.ads, ADS_CAP, codec.repo_ad_id),
            ('attestations', codec.ATTEST_KEYS, proc.stele.attestations,
             ATTEST_CAP, codec.attestation_id),
            ('rebuttals', codec.REBUT_KEYS, proc.stele.rebuttals, REBUT_CAP,
             codec.rebuttal_id)):
        try:
            names = sorted(os.listdir(_store_dir(kind)))
        except OSError:
            continue
        for name in names:
            if not name.endswith('.json') or len(name) != codec.DIGEST_HEX + 5:
                continue
            try:
                with open(os.path.join(_store_dir(kind), name)) as f:
                    parsed = codec.from_envelope(json.load(f), keys)
                if parsed is not None:
                    proc.stele.hold(table, ident(parsed[0]), parsed[0], cap)
            except (OSError, ValueError, KeyError, TypeError):
                continue


def _emit(proc, queues, event):
    try:
        queues[CfgIds.main].put(event, block=True, timeout=proc.q_cadence)
    except (Full, KeyError, TypeError):
        pass


def _ad_held(proc, queues, ad_id, ad, sig):
    _store('ads', ad_id, dict(ad, sig=sig))
    _emit(proc, queues, SteleEvent(EVENT_AD_HELD, ad_id, owner=ad['owner'],
                                   name=ad['name'], commit=ad['commit'],
                                   ts=ad['ts']))


def _attestation_held(proc, queues, at_id, at, sig):
    _store('attestations', at_id, dict(at, sig=sig))
    with proc.lock:
        ad = proc.stele.ads.get(at['repo_ad_id'])
    _emit(proc, queues, SteleEvent(
        EVENT_ATTESTATION_HELD, at_id, owner=ad['owner'] if ad else '',
        verifier=at['verifier'], name=ad['name'] if ad else '',
        commit=at['commit'], verdict=at['verdict'],
        channel=at.get('channel', codec.CHANNEL_PROBE),
        subject_id=at['repo_ad_id'], ts=at['ts']))


def _rebuttal_held(proc, queues, rb_id, rb, sig):
    _store('rebuttals', rb_id, dict(rb, sig=sig))
    _emit(proc, queues, SteleEvent(EVENT_REBUTTAL_HELD, rb_id, owner=rb['owner'],
                                   subject_id=rb['attestation_id'], ts=rb['ts']))


def _attested_owner(proc, at_id):
    """The owner of the repo the held attestation `at_id` is about, or None
    unless this node holds both it and its ad."""
    with proc.lock:
        at = proc.stele.attestations.get(at_id)
        ad = proc.stele.ads.get(at['repo_ad_id']) if at else None
    return ad['owner'] if ad else None


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
        _ad_held(proc, queues, ad_id, ad, sig)
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
        new = proc.stele.hold(proc.stele.attestations, digest, at, ATTEST_CAP)
    if new:
        _attestation_held(proc, queues, digest, at, sig)
    return True


def handle_rebut(proc, queues, message):
    if message.function != SteleProtocol.rebut:
        return False
    parsed = codec.from_envelope(_body(message), codec.REBUT_KEYS)
    sender = _sender(message)
    if parsed is None or not codec.rebuttal_valid(parsed[0]) or sender is None:
        proc.logger.warning('stele rebuttal malformed, refusing')
        return True
    rb, sig = parsed
    # First person, and only the owner of the repo the finding is about.
    if (rb['owner'] != str(sender.uuid)
            or not codec.verify(sender.signature.public,
                                codec.rebuttal_canonical(rb), sig)
            or _attested_owner(proc, rb['attestation_id']) != rb['owner']):
        proc.logger.warning("stele rebuttal is not the owner's reply to a held "
                            'attestation, refusing')
        return True
    rb_id = codec.rebuttal_id(rb)
    with proc.lock:
        new = proc.stele.hold(proc.stele.rebuttals, rb_id, rb, REBUT_CAP)
    if new:
        _rebuttal_held(proc, queues, rb_id, rb, sig)
    return True


def advertise_repo(proc, queues, name, url, ref, commit, seq=None,
                   description='', topics='', sbom_digest='', sbom_path='',
                   claim_verdict=codec.CLAIM_NONE):
    """The AT_APP_STELE_ADVERTISE_REPO verb: sign and multicast a v2 ad."""
    with proc.lock:
        if seq is None:
            proc.stele.ad_seq += 1
            seq = proc.stele.ad_seq
    ad = {'owner': str(proc.identity.uuid), 'name': name, 'url': url,
          'ref': ref, 'commit': commit, 'seq': int(seq), 'ts': int(time.time()),
          'v': 2, 'description': description or '', 'topics': topics or '',
          'sbom_digest': sbom_digest or '', 'sbom_path': sbom_path or '',
          'claim_verdict': claim_verdict or codec.CLAIM_NONE}
    if not codec.repo_ad_valid(ad):
        proc.logger.warning('stele advertise_repo malformed, refusing')
        return None
    canon = codec.repo_ad_canonical(ad)
    sig = codec.sign(proc.identity.signature.private, canon)
    ad_id = codec.repo_ad_id(ad)
    with proc.lock:
        new = proc.stele.hold(proc.stele.ads, ad_id, ad, ADS_CAP)
    if new:
        _ad_held(proc, queues, ad_id, ad, sig)
    _multicast(proc, queues, SteleProtocol.repo, dict(ad, sig=sig), 'a repo ad')
    return ad_id


def attest(proc, queues, owner, commit, scanner, scanner_version, db_digest,
           findings_digest, verdict, count, max_severity='',
           channel=codec.CHANNEL_PROBE, url=None, replicates=None):
    """The AT_APP_STELE_ATTEST verb. Refuses unless a verified ad from `owner`
    at `commit` is held; the subject of the score is that ad's owner. The
    channel decides what may be attested and what it scores (at_stele.h).

    A replication (`replicates` names a held attestation by ANOTHER verifier)
    re-ran that attestation's check: same commit, scanner, scanner version and
    database, about the same ad. It reports this verifier's own verdict and
    findings digest; agreeing with the original is the viewer's fold to judge,
    not this verb's."""
    channel = channel or codec.CHANNEL_PROBE
    if (channel == codec.CHANNEL_REPLICATION) != bool(replicates):
        proc.logger.warning('stele attest: a replication, and only a replication, '
                            'names the attestation it re-ran; refusing')
        return None
    with proc.lock:
        held = [(i, a) for i, a in proc.stele.ads.items()
                if a['owner'] == str(owner) and a['commit'] == commit]
        orig = proc.stele.attestations.get(replicates) if replicates else None
        orig_ad = proc.stele.ads.get(orig['repo_ad_id']) if orig else None
    if not held:
        proc.logger.warning('stele attest: no verified ad from %s at %s, '
                            'refusing', str(owner)[:8], str(commit)[:12])
        return None
    ad_id, ad = max(held, key=lambda ia: ia[1]['seq'])
    if replicates:
        if orig is None or orig_ad is None or orig_ad['owner'] != str(owner):
            proc.logger.warning('stele attest: replicates %s, which is not a held '
                                'attestation about this owner; refusing',
                                str(replicates)[:12])
            return None
        if orig['verifier'] == str(proc.identity.uuid):
            proc.logger.warning('stele attest: a verifier does not replicate '
                                'itself; refusing')
            return None
        if (orig['commit'], orig['scanner'], orig['scanner_version'],
                orig['db_digest']) != (commit, scanner, scanner_version, db_digest):
            proc.logger.warning('stele attest: a replication re-runs the same '
                                'check (commit, scanner, version, database); '
                                'refusing')
            return None
        ad_id, ad = orig['repo_ad_id'], orig_ad
    if url is not None and url != ad['url']:
        proc.logger.warning('stele attest: scanned %s, but the ad advertises %s; '
                            'refusing', url, ad['url'])
        return None
    finding = verdict == codec.VERDICT_VULN
    score = codec.SCORE_FINDING if finding else codec.SCORE_CLEAN
    if channel == codec.CHANNEL_CERTIFICATE:
        if ad.get('v') != 2 or not ad.get('sbom_digest'):
            proc.logger.warning('stele attest: a certificate needs an ad that '
                                'carries an SBOM; refusing')
            return None
    elif channel == codec.CHANNEL_SELF_CONSISTENCY:
        if ad.get('v') != 2 or ad.get('claim_verdict') != codec.VERDICT_CLEAN \
                or not finding:
            proc.logger.warning("stele attest: self_consistency needs the owner's "
                                'clean claim and a finding; refusing')
            return None
        score = SCORE_CONTRADICTED
    elif channel not in (codec.CHANNEL_PROBE, codec.CHANNEL_REPLICATION):
        proc.logger.warning("stele attest: channel '%s' is not one Stele attests "
                            'on; refusing', channel)
        return None
    try:
        scope = codec.scope(ad['owner'], ad['name'], commit, scanner)
    except (TypeError, AttributeError):
        return None
    at = {'verifier': str(proc.identity.uuid), 'repo_ad_id': ad_id,
          'commit': commit, 'scanner': scanner, 'scanner_version': scanner_version,
          'db_digest': db_digest, 'findings_digest': findings_digest,
          'verdict': verdict, 'count': int(count),
          'max_severity': max_severity or '', 'ts': int(time.time()),
          'v': 2, 'channel': channel, 'scope': scope}
    if replicates:
        at.update(v=3, replicates=replicates)
    if not codec.attestation_valid(at):
        proc.logger.warning('stele attest invalid, refusing')
        return None
    sig = codec.sign(proc.identity.signature.private,
                     codec.attestation_canonical(at))
    digest = codec.attestation_id(at)
    with proc.lock:
        new = proc.stele.hold(proc.stele.attestations, digest, at, ATTEST_CAP)
    if new:
        _attestation_held(proc, queues, digest, at, sig)
    _multicast(proc, queues, SteleProtocol.attest, dict(at, sig=sig),
               'an attestation')
    try:
        queues[CfgIds.reputation].put(
            AttestedScore(subject_uuid=ad['owner'], score=score,
                          channel=channel, evidence_digest=digest,
                          attest_scope=scope),
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
                   b.get('commit'), b.get('seq'), b.get('description', ''),
                   b.get('topics', ''), b.get('sbom_digest', ''),
                   b.get('sbom_path', ''),
                   b.get('claim_verdict', codec.CLAIM_NONE))
    return True


def handle_app_attest(proc, queues, message):
    if message.function != SteleProtocol.app_attest:
        return False
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, message.function)
    b = _body(message) or {}
    attest(proc, queues, b.get('owner'), b.get('commit'), b.get('scanner'),
           b.get('scanner_version'), b.get('db_digest'), b.get('findings_digest'),
           b.get('verdict'), b.get('count', -1), b.get('max_severity', ''),
           b.get('channel', codec.CHANNEL_PROBE), b.get('url'),
           b.get('replicates') or None)
    return True


def rebut(proc, queues, attestation_id, text):
    """The AT_APP_STELE_REBUT verb: this node, as the repo's owner, replies to
    an attestation about it. Shown, never scored."""
    if _attested_owner(proc, attestation_id) != str(proc.identity.uuid):
        proc.logger.warning("stele rebut: not a held attestation about this "
                            "node's repo; refusing")
        return None
    rb = {'owner': str(proc.identity.uuid), 'attestation_id': attestation_id,
          'text': text, 'ts': int(time.time())}
    if not codec.rebuttal_valid(rb):
        proc.logger.warning('stele rebut malformed, refusing')
        return None
    sig = codec.sign(proc.identity.signature.private, codec.rebuttal_canonical(rb))
    rb_id = codec.rebuttal_id(rb)
    with proc.lock:
        new = proc.stele.hold(proc.stele.rebuttals, rb_id, rb, REBUT_CAP)
    if new:
        _rebuttal_held(proc, queues, rb_id, rb, sig)
    _multicast(proc, queues, SteleProtocol.rebut, dict(rb, sig=sig), 'a rebuttal')
    return rb_id


def handle_app_rebut(proc, queues, message):
    if message.function != SteleProtocol.app_rebut:
        return False
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, message.function)
    b = _body(message) or {}
    rebut(proc, queues, b.get('attestation_id'), b.get('text'))
    return True
