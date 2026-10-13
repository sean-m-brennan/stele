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

from . import codec, team as teams
from .protocol import SteleProtocol
from .state import ADS_CAP, ATTEST_CAP, REBUT_CAP, SCORES_CAP, TEAMS_CAP

#: A clean claim the owner signed and a scan contradicts. Mirrors
#: STELE_SCORE_CONTRADICTED.
SCORE_CONTRADICTED = 0.1
#: The guardian of the machine that built a team release with a finding.
#: Mirrors STELE_SCORE_GUARDIAN.
SCORE_GUARDIAN = 0.45

#: The app event kinds (at_stele.h).
EVENT_AD_HELD, EVENT_ATTESTATION_HELD, EVENT_REBUTTAL_HELD = 1110, 1111, 1112
EVENT_TEAM_HELD = 1113


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


def _store_replace(kind, item_id, env):
    """Keep `env`, replacing what was there: a team's newest roster replaces
    its last. Mirrors _store_replace."""
    try:
        os.unlink(os.path.join(_store_dir(kind), '%s.json' % item_id))
    except OSError:
        pass
    _store(kind, item_id, env)


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
    # Rosters, then the attributions fixed from them on an earlier run (this
    # node's own record, after the ads they are about).
    for kind in ('teams', 'attributions'):
        try:
            names = sorted(os.listdir(_store_dir(kind)))
        except OSError:
            continue
        for name in names:
            if not name.endswith('.json') or len(name) != codec.DIGEST_HEX + 5:
                continue
            try:
                with open(os.path.join(_store_dir(kind), name)) as f:
                    env = json.load(f)
            except (OSError, ValueError):
                continue
            if kind == 'teams':
                t = teams.parse_team(env.get('roster') if isinstance(env, dict) else None)
                if t is not None:
                    _hold_team(proc, t)
            elif isinstance(env, dict) and name[:-5] in proc.stele.ads:
                attr = {k: env.get(k) for k in ATTR_KEYS}
                if all(isinstance(v, str) for v in attr.values()):
                    proc.stele.attributions[name[:-5]] = attr


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


# ---------------- teams (Phase 3, team.py) ----------------

ATTR_KEYS = ('polity', 'polity_did', 'officer', 'built_by', 'guardian', 'guardian_uuid')


def _hold_team(proc, t) -> bool:
    """Hold `t` when it is the team's first roster here or a higher seq."""
    have = proc.stele.teams.get(t['issuer'])
    if have is not None and have['seq'] >= t['seq']:
        return False
    if have is None and len(proc.stele.teams) >= TEAMS_CAP:
        return False
    proc.stele.teams[t['issuer']] = t
    return True


def _write_conflicts(proc):
    """AT's conflict set (AT ISSUES §2.54): every node each held team has EVER
    listed. Monotone, like attribution: a shorter roster must not turn a former
    teammate into an outsider, or certificates made while it was a teammate
    would fall short of the larger outside quorum wherever they are re-checked.
    The history is etc/stele/conflicts.json ({issuer: [uuid, ...]}). Mirrors
    _write_conflicts."""
    hist_path = os.path.join(os.path.dirname(_store_dir('x')), 'conflicts.json')
    try:
        with open(hist_path) as f:
            hist = json.load(f)
        if not isinstance(hist, dict):
            hist = {}
    except (OSError, ValueError):
        hist = {}
    with proc.lock:
        for issuer, t in proc.stele.teams.items():
            nodes = hist.setdefault(issuer, [])
            for m in t['members']:
                if m['at_uuid'] not in nodes:
                    nodes.append(m['at_uuid'])
    try:
        os.makedirs(os.path.dirname(hist_path), exist_ok=True)
        with open(hist_path + '.tmp', 'w') as f:
            json.dump(hist, f, indent=2, sort_keys=True)
        os.replace(hist_path + '.tmp', hist_path)
    except OSError:
        proc.logger.warning('stele: could not keep the team history')
    path = os.path.join(Configuration.get_cfg_dir(), 'attest_conflicts.cfg.json')
    try:
        tmp = path + '.tmp'
        with open(tmp, 'w') as f:
            json.dump({'teams': list(hist.values())}, f, indent=2)
        os.replace(tmp, path)
    except OSError:
        proc.logger.warning('stele: could not write the attestation conflict set')


def _key_of_node(proc, at_uuid):
    """The AT signing key (hex) this node holds for `at_uuid`, or None."""
    if str(proc.identity.uuid) == at_uuid:
        return bytes(proc.identity.signature.public).hex()
    peers = getattr(proc, 'peers', None)
    peer = peers.find_by_uuid(at_uuid) if peers is not None else None
    return bytes(peer.signature.public).hex() if peer is not None else None


def _attribution(proc, ad):
    """``(attribution, None)`` for a v3 ad a held roster accounts for, else
    ``(None, why)``. Caller holds proc.lock. Mirrors _attribution_locked."""
    rel = teams.parse_release(ad.get('release_auth')) if codec.is_team_ad(ad) else None
    if rel is None:
        return None, 'release authorization does not verify'
    if (rel['issuer'], rel['url'], rel['commit'], rel['repo']) != (
            ad['polity'], ad['url'], ad['commit'], ad['name']):
        return None, 'release authorization is for another release'
    t = proc.stele.teams.get(ad['polity'])
    if t is None:
        return None, 'no roster held for team %s' % ad['polity'][:12]
    officer = teams.member(t, did=rel['officer'])
    if officer is None or rel['officer'] not in t['officers'] \
            or officer['key'] != rel['officer_key']:
        return None, '%s is not a release officer of the team' % rel['officer'][:24]
    if officer['at_uuid'] != ad['owner']:
        return None, "the ad's owner is not the officer's node"
    g = teams.guardian_of(t, rel['built_by']) if rel['built_by'] else None
    gm = teams.member(t, did=g) if g else None
    return {'polity': ad['polity'], 'polity_did': t['polity'],
            'officer': rel['officer'], 'built_by': rel['built_by'],
            'guardian': g if gm else '',
            'guardian_uuid': gm['at_uuid'] if gm else ''}, None


def _attribute_held(proc):
    """Attribute every held, not yet attributed v3 ad the held rosters now
    account for. Once attributed, an ad stays the team's."""
    fresh = []
    with proc.lock:
        for ad_id, ad in proc.stele.ads.items():
            if not codec.is_team_ad(ad) or ad_id in proc.stele.attributions:
                continue
            attr, why = _attribution(proc, ad)
            if attr is None:
                proc.logger.debug('stele ad %s is not yet a team release: %s',
                                  ad_id[:12], why)
                continue
            proc.stele.attributions[ad_id] = attr
            fresh.append((ad_id, ad, attr))
    for ad_id, ad, attr in fresh:
        _store('attributions', ad_id, attr)
        proc.logger.info('stele team release %s@%s by %s (team %s%s)', ad['name'],
                         ad['commit'][:12], attr['officer'][:24], attr['polity'][:12],
                         ', guardian %s' % attr['guardian_uuid']
                         if attr['guardian'] else '')


def take_team(proc, queues, text, must_list, frm) -> bool:
    """Verify, hold, keep, announce and apply a roster; True when it was new.
    Held only when its root signature and every member's consent verify and
    `must_list` (a node's uuid) is a member. Mirrors _take_team."""
    t = teams.parse_team(text)
    if t is None:
        proc.logger.warning('stele team roster from %s does not verify, refusing', frm)
        return False
    if teams.member(t, at_uuid=must_list) is None:
        proc.logger.warning('stele team roster from %s does not list its sender; '
                            'rosters are never relayed, refusing', frm)
        return False
    ok, bad = teams.consents_ok(t, lambda u: _key_of_node(proc, u))
    if not ok:
        proc.logger.warning("stele team roster from %s lists %s without that node's "
                            'consent, refusing', frm, str(bad)[:8])
        return False
    with proc.lock:
        held = _hold_team(proc, t)
    if not held:
        return False
    _store_replace('teams', t['issuer'], {'roster': text})
    _write_conflicts(proc)
    _emit(proc, queues, SteleEvent(EVENT_TEAM_HELD, t['issuer'], name=t['polity'],
                                   ts=t['seq']))
    proc.logger.info('stele team %s roster seq %d from %s (%d members)',
                     t['issuer'][:12], t['seq'], frm, len(t['members']))
    _attribute_held(proc)
    return True


def handle_team(proc, queues, message):
    if message.function != SteleProtocol.team:
        return False
    sender = _sender(message)
    body = _body(message) or {}
    if sender is not None:
        take_team(proc, queues, body.get('roster'), str(sender.uuid),
                  getattr(sender, 'nickname', str(sender.uuid)[:8]))
    return True


def publish_team(proc, queues, text) -> bool:
    """The AT_APP_STELE_PUBLISH_TEAM verb: hold the roster here first, so one
    this node cannot verify never goes out, then multicast it. A roster already
    held is sent again: a member that joined since needs it."""
    me = str(proc.identity.uuid)
    take_team(proc, queues, text, me, 'this node')
    t = teams.parse_team(text)
    with proc.lock:
        have = proc.stele.teams.get(t['issuer']) if t else None
        mine = (have is not None and have['seq'] == t['seq']
                and teams.member(have, at_uuid=me) is not None)
    if mine:
        _multicast(proc, queues, SteleProtocol.team, {'roster': text}, 'a team roster')
    return mine


def handle_app_publish_team(proc, queues, message):
    if message.function != SteleProtocol.app_publish_team:
        return False
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, message.function)
    publish_team(proc, queues, (_body(message) or {}).get('roster'))
    return True


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
        if codec.is_team_ad(ad):
            _attribute_held(proc)
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
                   claim_verdict=codec.CLAIM_NONE, polity=None, release_auth=None,
                   provides=None):
    """The AT_APP_STELE_ADVERTISE_REPO verb: sign and multicast a v2 ad, a v3
    one (a team release) when `polity` or `release_auth` is given, or a v4 one
    when `provides` (the package the repo publishes as) is given."""
    with proc.lock:
        if seq is None:
            proc.stele.ad_seq += 1
            seq = proc.stele.ad_seq
    ad = {'owner': str(proc.identity.uuid), 'name': name, 'url': url,
          'ref': ref, 'commit': commit, 'seq': int(seq), 'ts': int(time.time()),
          'v': 2, 'description': description or '', 'topics': topics or '',
          'sbom_digest': sbom_digest or '', 'sbom_path': sbom_path or '',
          'claim_verdict': claim_verdict or codec.CLAIM_NONE}
    if polity is not None or release_auth is not None:
        ad.update(v=3, polity=polity, release_auth=release_auth)
    if provides is not None:
        ad.update(v=4, polity=ad.get('polity') or '',
                  release_auth=ad.get('release_auth') or '', provides=provides)
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
        if codec.is_team_ad(ad):
            _attribute_held(proc)
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
    # The newest: highest seq, then latest ts (a re-advertised commit at the
    # same seq means the owner's last ad). Mirrors C _find_ad.
    ad_id, ad = max(held, key=lambda ia: (ia[1]['seq'], ia[1]['ts']))
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
        # A provides check answers the ad's package claim; every other
        # certificate checks the SBOM the ad carries.
        if scanner == codec.SCANNER_PROVIDES:
            if ad.get('v') != 4 or not ad.get('provides'):
                proc.logger.warning('stele attest: a provides check needs an ad '
                                    'that names a package; refusing')
                return None
        elif ad.get('v') not in (2, 3, 4) or not ad.get('sbom_digest'):
            proc.logger.warning('stele attest: a certificate needs an ad that '
                                'carries an SBOM; refusing')
            return None
    elif channel == codec.CHANNEL_SELF_CONSISTENCY:
        if ad.get('v') not in (2, 3, 4) or ad.get('claim_verdict') != codec.VERDICT_CLEAN \
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


def attest_guardian(proc, queues, attributes):
    """Land the held finding `attributes` on the guardian of the machine that
    built its team release: a v4 attestation restating it, about the same ad,
    scored SCORE_GUARDIAN against the guardian's node. Mirrors
    _attest_guardian."""
    with proc.lock:
        orig = proc.stele.attestations.get(attributes) if attributes else None
        ad = proc.stele.ads.get(orig['repo_ad_id']) if orig else None
        attr = proc.stele.attributions.get(orig['repo_ad_id']) if orig else None
    if orig is None or ad is None:
        proc.logger.warning('stele attest: attributes %s, which is not a held '
                            'attestation; refusing', str(attributes)[:12])
        return None
    if orig['verdict'] != codec.VERDICT_VULN or orig.get('v') == 4:
        proc.logger.warning('stele attest: only a finding is attributed to a '
                            'guardian; refusing')
        return None
    if attr is None or not attr['guardian_uuid']:
        proc.logger.warning('stele attest: %s@%s is not a team release built by a '
                            'guarded machine; refusing', ad['name'], ad['commit'][:12])
        return None
    guardian = attr['guardian_uuid']
    if guardian == str(proc.identity.uuid):
        proc.logger.warning('stele attest: a guardian does not attest itself; '
                            'refusing')
        return None
    at = {k: orig[k] for k in codec.ATTEST_KEYS}
    at.update(verifier=str(proc.identity.uuid), repo_ad_id=orig['repo_ad_id'],
              ts=int(time.time()), v=4, channel=codec.CHANNEL_PROBE,
              scope=codec.scope(guardian, ad['name'], orig['commit'], orig['scanner']),
              attributes=attributes, guardian_of=attr['built_by'])
    if not codec.attestation_valid(at):
        proc.logger.warning('stele attest (guardian) invalid, refusing')
        return None
    sig = codec.sign(proc.identity.signature.private, codec.attestation_canonical(at))
    digest = codec.attestation_id(at)
    with proc.lock:
        new = proc.stele.hold(proc.stele.attestations, digest, at, ATTEST_CAP)
    if new:
        _attestation_held(proc, queues, digest, at, sig)
    _multicast(proc, queues, SteleProtocol.attest, dict(at, sig=sig), 'an attestation')
    try:
        queues[CfgIds.reputation].put(
            AttestedScore(subject_uuid=guardian, score=SCORE_GUARDIAN,
                          channel=codec.CHANNEL_PROBE, evidence_digest=digest,
                          attest_scope=at['scope']),
            block=True, timeout=proc.q_cadence)
    except (Full, KeyError):
        proc.logger.warning('stele attest: could not submit the attested score')
    with proc.lock:
        if len(proc.stele.scores_sent) < SCORES_CAP:
            proc.stele.scores_sent.append(
                {'subject': guardian, 'score': SCORE_GUARDIAN, 'digest': digest})
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
                   b.get('claim_verdict', codec.CLAIM_NONE),
                   b.get('polity'), b.get('release_auth'), b.get('provides'))
    return True


def handle_app_attest(proc, queues, message):
    if message.function != SteleProtocol.app_attest:
        return False
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, message.function)
    b = _body(message) or {}
    if 'attributes' in b:
        attest_guardian(proc, queues, b.get('attributes'))
        return True
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
