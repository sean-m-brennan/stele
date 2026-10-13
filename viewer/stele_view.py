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
"""stele_view: a repository's safety standing, as the viewer's own node sees it.

The trust panel (../extension) asks this service, which runs beside the
VIEWER'S steled and reads only that node's files. Nothing the forge serves is
evidence: the forge page tells the panel which repository it is looking at,
and that is all.

What it reads, under the node's root:

* ``etc/at/attested/<task>.json``: AutonomousTrust's durable records of
  verifier-attested entries, one per entry a quorum-signed checkpoint covers.
  Each is checked with AT's own ``verify_attested_record`` AGAINST THE NODE'S
  ROSTER (``etc/at/roster.cfg.json``, AT's ``load_anchor``): every key comes
  from the roster and none from the record, the checkpoint must be this
  group's, each quorum counts against at least three members, and where the
  node holds the same checkpoint the roots must match (``linked``). Then the
  entry is in the checkpoint's window, the checkpoint carries a quorum, and the
  attestation carries its verifier plus a strict majority of the other members,
  the subject's signature never counted. A record that does not verify is left
  out and counted as ``unverified``, with its reasons. A node with no roster
  verifies nothing.
* ``etc/stele/{ads,attestations,rebuttals}``: the signed Stele artifacts the
  node holds. A record's evidence digest is the id of the attestation it
  certifies; that attestation names the ad, and the ad names the repository.

**The standing.** For a repository (an owner's name), the newest commit it
advertised is the one shown. Its CHECKS are (scanner, channel) pairs; each
holds every verified result for it, the latest per verifier, with a
replication filed under the check it replicates. No single verifier is
authoritative (Phase 2): a verifier COUNTS only at tier 3 or above in this
node's roster (``--tier``), and a check is CONFIRMED when ``--replicas`` (2)
counted verifiers report the same findings digest. Findings are asymmetric:

* a confirmed finding makes the repository **failing**, its score the lowest
  finding's (0.3, or 0.1 for a contradicted claim). A failure never fades: it
  is answered by a clean scan of a newer commit, which is evidence, never by
  waiting;
* counted verifiers that disagree make it **disputed**;
* a finding nobody counted has confirmed, a single verifier's or one below
  the tier, makes it **failing-unconfirmed**;
* clean but short of the replicas is **single-source**;
* all checks clean and confirmed is clean at 0.8, fading toward unknown with
  AT's decay shape: nothing for a day, then a 30-day half-life toward 0.21.
  Above 0.6 it is **verified-safe**, above 0.3 **aging**, and below that
  **unknown**;
* no verified attestation of the newest commit is **unknown** (neutral, never
  branded unsafe), with what earlier commits showed noted beside it.

Only verified-safe is green. A verifier below the tier is shown but never
counted, so the subject's own fresh node can neither dispute a finding nor
confirm a clean bill.

**Bundles.** Someone else may hand over records, the owner's forge
(``.stele/standing.json``) included. ``POST /verify`` folds a bundle in for
that one answer, writing nothing: ads and attestations are filed under the id
their content hashes to, and only records that verify against THIS node's
roster count. A bundle of the owner's own making verifies on its own terms
and not on these.

Each check carries its committed reason (scanner, channel, count, worst
severity, verifier, checkpoint epoch) and the owner's rebuttal when there is
one. The rebuttal is shown, never scored.

**Teams (Phase 3).** A team is an Ethne polity, known here by the roster its
root key signed (``etc/stele/teams/<issuer>.json``), held when the signature
and every member node's consent verify against THIS node's roster. A record
about a team's member is verified with the member's teammates left out
(``verify_attested_record(..., exclude=...)``, AT ISSUES §2.54), from this
node's own copy of the roster and never from the record. A repository is the
team's when the node attributed one of its releases to the team
(``etc/stele/attributions``, fixed once and never undone). The TEAM STANDING is
the worst of its repositories' standings and its members' own repositories'
standings, in the order failing, failing-unconfirmed, disputed, unknown,
single-source, aging, verified-safe: one confirmed finding anywhere makes the
team failing. Its concerns are the verified findings, the guardian's included;
every one is signed by the verifier that found it, never by the team.

**Profiles (Phase 4).** All of the above is ``stele-default``, Stele's own
reading. A PROFILE (stele_profile.py) is another reading of the same facts: how
many counted verifiers must agree and at what tier, which checks must be
present and which are set aside, the severity below which a finding is a
concern rather than a failure, how fast a clean reading fades, and whether a
repository stands no better than its team. A profile is built in, the
consumer's own, or a polity's signed profile the consumer follows (Ethne
D42). It relaxes Stele's reading only inside floors: a counted confirmed
finding is never green, a critical one always counts, a failure never fades,
and a standing with nothing counted is unknown. Every answer names the profile
it was read under, and every set-aside check is shown with its reason.

**Supply chain (Phase 4).** A repository's DEPENDENCIES are the components of
the SBOM its ad pins, which this node must hold (stele_deps.py: the verifier
that checked it keeps it, as do ``stele_ctl sbom-add`` and ``sbom-fetch``, and
a bundle may carry it). Each dependency is a purl. It RESOLVES to the
repositories whose v4 ads say they publish that package (``provides``) and
whose ``provides`` check counted verifiers confirmed clean, or to the
repositories the reader pinned it to (``etc/stele/deps-map.json``), which
replace every claimant. Of each, the ad whose ref names the version the purl
pins (``v1.2.0`` or ``1.2.0``; a Go pseudo-version by its commit) is the one
read, with its own dependencies, to a depth of 8 and never round a cycle. A
dependency several repositories claim stands at the worst of them, so a
squatter can lower it and never raise it; a pin is the reader's answer to a
squatter. A dependency that is not on Stele, a version no held ad names, a
claim no counted verifier confirmed, and an SBOM this node does not hold are
all shown and never folded: the repository's own OSV probe already covers the
known vulnerabilities in what Stele cannot read. Under ``deps: worst`` (a
profile field, ``stele-strict``'s) a repository stands no better than its
worst resolved dependency (``capped_by_deps``); under ``show`` it is read
beside it.

**Discovery relays (Phase 4).** Relays index claims from every group, not
only this node's: ads, attestations, records and anchors that anyone
published (at-stele/c/stele/stele_relay.h). A record from another group
verifies only under the GROUP ANCHOR of a polity this reader follows (Ethne
D43, stele_anchors.py): the anchor supplies that group's keys and tiers, a
verifier counts at the tier the anchor states under this reader's profile, and
the answer names the polity (``anchored_by``) and how many of the checkpoints
the group signed since the first record shown came with a record about the
repository. A relay's own ranking is shown beside, as its word, never as a
verdict; a repository whose group this reader does not follow is listed and
unverified.

  stele_view.py --root VIEWER_ROOT [--port 8099]

  stele_view.py --root VIEWER_ROOT [--profile NAME|followed]

  Every endpoint but /health takes ?profile=NAME|followed for that answer.

  GET /standing?url=<clone url>   the standing of the repository at that URL
  POST /verify?url=<clone url>    the same, with a bundle (JSON body) folded in
  GET /search?q=<text>            heard repositories matching the text, best
                                  standing first (local only; no global index)
  GET /team?polity=<issuer hex>   a team's standing, repositories and concerns
  GET /teams?q=<text>             heard teams matching the text (separate from
                                  /search, which lists repositories)
  GET /relay/search?q=<text>      what the node's discovery relays found, each
                                  relay's own word beside what this node verified
  GET /relay/standing?url=<url>   the claims the relays hold about the repository,
                                  folded in and verified here (?fresh=0: the
                                  node's last answer, without asking again)
  GET /health                     liveness
  GET /                           a page for people: search, and a URL lookup
"""
import glob
import hashlib
import json
import math
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
AT_PY = os.environ.get('AT_PYTHON') or os.path.normpath(os.path.join(
    HERE, '..', '..', '..', 'lib', 'autonomous_trust', 'src', 'autonomous-trust'))
STELE_PY = os.path.normpath(os.path.join(HERE, '..', 'at-stele', 'python'))
for _p in (STELE_PY, AT_PY, HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import stele_anchors  # noqa: E402
import stele_deps  # noqa: E402
import stele_profile  # noqa: E402  (after the path setup, like the AT imports)

#: How deep a dependency's own dependencies are read (Phase 4).
DEPS_DEPTH = 8

#: Scores and the decay shape (CODE_SHARING_PLAN §4.3; user decision
#: 2026-10-05: 30-day half-life, one-day onset).
SCORE_CLEAN = 0.8
DECAY_ASYMPTOTE = 0.21
DECAY_ONSET = 86400.0
DECAY_HALF_LIFE = 30 * 86400.0
SAFE_FLOOR = 0.6
AGING_FLOOR = 0.3

#: The bundle a forge or peer may hand over (BUNDLE: records + artifacts).
BUNDLE_SCHEMA = 'stele-bundle-1'
BUNDLE_MAX = 4 << 20

STATE_ORDER = {'verified-safe': 0, 'aging': 1, 'single-source': 2, 'unknown': 3,
               'disputed': 4, 'failing-unconfirmed': 5, 'failing': 6}


def worst_state(states):
    """The worst of ``states`` by STATE_ORDER; 'unknown' for none."""
    states = [st for st in states if st in STATE_ORDER]
    return max(states, key=STATE_ORDER.get) if states else 'unknown'


def decayed(score: float, idle: float, onset: float = DECAY_ONSET,
            half_life: float = DECAY_HALF_LIFE) -> float:
    """AT's decay shape (reputation_decayed_score) with Stele's parameters (a
    profile's, when it sets them): a score above the asymptote fades toward it
    once idle past the onset; one at or below it never moves, so a failure
    never fades under any profile."""
    if score <= DECAY_ASYMPTOTE or idle <= onset:
        return score
    return DECAY_ASYMPTOTE + (score - DECAY_ASYMPTOTE) * math.pow(
        0.5, (idle - onset) / half_life)


def _load_dir(path):
    out = {}
    for f in glob.glob(os.path.join(path, '*.json')):
        try:
            with open(f) as fh:
                out[os.path.basename(f)[:-5]] = json.load(fh)
        except (OSError, ValueError):
            continue
    return out


#: A check is CONFIRMED once this many distinct verifiers at or above
#: REPLICA_TIER (in the viewer node's own roster) report the same findings
#: digest for it (user decision 2026-10-05: N = 2, tier 3).
REPLICAS = 2
REPLICA_TIER = 3


def _check_state(results, replicas):
    """One check's state from its verified results, ``[(verifier, eligible,
    verdict, findings_digest, ts)]``, latest per verifier.

    Findings are asymmetric: any finding blocks green. A finding is CONFIRMED
    when ``replicas`` eligible verifiers report the same digest for it, even
    over a dissent; an eligible verifier's clean result against another's
    finding makes the check DISPUTED; a finding nobody eligible has confirmed
    (including findings that differ in detail) is UNCONFIRMED. A clean result
    is CONFIRMED only with ``replicas`` eligible verifiers agreeing on its
    digest, and SINGLE-SOURCE short of that. A verifier below the tier is shown but
    never counted, so the subject's own fresh node cannot dispute a finding or
    confirm a clean bill."""
    eligible = [r for r in results if r[1]]
    by_digest = {}
    for r in eligible:
        by_digest.setdefault((r[2], r[3]), set()).add(r[0])
    vuln = [(len(v), k) for k, v in by_digest.items() if k[0] == 'vuln']
    clean = [(len(v), k) for k, v in by_digest.items() if k[0] == 'clean']
    if vuln and max(vuln)[0] >= replicas:
        return 'confirmed-finding', max(vuln)[0]
    if vuln and clean:
        return 'disputed', max(n for n, _ in vuln + clean)
    if vuln or any(r[2] == 'vuln' for r in results):
        return 'unconfirmed-finding', max(vuln)[0] if vuln else 0
    n = max(clean)[0] if clean else 0
    return ('confirmed-clean' if n >= replicas else 'single-source'), n


def _stopped_short(st):
    """Whether a standing's dependency reading stopped at a cycle or the
    depth, anywhere below it."""
    return any(c.get('status') in ('cycle', 'too-deep') or c.get('partial')
               for item in (st.get('deps') or {}).get('items', ())
               for c in item['claimants'])


class NodeView:
    """Everything the standing is folded from, read fresh from one node root,
    plus any records a bundle brought (:meth:`add_bundle`)."""

    def __init__(self, root, replicas=None, tier=None, profile=None):
        """``profile`` is a choice for :func:`stele_profile.load` (a name, or
        ``followed``), a ``(profile, meta)`` pair already loaded, or None for
        the node's own preference. ``replicas`` and ``tier`` override the
        profile's (the operator's ``--replicas``/``--tier``), and the override
        is named in every answer. Raises ``stele_profile.ProfileError`` for a
        choice that cannot be applied."""
        from autonomous_trust.core.reputation.reputation import load_anchor
        self.root = root
        if isinstance(profile, tuple):
            self.profile, self.profile_meta = profile[0], dict(profile[1])
        else:
            self.profile, self.profile_meta = stele_profile.load(root, profile)
        self._override(replicas, tier)
        stele = os.path.join(root, 'etc', 'stele')
        self.ads = _load_dir(os.path.join(stele, 'ads'))
        self.attestations = _load_dir(os.path.join(stele, 'attestations'))
        self.rebuttals = _load_dir(os.path.join(stele, 'rebuttals'))
        # The trust anchor: this node's own roster (AT roster.cfg.json). A
        # record is checked against the keys and group THIS node holds, never
        # against the keys it carries, which a forger would write too.
        self.anchor = load_anchor(root)
        # Teams: rosters this view verified itself, and the node's own record of
        # which releases it attributed to them (fixed once, never undone).
        self.teams = {}          # issuer -> team (team.parse_team)
        for env in _load_dir(os.path.join(stele, 'teams')).values():
            self._take_team(env.get('roster') if isinstance(env, dict) else None)
        self.attributions = {k: v for k, v in
                             _load_dir(os.path.join(stele, 'attributions')).items()
                             if isinstance(v, dict) and k in self.ads}
        # Every node each team has ever listed, as the node kept it: a former
        # teammate stays one (the node's own record, like the attributions).
        try:
            with open(os.path.join(stele, 'conflicts.json')) as f:
                hist = json.load(f)
        except (OSError, ValueError):
            hist = {}
        self.team_history = {k: set(v) for k, v in (hist or {}).items()
                             if isinstance(v, list)}
        self._attribute()
        # Supply chain (Phase 4): this reader's pins, and SBOMs a bundle carried.
        self.deps_map = stele_deps.load_map(root)
        self.sboms = {}          # sha256 -> parsed SBOM, for this view only
        self._dep_memo = {}
        # Other groups (Phase 4, discovery relays): the polities this reader
        # follows, whose group anchors supply the keys and tiers of groups it
        # is not in (Ethne D43). {issuer: (anchor, text)}.
        self.anchors = stele_anchors.followed(root)
        self.verified = {}       # attestation id -> {epoch, score, channel, linked, via}
        self.unverified = 0
        self.unverified_reasons = []
        for rec in _load_dir(os.path.join(root, 'etc', 'at', 'attested')).values():
            self._take_record(rec)

    def _override(self, replicas, tier):
        """Apply the operator's --replicas/--tier on top of the profile, inside
        the same floors, and say so in the profile block."""
        over = {k: int(v) for k, v in (('replicas', replicas), ('tier', tier))
                if v is not None and int(v) != self.profile[k]}
        if over:
            self.profile = stele_profile.parse(dict(self.profile, **over))
            self.profile_meta['overrides'] = over
        self.replicas, self.tier = self.profile['replicas'], self.profile['tier']

    def _take_team(self, text):
        """Hold a roster when its root signature and every member's consent
        verify against this node's roster, and it is the team's newest here."""
        from autonomous_trust.stele import team
        t = team.parse_team(text)
        if t is None or self.anchor is None:
            return False
        keys = {u: str(m.get('pubkey')) for u, m in self.anchor['members'].items()}
        ok, _bad = team.consents_ok(t, keys.get)
        have = self.teams.get(t['issuer'])
        if not ok or (have is not None and have['seq'] >= t['seq']):
            return False
        self.teams[t['issuer']] = t
        return True

    def _attribute(self):
        """Attribute held v3 ads that a held roster accounts for and the node
        has not (a bundle's, typically). Mirrors the node's _attribution."""
        from autonomous_trust.stele import team
        from autonomous_trust.stele import codec
        for ad_id, ad in self.ads.items():
            if not codec.is_team_ad(ad) or ad_id in self.attributions:
                continue
            rel = team.parse_release(ad.get('release_auth'))
            t = self.teams.get(ad.get('polity'))
            if rel is None or t is None or (rel['issuer'], rel['url'], rel['commit'],
                                             rel['repo']) != (ad['polity'], ad['url'],
                                                              ad['commit'], ad['name']):
                continue
            officer = team.member(t, did=rel['officer'])
            if (officer is None or rel['officer'] not in t['officers']
                    or officer['key'] != rel['officer_key']
                    or officer['at_uuid'] != ad.get('owner')):
                continue
            g = team.guardian_of(t, rel['built_by']) if rel['built_by'] else None
            gm = team.member(t, did=g) if g else None
            self.attributions[ad_id] = {
                'polity': ad['polity'], 'polity_did': t['polity'],
                'officer': rel['officer'], 'built_by': rel['built_by'],
                'guardian': g if gm else '', 'guardian_uuid': gm['at_uuid'] if gm else ''}

    def teammates(self, node):
        """The nodes that share a team with ``node``, now or before (AT ISSUES
        §2.54): the held rosters and every node the node's history says a team
        ever listed. Monotone, as AT's conflict set is."""
        out = set()
        for issuer in set(self.teams) | set(self.team_history):
            nodes = set(self.team_history.get(issuer, ()))
            if issuer in self.teams:
                nodes |= {m['at_uuid'] for m in self.teams[issuer]['members']}
            if node in nodes:
                out |= nodes - {node}
        return out

    def _take_record(self, rec, source='node'):
        """Verify one record against the anchor and keep it when it certifies a
        held attestation about its ad's owner. Returns True when kept."""
        from autonomous_trust.core.reputation.reputation import verify_attested_record
        entry = (rec or {}).get('entry') or {}
        mates = sorted(self.teammates(str(entry.get('subject_id'))))
        if self.anchor is None:
            ok, why, details = False, ['this node has no roster to verify against'], {}
        else:
            details = {}
            # The subject's teammates witness nothing about it, by THIS node's
            # roster of the team, never the record's own `excluded` list.
            ok, why = verify_attested_record(rec, self.anchor, details, exclude=mates)
        via = None
        if not ok:
            # Another group's record: only under the anchor of a polity this
            # reader follows, and only one that lists the record's subject.
            from autonomous_trust.stele import anchor as group_anchor
            subject = str(entry.get('subject_id'))
            for issuer, (a, _text) in sorted(self.anchors.items()):
                if subject not in {m['at_uuid'] for m in a['members']}:
                    continue
                d2 = {}
                ok2, _why2 = verify_attested_record(rec, group_anchor.to_at_anchor(a), d2,
                                                    exclude=mates)
                if ok2:
                    ok, why, details, via = True, [], d2, issuer
                    break
        digest = entry.get('evidence_digest')
        if not ok:
            self.unverified += 1
            self.unverified_reasons.append({'task': entry.get('task_id'),
                                            'source': source, 'reasons': why})
            return False
        if digest not in self.attestations:
            return False
        at = self.attestations[digest]
        ad = self.ads.get(at.get('repo_ad_id'))
        # The certified score must be about the ad's owner: a record about
        # somebody else cannot vouch for this repository. A guardian
        # attestation (v4) is about the guardian the node attributed.
        about = ad.get('owner') if ad is not None else None
        if at.get('v') == 4:
            about = (self.attributions.get(at.get('repo_ad_id')) or {}).get('guardian_uuid')
        if ad is None or not about or entry.get('subject_id') != about:
            return False
        self.verified[digest] = {
            'epoch': (rec.get('checkpoint') or {}).get('epoch'),
            'score': entry.get('p1_score'),
            'channel': entry.get('p1_channel'),
            'linked': bool(details.get('linked')), 'source': source, 'via': via}
        return True

    def add_bundle(self, bundle):
        """Fold in a STANDING BUNDLE that someone else hands over (the owner's
        forge, a peer): ``{"records": [...], "attestations": [envelope, ...],
        "ads": [envelope, ...], "sboms": {sha256: text}}``. An SBOM is taken
        only when its text hashes to its name. Ads and attestations are taken by CONTENT:
        each is filed under the id its canonical bytes hash to, so a record
        that verifies against this node's anchor binds exactly the attestation
        it names, and that attestation the ad. Nothing is written to the node.
        Returns ``{"verified": n, "unverified": [reasons]}``."""
        from autonomous_trust.stele import codec
        before = len(self.unverified_reasons)
        if not isinstance(bundle, dict):
            return {'verified': 0, 'unverified': [{'reasons': ['not a bundle']}]}
        for text in bundle.get('teams') or []:
            self._take_team(text)
        # A newer profile from the issuer this node follows, for this answer
        # only (stele_profile.offer); anything else in the slot is ignored.
        taken = stele_profile.offer(self.profile_meta, bundle.get('profile'))
        if taken is not None:
            over = self.profile_meta.get('overrides') or {}
            self.profile, self.profile_meta = taken[0], taken[1]
            self.profile_meta.pop('overrides', None)
            self._override(over.get('replicas'), over.get('tier'))
        for env in bundle.get('ads') or []:
            parsed = codec.from_envelope(env, codec.AD_KEYS)
            if parsed and codec.repo_ad_valid(parsed[0]):
                self.ads.setdefault(codec.repo_ad_id(parsed[0]), dict(env))
        for env in bundle.get('attestations') or []:
            parsed = codec.from_envelope(env, codec.ATTEST_KEYS)
            if parsed and codec.attestation_valid(parsed[0]):
                self.attestations.setdefault(codec.attestation_id(parsed[0]),
                                             dict(env))
        for env in bundle.get('rebuttals') or []:
            parsed = codec.from_envelope(env, codec.REBUT_KEYS)
            if parsed and codec.rebuttal_valid(parsed[0]):
                self.rebuttals.setdefault(codec.rebuttal_id(parsed[0]), dict(env))
        # A newer anchor from a polity this reader follows, for this answer
        # only; an anchor from anyone else is not believed (stele_anchors.offer).
        for text in bundle.get('anchors') or []:
            stele_anchors.offer(self.anchors, text)
        sboms = bundle.get('sboms')
        for digest, text in (sboms.items() if isinstance(sboms, dict) else ()):
            if not isinstance(text, str):
                continue
            raw = text.encode('utf-8')
            if hashlib.sha256(raw).hexdigest() != digest:
                continue
            try:
                sbom = json.loads(raw)
            except ValueError:
                continue
            if isinstance(sbom, dict):
                self.sboms[digest] = sbom
        self._dep_memo.clear()
        self._attribute()
        kept = sum(1 for rec in bundle.get('records') or []
                   if isinstance(rec, dict) and self._take_record(rec, 'bundle'))
        return {'verified': kept, 'unverified': self.unverified_reasons[before:]}

    def _eligible(self, verifier, via=None):
        """Whether ``verifier`` counts toward agreement: tier >= self.tier in
        this node's roster, or this node itself (its own scan is its own). For
        a record verified under a followed polity's anchor (``via``), the tier
        is the one that anchor states."""
        if via is not None:
            a = (self.anchors.get(via) or (None,))[0]
            m = next((m for m in (a or {}).get('members', ()) if m['at_uuid'] == verifier),
                     None)
            return m is not None and int(m['tier']) >= self.tier
        if self.anchor is None:
            return False
        if verifier == self.anchor.get('self'):
            return True
        m = self.anchor['members'].get(verifier) or {}
        return int(m.get('tier', -1)) >= self.tier

    def repos(self):
        """{(owner, name): newest ad} over every held ad."""
        out = {}
        for ad_id, ad in self.ads.items():
            key = (ad.get('owner'), ad.get('name'))
            cur = out.get(key)
            if cur is None or (ad.get('seq', 0), ad.get('ts', 0)) > \
                    (cur[1].get('seq', 0), cur[1].get('ts', 0)):
                out[key] = (ad_id, ad)
        return out

    def _rebuttal_of(self, at_id, owner):
        for rb in self.rebuttals.values():
            if rb.get('attestation_id') == at_id and rb.get('owner') == owner:
                return rb.get('text')
        return None

    def _checks(self, ad_ids, owner):
        """One check per (commit, scanner, channel) about any of ``ad_ids``:
        every verified result for it, latest per verifier, a replication filed
        under the check of the attestation it replicates."""
        groups = {}
        for at_id, at in self.attestations.items():
            if at.get('repo_ad_id') not in ad_ids or at_id not in self.verified \
                    or at.get('v') == 4:
                continue
            channel = at.get('channel', 'probe')
            if channel == 'replication':
                orig = self.attestations.get(at.get('replicates')) or {}
                channel = orig.get('channel', 'probe')
            key = (at.get('commit'), at.get('scanner'), channel)
            per = groups.setdefault(key, {})
            cur = per.get(at.get('verifier'))
            if cur is None or at.get('ts', 0) > cur[1].get('ts', 0):
                per[at.get('verifier')] = (at_id, at)
        out = []
        for (commit, scanner, channel), per in sorted(groups.items()):
            results = [(v, self._eligible(v, self.verified[i].get('via')), at.get('verdict'),
                        at.get('findings_digest'), at.get('ts', 0))
                       for v, (i, at) in sorted(per.items())]
            state, agreement = _check_state(results, self.replicas)
            # The result shown: the worst, newest one.
            at_id, at = max(per.values(), key=lambda ia: (
                ia[1].get('verdict') == 'vuln', ia[1].get('ts', 0)))
            v = self.verified[at_id]
            set_aside = self._set_aside(scanner, channel, at)
            out.append({
                'scanner': scanner, 'channel': channel, 'state': state,
                'agreement': agreement, 'replicas_needed': self.replicas,
                'verifiers': [{'verifier': r[0], 'counted': r[1], 'verdict': r[2],
                               'findings_digest': r[3]} for r in results],
                'verdict': at.get('verdict'), 'count': at.get('count'),
                'max_severity': at.get('max_severity'), 'commit': commit,
                'verifier': at.get('verifier'), 'ts': at.get('ts'),
                'attestation_id': at_id, 'score': v['score'],
                'linked': v['linked'], 'source': v['source'], 'via': v.get('via'),
                'reason': '%s on %s: %s (%s finding%s%s), %s verifier%s '
                          '(%d needed), attested by quorum at checkpoint epoch '
                          '%s' % (
                              scanner, channel, at.get('verdict'), at.get('count'),
                              '' if at.get('count') == 1 else 's',
                              ', worst %s' % at['max_severity']
                              if at.get('max_severity') else '', agreement,
                              ' agrees' if agreement == 1 else 's agree',
                              self.replicas, v['epoch']),
                'rebuttal': self._rebuttal_of(at_id, owner),
                'counted': set_aside is None, 'set_aside': set_aside})
        return out

    def _set_aside(self, scanner, channel, at):
        """Why the profile sets this check aside, or None when it counts. A
        set-aside check is still shown, never hidden, and a critical finding
        is never set aside, not even by ``ignore`` (floors)."""
        name = self.profile['name']
        if at.get('verdict') == 'vuln' and stele_profile.severity_rank(
                at.get('max_severity')) == stele_profile.CRITICAL:
            return None
        if '%s:%s' % (scanner, channel) in self.profile['ignore']:
            return 'ignored by %s' % name
        if at.get('verdict') == 'vuln' and not stele_profile.counts_finding(
                self.profile, at.get('max_severity')):
            return 'below the %s severity floor of %s' % (
                self.profile['severity_floor'], name)
        return None

    def standing(self, owner, name, now=None, with_team=True, with_deps=True):
        now = time.time() if now is None else now
        repos = self.repos()
        if (owner, name) not in repos:
            return None
        ad_id, ad = repos[(owner, name)]
        return self._standing_of(ad_id, ad, now, with_team, with_deps)

    def _standing_of(self, ad_id, ad, now, with_team=True, with_deps=True,
                     seen=(), depth=0):
        """The standing of the commit ``ad`` advertises: the newest, or the
        release a dependent pins. ``seen`` holds the ads whose dependencies are
        being read above this one, so a cycle is named and never followed."""
        owner, name = ad.get('owner'), ad.get('name')
        same_commit = {i for i, a in self.ads.items()
                       if a.get('owner') == owner and a.get('name') == name
                       and a.get('commit') == ad.get('commit')}
        checks = self._checks(same_commit, owner)
        out = {'repo': {k: ad.get(k) for k in ('owner', 'name', 'url', 'ref', 'commit',
                                                'description', 'topics')},
               'checks': checks, 'unverified_records': self.unverified,
               'anchored': self.anchor is not None,
               'replicas': self.replicas, 'as_of': int(now),
               'profile': dict(self.profile_meta)}
        # Only the checks the profile counts are folded; the rest are shown.
        counted = [c for c in checks if c['counted']]
        states = {c['state'] for c in counted}
        findings = [c for c in counted if c['verdict'] == 'vuln']
        present = {'%s:%s' % (c['scanner'], c['channel']) for c in counted}
        missing = [r for r in self.profile['require'] if r not in present]
        if missing:
            out['missing_required'] = missing
        if 'confirmed-finding' in states:
            out['state'] = 'failing'
            out['score'] = min(float(c['score']) for c in findings)
        elif 'disputed' in states:
            out['state'] = 'disputed'
            out['score'] = None
        elif 'unconfirmed-finding' in states:
            out['state'] = 'failing-unconfirmed'
            out['score'] = min(float(c['score']) for c in findings)
        elif missing:
            # A required check this commit was never given is no clean bill.
            out['state'] = 'unknown'
            out['score'] = None
        elif 'single-source' in states:
            out['state'] = 'single-source'
            out['score'] = None
        elif counted:
            oldest = min(c['ts'] for c in counted)
            score = decayed(SCORE_CLEAN, now - oldest,
                            self.profile['onset_days'] * 86400.0,
                            self.profile['half_life_days'] * 86400.0)
            out['score'] = round(score, 4)
            out['state'] = ('verified-safe' if score >= SAFE_FLOOR else
                            'aging' if score >= AGING_FLOOR else 'unknown')
        elif checks:
            # Everything here was set aside: nothing counted is never safe.
            out['state'] = 'unknown'
            out['score'] = None
        else:
            out['state'] = 'unknown'
            out['score'] = None
            older = {i for i, a in self.ads.items()
                     if a.get('owner') == owner and a.get('name') == name} - same_commit
            prior = self._checks(older, owner)
            if prior:
                out['earlier_commits'] = prior
        self._anchored(out, checks)
        attr = self.attributions.get(ad_id) or next(
            (self.attributions[i] for i in sorted(same_commit) if i in self.attributions),
            None)
        if attr is not None:
            out['team'] = {k: attr.get(k) for k in ('polity', 'polity_did', 'officer',
                                                    'built_by', 'guardian')}
            if with_team:
                ts = self.team_standing(attr['polity'], now)
                out['team']['state'] = ts['state'] if ts else 'unknown'
                # A profile may hold a repository to its team's standing.
                if self.profile['team'] == 'worst':
                    capped = worst_state([out['state'], out['team']['state']])
                    if capped != out['state']:
                        out['state'] = capped
                        out['capped_by_team'] = True
        if with_deps:
            deps = self._dependencies(ad_id, ad, now, tuple(seen) + (ad_id,), depth)
            out['deps'] = deps
            # A profile may hold a repository to its worst resolved dependency.
            if self.profile.get('deps') == 'worst' and deps['state'] is not None:
                capped = worst_state([out['state'], deps['state']])
                if capped != out['state']:
                    out['state'] = capped
                    out['capped_by_deps'] = True
        return out

    def _anchored(self, out, checks):
        """Name the polity whose anchor the counted checks were verified under
        (another group's repository), and how much of what that group signed
        since the first record shown came with a record about it."""
        vias = sorted({c['via'] for c in checks if c.get('via')})
        if not vias:
            return
        a = self.anchors[vias[0]][0]
        out['anchored_by'] = {'issuer': a['issuer'], 'polity': a['polity'], 'seq': a['seq'],
                              'tiers': 'tiers as %s reads them' % a['polity']}
        epochs = {self.verified[c['attestation_id']]['epoch'] for c in checks
                  if c.get('via') == vias[0]}
        epochs.discard(None)
        if epochs:
            listed = {c['epoch'] for c in a['checkpoints'] if c['epoch'] >= min(epochs)}
            seen = epochs & listed
            # A checkpoint with no record about this repository is no proof one
            # was left out (most hold none); the count is shown, not judged.
            out['checkpoints'] = {'listed': len(listed), 'with_records': len(seen),
                                  'not_shown': len(listed - seen)}

    def relay_search(self, doc, now=None):
        """Fold a relay search answer (``etc/stele/relay/search-*.json``):
        every repository any relay found, with each relay's own word beside
        what THIS node verified about it. The relay's ranking is never a
        verdict; a repository whose group this reader does not follow is
        listed, unverified."""
        merged, order = {}, []
        for r in (doc or {}).get('relays') or []:
            answer = r.get('answer') or {}
            for hit in answer.get('results') or []:
                repo = hit.get('repo') or {}
                key = (repo.get('owner'), repo.get('name'))
                if key not in merged:
                    merged[key] = {'repo': repo, 'relays': []}
                    order.append(key)
                merged[key]['relays'].append(dict(hit.get('relay') or {},
                                                  relay=r.get('relay')))
        # What the node already fetched about a repository (its last fetch
        # answer, etc/stele/relay/fetch-<rid>.json) is folded in and verified.
        held = self.repos()
        for key in order:
            url = (merged[key]['repo'] or {}).get('url')
            if key in held or not isinstance(url, str):
                continue
            rid = hashlib.sha256(('fetch|%s' % url).encode('utf-8')).hexdigest()[:16]
            try:
                with open(os.path.join(self.root, 'etc', 'stele', 'relay',
                                       'fetch-%s.json' % rid)) as f:
                    fetched = json.load(f)
            except (OSError, ValueError):
                continue
            for r in fetched.get('relays') or []:
                b = (r.get('answer') or {}).get('bundle')
                if isinstance(b, dict):
                    self.add_bundle(b)
        held = self.repos()
        home = set((self.anchor or {}).get('members') or ())
        out = []
        for key in order:
            e = merged[key]
            issuers = {r.get('anchor_issuer') for r in e['relays']} - {None}
            st = self.standing(key[0], key[1], now) if key in held else None
            e['verified'] = st
            if st is None:
                e['reason'] = ('fetch to verify' if key[0] in home or issuers & set(self.anchors)
                               else 'group not followed')
            out.append(e)
        verified = sorted((e for e in out if e['verified']),
                          key=lambda e: STATE_ORDER[e['verified']['state']])
        return {'query': (doc or {}).get('query'), 'complete': (doc or {}).get('complete'),
                'results': verified + [e for e in out if not e['verified']]}

    def relay_standing(self, doc, url, now=None):
        """Fold a relay fetch answer (``etc/stele/relay/fetch-*.json``) into
        this view, as bundles, and read the repository at ``url``."""
        relays = []
        for r in (doc or {}).get('relays') or []:
            b = (r.get('answer') or {}).get('bundle')
            got = self.add_bundle(b) if isinstance(b, dict) else {'verified': 0}
            relays.append({'relay': r.get('relay'), 'verified': got['verified'],
                           'records': len((b or {}).get('records') or []),
                           'anchors': len((b or {}).get('anchors') or [])})
        st = self.standing_by_url(url, now)
        out = {'url': url, 'relays': relays, 'complete': (doc or {}).get('complete'),
               'standing': st or {'state': 'unknown', 'heard': False}}
        if st is not None and not st.get('anchored_by') and st['repo'].get('owner') not in \
                set((self.anchor or {}).get('members') or ()):
            out['reason'] = 'group not followed'
        return out

    def _sbom_of(self, digest):
        return self.sboms.get(digest) or stele_deps.held_sbom(self.root, digest)

    def _release_for(self, owner, name, version):
        """The newest held ad of (owner, name) whose ref, or commit for a Go
        pseudo-version, is the release ``version`` names; or None."""
        best = None
        for ad_id, ad in self.ads.items():
            if ad.get('owner') != owner or ad.get('name') != name:
                continue
            if not stele_deps.version_matches(ad.get('ref'), version,
                                              ad.get('commit')):
                continue
            if best is None or (ad.get('seq', 0), ad.get('ts', 0)) > \
                    (best[1].get('seq', 0), best[1].get('ts', 0)):
                best = (ad_id, ad)
        return best

    def _claim_confirmed(self, ad_id, ad):
        """Whether counted verifiers confirmed the package ``ad`` claims: its
        commit's ``provides`` check is confirmed clean and counted."""
        same = {i for i, a in self.ads.items()
                if a.get('owner') == ad.get('owner') and a.get('name') == ad.get('name')
                and a.get('commit') == ad.get('commit')}
        return any(c['scanner'] == 'provides' and c['channel'] == 'certificate'
                   and c['state'] == 'confirmed-clean' and c['counted']
                   for c in self._checks(same, ad.get('owner')))

    def _claimants(self, base):
        """``[((owner, name), via)]``: the repositories a package resolves to.
        A pin of this reader's replaces every claimant."""
        pinned = self.deps_map.get(base)
        out = set()
        for ad in self.ads.values():
            key = (ad.get('owner'), ad.get('name'))
            if pinned is not None:
                if ad.get('url') in pinned:
                    out.add((key, 'pin'))
            elif ad.get('v') == 4 and ad.get('provides') == base:
                out.add((key, 'provides'))
        return sorted(out, key=lambda kv: (str(kv[0][0]), str(kv[0][1])))

    def _dependencies(self, ad_id, ad, now, seen, depth):
        """The dependency block of a standing (Phase 4): every component of
        the SBOM ``ad`` pins, each resolved to the repositories that publish it
        or left unresolved, and the worst resolved state."""
        digest = ad.get('sbom_digest') or ''
        out = {'sbom': 'none', 'sbom_digest': digest, 'items': [], 'state': None,
               'resolved': 0, 'unresolved': 0}
        if not digest:
            return out
        sbom = self._sbom_of(digest)
        if sbom is None:
            out['sbom'] = 'not-held'
            return out
        out['sbom'] = 'held'
        resolved_states = []
        for purl in stele_deps.components(sbom):
            base, version = stele_deps.purl_base(purl), stele_deps.purl_version(purl)
            item = {'purl': purl, 'package': base, 'version': version,
                    'claimants': []}
            for (owner, name), via in self._claimants(base):
                c = {'owner': owner, 'name': name, 'via': via}
                rel = self._release_for(owner, name, version)
                if rel is None:
                    c['status'] = 'version-not-held'
                elif via == 'provides' and not self._claim_confirmed(*rel):
                    c['status'] = 'claim-unconfirmed'
                elif rel[0] in seen:
                    c['status'] = 'cycle'
                elif depth + 1 > DEPS_DEPTH:
                    c['status'] = 'too-deep'
                else:
                    st = self._dep_standing(rel[0], rel[1], now, seen, depth + 1)
                    c.update(status='resolved', state=st['state'],
                             url=rel[1].get('url'), ref=rel[1].get('ref'),
                             commit=rel[1].get('commit'))
                    if st.get('capped_by_deps'):
                        c['capped_by_deps'] = True
                    if _stopped_short(st):
                        c['partial'] = True   # read short of a cycle or the depth
                item['claimants'].append(c)
            got = [c['state'] for c in item['claimants'] if c['status'] == 'resolved']
            if got:
                # Several repositories claim it: the worst of them stands.
                item['status'], item['state'] = 'resolved', worst_state(got)
                resolved_states.append(item['state'])
                out['resolved'] += 1
            else:
                item['status'] = next(
                    (s for s in ('version-not-held', 'claim-unconfirmed', 'cycle',
                                 'too-deep')
                     if any(c['status'] == s for c in item['claimants'])),
                    'not-on-stele')
                item['state'] = None
                out['unresolved'] += 1
            out['items'].append(item)
        if resolved_states:
            out['state'] = worst_state(resolved_states)
        return out

    def _dep_standing(self, ad_id, ad, now, seen, depth):
        """A dependency's standing, read once per view. A reading that stopped
        at a cycle depends on where it was entered from, so it is not kept."""
        hit = self._dep_memo.get((ad_id, now))
        if hit is not None:
            return hit
        st = self._standing_of(ad_id, ad, now, True, True, seen, depth)
        if not _stopped_short(st):
            self._dep_memo[(ad_id, now)] = st
        return st

    def team_standing(self, issuer, now=None):
        """A team's standing: the worst of its repositories' and its members'
        own repositories' standings (user decision 2026-10-07), with every
        verified finding as a concern. None for a team this node holds no
        roster for."""
        now = time.time() if now is None else now
        t = self.teams.get(issuer)
        if t is None:
            return None
        nodes = {m['at_uuid'] for m in t['members']}
        team_ads = {i for i, a in self.attributions.items() if a.get('polity') == issuer}
        repos = []
        for (owner, name), (_i, ad) in sorted(self.repos().items(),
                                              key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
            ours = any(self.ads.get(i, {}).get('owner') == owner
                       and self.ads.get(i, {}).get('name') == name for i in team_ads)
            if not ours and owner not in nodes:
                continue
            st = self.standing(owner, name, now, with_team=False, with_deps=False)
            st['team_release'] = ours
            repos.append(st)
        concerns = [dict(c, repo=st['repo']['name']) for st in repos
                    for c in st['checks'] if c['verdict'] == 'vuln']
        # Findings landed on a builder's guardian (v4), verified like the rest,
        # against the commit each repository shows now: like a check, a
        # guardian's finding is answered by a clean newer release.
        shown = {(st['repo']['owner'], st['repo']['name'], st['repo']['commit'])
                 for st in repos}
        for at_id, at in self.attestations.items():
            ad = self.ads.get(at.get('repo_ad_id')) or {}
            if at.get('v') == 4 and at_id in self.verified \
                    and at.get('repo_ad_id') in team_ads \
                    and (ad.get('owner'), ad.get('name'), ad.get('commit')) in shown:
                attr = self.attributions[at['repo_ad_id']]
                concerns.append({
                    'scanner': at.get('scanner'), 'channel': 'guardian',
                    'verdict': 'vuln', 'attestation_id': at_id,
                    'verifier': at.get('verifier'),
                    'repo': (self.ads.get(at['repo_ad_id']) or {}).get('name'),
                    'reason': '%s: %s answers for %s, the machine that built it' % (
                        at.get('scanner'), attr.get('guardian'), attr.get('built_by'))})
        return {'team': {'issuer': issuer, 'polity': t['polity'], 'seq': t['seq'],
                         'members': [{'did': m['did'], 'at_uuid': m['at_uuid']}
                                     for m in t['members']],
                         'officers': list(t['officers']),
                         'guardians': list(t['guardians'])},
                'state': worst_state([st['state'] for st in repos]),
                'repos': repos, 'concerns': concerns, 'as_of': int(now),
                'profile': dict(self.profile_meta)}

    def search_teams(self, q, now=None, limit=50):
        """Held teams whose polity DID, root key or repository names match the
        words of ``q``, best standing first. Separate from :meth:`search`."""
        words = [w for w in (q or '').lower().split() if w]
        hits = []
        for issuer in self.teams:
            ts = self.team_standing(issuer, now)
            # Repository names and URLs too, so a forge organization's page
            # finds its team by the organization's name.
            hay = ' '.join([issuer, ts['team']['polity']]
                           + [(r['repo']['name'] or '') + ' ' + (r['repo']['url'] or '')
                              for r in ts['repos']]).lower()
            match = sum(1 for w in words if w in hay)
            if words and match == 0:
                continue
            hits.append((STATE_ORDER[ts['state']], -match, issuer, ts))
        hits.sort(key=lambda h: h[:3])
        return [h[3] for h in hits[:limit]]

    def standing_by_url(self, url, now=None):
        for (owner, name), (_i, ad) in self.repos().items():
            if ad.get('url') == url:
                return self.standing(owner, name, now)
        return None

    def search(self, q, now=None, limit=50):
        """Heard repositories whose name, url, description or topics match the
        words of ``q``; best standing first, then the better match."""
        words = [w for w in (q or '').lower().split() if w]
        hits = []
        for (owner, name), (_i, ad) in self.repos().items():
            fields = {'name': 4, 'topics': 3, 'description': 2, 'url': 1}
            match = 0
            for w in words:
                for f, weight in fields.items():
                    if w in str(ad.get(f) or '').lower():
                        match += weight
            if words and match == 0:
                continue
            st = self.standing(owner, name, now)
            hits.append((STATE_ORDER[st['state']], -match, name, st))
        hits.sort(key=lambda h: h[:3])
        return [h[3] for h in hits[:limit]]


#: The page at /. It reads the endpoints above from its own origin, and puts
#: every string it shows through textContent, since ads, reasons and
#: rebuttals are text other people wrote.
INDEX = '''<!doctype html>
<html><head><meta charset="utf-8"><title>Stele view</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body{font:14px/1.45 system-ui,sans-serif;max-width:760px;margin:24px auto;padding:0 16px;color:#1f2328}
 input{width:100%;box-sizing:border-box;padding:6px;margin:4px 0 12px}
 .hit{border-left:4px solid #57606a;padding:4px 10px;margin:10px 0}
 .muted{color:#57606a;font-size:12px}.reb{color:#57606a;font-style:italic}
</style></head><body>
<h1>Stele view</h1>
<p class="muted">What this node has verified. Nothing here comes from a forge.</p>
<label>Search repositories this node has heard of
 <input id="q" type="search" placeholder="name, topic, description"></label>
<label>Search the relays (other groups; their word, and what this node verified)
 <input id="r" type="search" placeholder="name, topic, description"></label>
<label>Standing of a clone URL
 <input id="u" type="url" placeholder="http://localhost:3000/stele/demo.git"></label>
<div id="out"></div>
<script>
const COLORS={'verified-safe':'#1a7f37',aging:'#9a6700',unknown:'#57606a',failing:'#cf222e'};
const out=document.getElementById('out');
function el(t,c,x){const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e;}
function card(st){
  const h=el('div','hit');h.style.borderLeftColor=COLORS[st.state]||'#57606a';
  const r=st.repo||{};
  h.append(el('div',null,(r.name||'?')+'  '+st.state+(st.score!=null?'  ('+st.score+')':'')),
           el('div','muted',(r.url||'')+(r.commit?' @ '+r.commit.slice(0,12):'')));
  if(st.profile)h.append(el('div','muted','Read under '+st.profile.name+(st.profile.source==='followed'?' (followed)':'')));
  if(r.description)h.append(el('div',null,r.description));
  for(const c of st.checks||[]){h.append(el('div',null,c.reason+(c.set_aside?' [set aside: '+c.set_aside+']':'')));
    if(c.rebuttal)h.append(el('div','reb',"Owner's response (not scored): "+c.rebuttal));}
  if(!(st.checks||[]).length&&st.earlier_commits)
    h.append(el('div','muted','The newest commit has not been verified; earlier commits were.'));
  const d=st.deps;
  if(d&&d.sbom==='not-held')h.append(el('div','muted','Dependencies: this node does not hold the SBOM the ad pins.'));
  if(d&&d.sbom==='held'){
    h.append(el('div','muted','Dependencies: '+d.resolved+' on Stele'+(d.state?' (worst '+d.state+')':'')+
      ', '+d.unresolved+' not read'+(st.capped_by_deps?'; this repository stands no better than its worst':'')));
    for(const i of d.items){if(i.status!=='resolved')continue;
      h.append(el('div',null,'  '+i.purl+': '+i.state+' ('+i.claimants.filter(c=>c.status==='resolved')
        .map(c=>(c.url||c.name)+(c.via==='pin'?', pinned':'')).join('; ')+')'));}
  }
  return h;
}
async function search(q){
  const r=await (await fetch('search?q='+encodeURIComponent(q))).json();
  out.replaceChildren(...(r.results.length?r.results.map(card):[el('p','muted','Nothing heard matches.')]));
}
async function lookup(u){
  const st=await (await fetch('standing?url='+encodeURIComponent(u))).json();
  out.replaceChildren(st.heard===false?el('p','muted','This node has not heard of '+u+'.'):card(st));
}
async function relays(q){
  const r=await (await fetch('relay/search?q='+encodeURIComponent(q))).json();
  out.replaceChildren(...(r.results.length?r.results.map(e=>{
    const h=e.verified?card(e.verified):el('div','hit',(e.repo.name||'?')+'  '+(e.reason||'unverified'));
    for(const w of e.relays)h.append(el('div','muted','The relay '+w.relay+' says: '+w.findings+' finding(s), '+
      w.clean+' clean, '+w.verifiers+' verifier(s). Its word, not verified here.'));
    return h;}):[el('p','muted','No relay answered, or none found anything.')]));
}
let t;
document.getElementById('r').addEventListener('change',e=>{if(e.target.value)relays(e.target.value.trim());});
document.getElementById('q').addEventListener('input',e=>{clearTimeout(t);t=setTimeout(()=>search(e.target.value),200);});
document.getElementById('u').addEventListener('change',e=>{if(e.target.value)lookup(e.target.value.trim());});
search('');
</script></body></html>
'''


def _ctl():
    tools = os.path.normpath(os.path.join(HERE, '..', 'tools'))
    if tools not in sys.path:
        sys.path.insert(0, tools)
    import stele_ctl
    return stele_ctl


def relay_answer(root, kind, query):
    """The node's last answer from its relays for ``kind`` ('search' or
    'fetch') and ``query``, or None."""
    try:
        with open(_ctl().relay_result_path(root, kind, query)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def ask_relays(root, kind, query, wait=10.0):
    """Have the node ask its relays now (its app verb, through
    libstele_shim as stele_ctl does) and wait for the answer. Returns the
    answer, or the last one on file when the node cannot be asked."""
    ctl = _ctl()
    path = ctl.relay_result_path(root, kind, query)
    try:
        lib, h = ctl._shim(root)
    except (SystemExit, OSError, AttributeError):
        return relay_answer(root, kind, query)
    before = os.path.getmtime(path) if os.path.exists(path) else None
    send = lib.stele_relay_search if kind == 'search' else lib.stele_relay_fetch
    try:
        if send(b'extern_to_at', query.encode()) == 0:
            deadline = time.time() + wait
            while time.time() < deadline:
                if os.path.exists(path) and os.path.getmtime(path) != before:
                    break
                time.sleep(0.25)
    finally:
        lib.stele_close(h)
    return relay_answer(root, kind, query)


def make_handler(root, replicas=None, tier=None, profile=None, ask=ask_relays):
    """``profile`` is the operator's --profile; a request's ``?profile=``
    overrides it for that answer. ``ask(root, kind, query)`` has the node ask
    its relays (None: read only the last answer on file)."""
    def _relay(kind, query, fresh):
        if fresh and ask is not None:
            return ask(root, kind, query)
        return relay_answer(root, kind, query)

    class View(BaseHTTPRequestHandler):
        def _view(self, args):
            """The view for this request, or None after answering 400 for a
            profile that cannot be applied."""
            choice = (args.get('profile') or [''])[0] or profile
            try:
                return NodeView(root, replicas, tier, choice)
            except stele_profile.ProfileError as e:
                self._send(400, {'error': str(e), 'profile': choice})
                return None

        def _send(self, code, body):
            raw = json.dumps(body, indent=2).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            # No Access-Control-Allow-Origin: a web page must not read what
            # this node knows. The extension's background worker can.
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            u = urlparse(self.path)
            args = parse_qs(u.query)
            if u.path == '/health':
                return self._send(200, {'ok': True})
            if u.path in ('/', '/index.html'):
                raw = INDEX.encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return None
            view = self._view(args)
            if view is None:
                return None
            if u.path == '/standing':
                st = view.standing_by_url((args.get('url') or [''])[0])
                return self._send(200 if st else 404, st or {'state': 'unknown',
                                                             'heard': False})
            if u.path == '/search':
                return self._send(200, {'results': view.search(
                    (args.get('q') or [''])[0])})
            if u.path == '/team':
                ts = view.team_standing((args.get('polity') or [''])[0])
                return self._send(200 if ts else 404, ts or {'state': 'unknown',
                                                             'heard': False})
            if u.path == '/teams':
                return self._send(200, {'results': view.search_teams(
                    (args.get('q') or [''])[0])})
            fresh = (args.get('fresh') or ['1'])[0] != '0'
            if u.path == '/relay/search':
                q = (args.get('q') or [''])[0]
                return self._send(200, view.relay_search(_relay('search', q, fresh)))
            if u.path == '/relay/standing':
                url = (args.get('url') or [''])[0]
                out = view.relay_standing(_relay('fetch', url, fresh), url)
                return self._send(200 if out['standing'].get('heard', True) else 404, out)
            return self._send(404, {'error': 'not found',
                                    'endpoints': ['/', '/standing?url=', '/search?q=',
                                                  '/team?polity=', '/teams?q=',
                                                  '/relay/search?q=', '/relay/standing?url=',
                                                  '/health']})

        def do_POST(self):
            u = urlparse(self.path)
            if u.path != '/verify':
                return self._send(404, {'error': 'not found'})
            size = int(self.headers.get('Content-Length') or 0)
            if size <= 0 or size > BUNDLE_MAX:
                return self._send(413 if size > 0 else 400,
                                  {'error': 'a bundle of 1 byte to %d' % BUNDLE_MAX})
            try:
                bundle = json.loads(self.rfile.read(size))
            except ValueError:
                return self._send(400, {'error': 'not JSON'})
            view = self._view(parse_qs(u.query))
            if view is None:
                return None
            got = view.add_bundle(bundle)
            url = (parse_qs(u.query).get('url') or [''])[0]
            st = view.standing_by_url(url) if url else None
            return self._send(200, dict(got, standing=st or {'state': 'unknown',
                                                              'heard': False}))

        def log_message(self, fmt, *args):
            pass
    return View


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--root', required=True, help="the viewer node's root")
    ap.add_argument('--port', type=int, default=8099)
    ap.add_argument('--profile', default=None,
                    help='the profile to read standings under: a built-in name '
                         '(stele-default, stele-strict), a local one from '
                         "etc/stele/profiles, or 'followed' (default: the node's "
                         'etc/stele/profile.json, else stele-default)')
    ap.add_argument('--replicas', type=int, default=None,
                    help="override the profile's counted verifiers that must agree")
    ap.add_argument('--tier', type=int, default=None,
                    help="override the profile's tier a verifier must hold in "
                         "this node's roster to be counted")
    args = ap.parse_args(argv[1:])
    try:
        NodeView(args.root, args.replicas, args.tier, args.profile)
    except stele_profile.ProfileError as e:
        print('stele_view: %s' % e, file=sys.stderr)
        return 2
    server = ThreadingHTTPServer(('127.0.0.1', args.port),
                                 make_handler(args.root, args.replicas, args.tier,
                                              args.profile))
    print(f'stele_view: http://127.0.0.1:{args.port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
