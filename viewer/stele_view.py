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

  stele_view.py --root VIEWER_ROOT [--port 8099]

  GET /standing?url=<clone url>   the standing of the repository at that URL
  POST /verify?url=<clone url>    the same, with a bundle (JSON body) folded in
  GET /search?q=<text>            heard repositories matching the text, best
                                  standing first (local only; no global index)
  GET /health                     liveness
  GET /                           a page for people: search, and a URL lookup
"""
import glob
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
for _p in (STELE_PY, AT_PY):
    if _p not in sys.path:
        sys.path.insert(0, _p)

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


def decayed(score: float, idle: float) -> float:
    """AT's decay shape (reputation_decayed_score) with Stele's parameters: a
    score above the asymptote fades toward it once idle past the onset; one at
    or below it never moves."""
    if score <= DECAY_ASYMPTOTE or idle <= DECAY_ONSET:
        return score
    return DECAY_ASYMPTOTE + (score - DECAY_ASYMPTOTE) * math.pow(
        0.5, (idle - DECAY_ONSET) / DECAY_HALF_LIFE)


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


class NodeView:
    """Everything the standing is folded from, read fresh from one node root,
    plus any records a bundle brought (:meth:`add_bundle`)."""

    def __init__(self, root, replicas=REPLICAS, tier=REPLICA_TIER):
        from autonomous_trust.core.reputation.reputation import load_anchor
        self.root = root
        self.replicas, self.tier = int(replicas), int(tier)
        stele = os.path.join(root, 'etc', 'stele')
        self.ads = _load_dir(os.path.join(stele, 'ads'))
        self.attestations = _load_dir(os.path.join(stele, 'attestations'))
        self.rebuttals = _load_dir(os.path.join(stele, 'rebuttals'))
        # The trust anchor: this node's own roster (AT roster.cfg.json). A
        # record is checked against the keys and group THIS node holds, never
        # against the keys it carries, which a forger would write too.
        self.anchor = load_anchor(root)
        self.verified = {}       # attestation id -> {epoch, score, channel, linked}
        self.unverified = 0
        self.unverified_reasons = []
        for rec in _load_dir(os.path.join(root, 'etc', 'at', 'attested')).values():
            self._take_record(rec)

    def _take_record(self, rec, source='node'):
        """Verify one record against the anchor and keep it when it certifies a
        held attestation about its ad's owner. Returns True when kept."""
        from autonomous_trust.core.reputation.reputation import verify_attested_record
        entry = (rec or {}).get('entry') or {}
        if self.anchor is None:
            ok, why, details = False, ['this node has no roster to verify against'], {}
        else:
            details = {}
            ok, why = verify_attested_record(rec, self.anchor, details)
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
        # somebody else cannot vouch for this repository.
        if ad is None or entry.get('subject_id') != ad.get('owner'):
            return False
        self.verified[digest] = {
            'epoch': (rec.get('checkpoint') or {}).get('epoch'),
            'score': entry.get('p1_score'),
            'channel': entry.get('p1_channel'),
            'linked': bool(details.get('linked')), 'source': source}
        return True

    def add_bundle(self, bundle):
        """Fold in a STANDING BUNDLE that someone else hands over (the owner's
        forge, a peer): ``{"records": [...], "attestations": [envelope, ...],
        "ads": [envelope, ...]}``. Ads and attestations are taken by CONTENT:
        each is filed under the id its canonical bytes hash to, so a record
        that verifies against this node's anchor binds exactly the attestation
        it names, and that attestation the ad. Nothing is written to the node.
        Returns ``{"verified": n, "unverified": [reasons]}``."""
        from autonomous_trust.stele import codec
        before = len(self.unverified_reasons)
        if not isinstance(bundle, dict):
            return {'verified': 0, 'unverified': [{'reasons': ['not a bundle']}]}
        for env in bundle.get('ads') or []:
            parsed = codec.from_envelope(env, codec.AD_KEYS)
            if parsed and codec.repo_ad_valid(parsed[0]):
                self.ads.setdefault(codec.repo_ad_id(parsed[0]), dict(env))
        for env in bundle.get('attestations') or []:
            parsed = codec.from_envelope(env, codec.ATTEST_KEYS)
            if parsed and codec.attestation_valid(parsed[0]):
                self.attestations.setdefault(codec.attestation_id(parsed[0]),
                                             dict(env))
        kept = sum(1 for rec in bundle.get('records') or []
                   if isinstance(rec, dict) and self._take_record(rec, 'bundle'))
        return {'verified': kept, 'unverified': self.unverified_reasons[before:]}

    def _eligible(self, verifier):
        """Whether ``verifier`` counts toward agreement: tier >= self.tier in
        this node's roster, or this node itself (its own scan is its own)."""
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
            if at.get('repo_ad_id') not in ad_ids or at_id not in self.verified:
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
            results = [(v, self._eligible(v), at.get('verdict'),
                        at.get('findings_digest'), at.get('ts', 0))
                       for v, (_i, at) in sorted(per.items())]
            state, agreement = _check_state(results, self.replicas)
            # The result shown: the worst, newest one.
            at_id, at = max(per.values(), key=lambda ia: (
                ia[1].get('verdict') == 'vuln', ia[1].get('ts', 0)))
            v = self.verified[at_id]
            out.append({
                'scanner': scanner, 'channel': channel, 'state': state,
                'agreement': agreement, 'replicas_needed': self.replicas,
                'verifiers': [{'verifier': r[0], 'counted': r[1], 'verdict': r[2],
                               'findings_digest': r[3]} for r in results],
                'verdict': at.get('verdict'), 'count': at.get('count'),
                'max_severity': at.get('max_severity'), 'commit': commit,
                'verifier': at.get('verifier'), 'ts': at.get('ts'),
                'attestation_id': at_id, 'score': v['score'],
                'linked': v['linked'], 'source': v['source'],
                'reason': '%s on %s: %s (%s finding%s%s), %s of %d verifiers '
                          'agree, attested by quorum at checkpoint epoch %s' % (
                              scanner, channel, at.get('verdict'), at.get('count'),
                              '' if at.get('count') == 1 else 's',
                              ', worst %s' % at['max_severity']
                              if at.get('max_severity') else '', agreement,
                              self.replicas, v['epoch']),
                'rebuttal': self._rebuttal_of(at_id, owner)})
        return out

    def standing(self, owner, name, now=None):
        now = time.time() if now is None else now
        repos = self.repos()
        if (owner, name) not in repos:
            return None
        ad_id, ad = repos[(owner, name)]
        same_commit = {i for i, a in self.ads.items()
                       if a.get('owner') == owner and a.get('name') == name
                       and a.get('commit') == ad.get('commit')}
        checks = self._checks(same_commit, owner)
        out = {'repo': {k: ad.get(k) for k in ('owner', 'name', 'url', 'ref', 'commit',
                                                'description', 'topics')},
               'checks': checks, 'unverified_records': self.unverified,
               'anchored': self.anchor is not None,
               'replicas': self.replicas, 'as_of': int(now)}
        states = {c['state'] for c in checks}
        findings = [c for c in checks if c['verdict'] == 'vuln']
        if 'confirmed-finding' in states:
            out['state'] = 'failing'
            out['score'] = min(float(c['score']) for c in findings)
        elif 'disputed' in states:
            out['state'] = 'disputed'
            out['score'] = None
        elif 'unconfirmed-finding' in states:
            out['state'] = 'failing-unconfirmed'
            out['score'] = min(float(c['score']) for c in findings)
        elif 'single-source' in states:
            out['state'] = 'single-source'
            out['score'] = None
        elif checks:
            oldest = min(c['ts'] for c in checks)
            score = decayed(SCORE_CLEAN, now - oldest)
            out['score'] = round(score, 4)
            out['state'] = ('verified-safe' if score >= SAFE_FLOOR else
                            'aging' if score >= AGING_FLOOR else 'unknown')
        else:
            out['state'] = 'unknown'
            out['score'] = None
            older = {i for i, a in self.ads.items()
                     if a.get('owner') == owner and a.get('name') == name} - same_commit
            prior = self._checks(older, owner)
            if prior:
                out['earlier_commits'] = prior
        return out

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
  if(r.description)h.append(el('div',null,r.description));
  for(const c of st.checks||[]){h.append(el('div',null,c.reason));
    if(c.rebuttal)h.append(el('div','reb',"Owner's response (not scored): "+c.rebuttal));}
  if(!(st.checks||[]).length&&st.earlier_commits)
    h.append(el('div','muted','The newest commit has not been verified; earlier commits were.'));
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
let t;
document.getElementById('q').addEventListener('input',e=>{clearTimeout(t);t=setTimeout(()=>search(e.target.value),200);});
document.getElementById('u').addEventListener('change',e=>{if(e.target.value)lookup(e.target.value.trim());});
search('');
</script></body></html>
'''


def make_handler(root, replicas=REPLICAS, tier=REPLICA_TIER):
    class View(BaseHTTPRequestHandler):
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
            view = NodeView(root, replicas, tier)
            if u.path == '/standing':
                st = view.standing_by_url((args.get('url') or [''])[0])
                return self._send(200 if st else 404, st or {'state': 'unknown',
                                                             'heard': False})
            if u.path == '/search':
                return self._send(200, {'results': view.search(
                    (args.get('q') or [''])[0])})
            return self._send(404, {'error': 'not found',
                                    'endpoints': ['/', '/standing?url=', '/search?q=',
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
            view = NodeView(root, replicas, tier)
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
    ap.add_argument('--replicas', type=int, default=REPLICAS,
                    help='counted verifiers that must agree (default 2)')
    ap.add_argument('--tier', type=int, default=REPLICA_TIER,
                    help="the tier a verifier must hold in this node's roster "
                         'to be counted (default 3)')
    args = ap.parse_args(argv[1:])
    server = ThreadingHTTPServer(('127.0.0.1', args.port),
                                 make_handler(args.root, args.replicas, args.tier))
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
