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
"""Stele Phase 4: a discovery relay's store, the "stl_" op family an AT relay
serves. Twin of at-stele/c/stele/stele_relay.c; see stele_relay.h for the ops.

It indexes verifiable claims, never authority: what anyone publishes, filed by
content, handed back to whoever asks, with the relay's own unverified ranking
beside it. The reader verifies all of it (a record only under a group anchor it
follows). The network glue is C's (stele_relay_net.c): steled is the C node."""
import hashlib
import json
import threading
import time

from . import codec
from .anchor import parse_anchor
from .team import parse_team

PREFIX = 'stl_'
ITEMS_MAX = 16384
FILES_MAX = 256
BATCH = 256
RESULTS_MAX = 32
FETCH_MAX = 512
SBOM_MAX = 1024 * 1024
RATE_DEFAULT = 60.0
BUCKETS_MAX = 1024


def _hex(s, n) -> bool:
    return isinstance(s, str) and len(s) == n and all(c in '0123456789abcdef' for c in s)


def _blake(text: str) -> str:
    return hashlib.blake2b(text.encode('utf-8'), digest_size=32).hexdigest()


class RelayStore:
    """What one relay holds, and how it answers. Thread-safe."""

    def __init__(self, rate=None, clock=None):
        self.rate = float(rate) if rate and rate > 0 else RATE_DEFAULT
        self.clock = clock or (lambda: int(time.time()))
        self.lock = threading.Lock()
        self.items = {}           # (kind, id) -> {item, order, ...}
        self.order = 0
        self.teams = {}           # issuer -> (seq, text)
        self.anchors = {}         # issuer -> (seq, text, nodes)
        self.buckets = {}         # registrant -> [tokens, last]

    def size(self) -> int:
        with self.lock:
            return len(self.items) + len(self.teams) + len(self.anchors)

    # ---- the rate ----

    def _spend(self, uuid) -> bool:
        now = self.clock()
        b = self.buckets.get(uuid)
        if b is None:
            if len(self.buckets) >= BUCKETS_MAX:
                del self.buckets[min(self.buckets, key=lambda k: self.buckets[k][1])]
            b = self.buckets[uuid] = [self.rate, now]
        b[0] = min(self.rate, b[0] + (now - b[1]) * self.rate / 60.0)
        b[1] = now
        if b[0] < 1.0:
            return False
        b[0] -= 1.0
        return True

    # ---- filing ----

    def _file(self, files, issuer, seq, text, nodes=None):
        have = files.get(issuer)
        if have is not None and seq <= have[0]:
            return None if have[1] == text else 'stale'
        if have is None and len(files) >= FILES_MAX:
            return 'full'
        files[issuer] = (seq, text, nodes or [])
        return None

    def _publish_one(self, e):
        kind = e.get('kind') if isinstance(e, dict) else None
        item = e.get('item') if isinstance(e, dict) else None
        if not isinstance(kind, str) or item is None:
            return 'malformed'
        held = {}
        if kind == 'ad':
            got = codec.from_envelope(item, codec.AD_KEYS)
            if not got or not codec.repo_ad_valid(got[0]):
                return 'malformed'
            held['ad'] = got[0]
            iid = codec.repo_ad_id(got[0])
        elif kind == 'attestation':
            got = codec.from_envelope(item, codec.ATTEST_KEYS)
            if not got or not codec.attestation_valid(got[0]):
                return 'malformed'
            held['at'] = got[0]
            iid = codec.attestation_id(got[0])
        elif kind == 'rebuttal':
            got = codec.from_envelope(item, codec.REBUT_KEYS)
            if not got or not codec.rebuttal_valid(got[0]):
                return 'malformed'
            held['ref'] = got[0]['attestation_id']
            iid = codec.rebuttal_id(got[0])
        elif kind == 'record':
            entry = item.get('entry') if isinstance(item, dict) else None
            ck = item.get('checkpoint') if isinstance(item, dict) else None
            digest = entry.get('evidence_digest') if isinstance(entry, dict) else None
            root = ck.get('root') if isinstance(ck, dict) else None
            epoch = ck.get('epoch') if isinstance(ck, dict) else None
            if (item.get('schema') != '1' or not _hex(digest, 64) or not _hex(root, 64)
                    or not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0):
                return 'malformed'
            held['ref'] = digest
            iid = _blake('%s|%d|%s' % (digest, epoch, root))
        elif kind == 'sbom':
            digest = item.get('digest') if isinstance(item, dict) else None
            text = item.get('text') if isinstance(item, dict) else None
            if (not _hex(digest, 64) or not isinstance(text, str)
                    or len(text.encode('utf-8')) > SBOM_MAX
                    or hashlib.sha256(text.encode('utf-8')).hexdigest() != digest):
                return 'malformed'
            try:
                if not isinstance(json.loads(text), dict):
                    return 'malformed'
            except ValueError:
                return 'malformed'
            item, iid = text, digest
        elif kind == 'team':
            t = parse_team(item) if isinstance(item, str) else None
            return 'malformed' if t is None else self._file(self.teams, t['issuer'],
                                                            t['seq'], item)
        elif kind == 'anchor':
            a = parse_anchor(item) if isinstance(item, str) else None
            if a is None:
                return 'malformed'
            return self._file(self.anchors, a['issuer'], a['seq'], item,
                              [m['at_uuid'] for m in a['members']])
        else:
            return 'unknown_kind'
        key = (kind, iid)
        if key in self.items:
            return None                     # held already: content-addressed
        if len(self.items) >= ITEMS_MAX:
            del self.items[min(self.items, key=lambda k: self.items[k]['order'])]
        self.items[key] = dict(held, item=item, order=self.order, id=iid)
        self.order += 1
        return None

    def _publish(self, req):
        items = req.get('items')
        if not isinstance(items, list) or len(items) > BATCH:
            return {'op': 'stl_refused', 'reason': 'malformed'}
        accepted, refused = 0, []
        for i, e in enumerate(items):
            why = self._publish_one(e)
            if why is None:
                accepted += 1
            else:
                refused.append({'index': i, 'reason': why})
        return {'op': 'stl_published', 'accepted': accepted, 'refused': refused}

    # ---- searching ----

    def _kind(self, kind):
        return sorted((v for (k, _i), v in self.items.items() if k == kind),
                      key=lambda v: v['order'])

    def _anchor_issuer(self, owner):
        hits = sorted(i for i, (_s, _t, nodes) in self.anchors.items() if owner in nodes)
        return hits[0] if hits else None

    def _newest_ads(self):
        newest = {}
        for v in self._kind('ad'):
            ad = v['ad']
            key = (ad['owner'], ad['name'])
            cur = newest.get(key)
            if cur is None or (ad['seq'], ad['ts']) > (cur['ad']['seq'], cur['ad']['ts']):
                newest[key] = v
        return newest

    def _search(self, req):
        q = req.get('q') if isinstance(req.get('q'), str) else ''
        limit = req.get('limit')
        if not isinstance(limit, int) or isinstance(limit, bool) or not 0 < limit <= RESULTS_MAX:
            limit = RESULTS_MAX
        words = [w[:64] for w in q.split(' ') if w][:16]
        ads_by_id = {v['id']: v['ad'] for v in self._kind('ad')}
        hits = []
        for (owner, name), v in self._newest_ads().items():
            ad = v['ad']
            match = sum((4 if w.lower() in ad['name'].lower() else 0)
                        + (3 if w.lower() in ad.get('topics', '').lower() else 0)
                        + (2 if w.lower() in ad.get('description', '').lower() else 0)
                        + (1 if w.lower() in ad['url'].lower() else 0) for w in words)
            if words and match == 0:
                continue
            findings = clean = 0
            verifiers = set()
            for a in self._kind('attestation'):
                about = ads_by_id.get(a['at']['repo_ad_id'])
                if about is None or (about['owner'], about['name'], about['commit']) != \
                        (owner, name, ad['commit']):
                    continue
                if a['at']['verdict'] == codec.VERDICT_VULN:
                    findings += 1
                else:
                    clean += 1
                verifiers.add(a['at']['verifier'])
            hits.append(((findings > 0, -clean, -match, name, owner), ad, findings, clean,
                         len(verifiers)))
        hits.sort(key=lambda h: h[0])
        results = []
        for _k, ad, findings, clean, n in hits[:limit]:
            results.append({
                'repo': {'owner': ad['owner'], 'name': ad['name'], 'url': ad['url'],
                         'ref': ad['ref'], 'commit': ad['commit'],
                         'description': ad.get('description', ''),
                         'topics': ad.get('topics', ''),
                         'polity': ad.get('polity', '') if codec.is_team_ad(ad) else ''},
                'relay': {'findings': findings, 'clean': clean, 'verifiers': n,
                          'anchor_issuer': self._anchor_issuer(ad['owner'])}})
        return {'op': 'stl_results', 'q': q, 'results': results}

    # ---- fetching ----

    def _fetch(self, req):
        url = req.get('url') if isinstance(req.get('url'), str) else ''
        repos = {(v['ad']['owner'], v['ad']['name']) for v in self._kind('ad')
                 if v['ad']['url'] == url}

        def pick(kind, want):
            return sorted((v for v in self._kind(kind) if want(v)),
                          key=lambda v: v['id'])[:FETCH_MAX]
        ads = pick('ad', lambda v: (v['ad']['owner'], v['ad']['name']) in repos)
        ad_ids = {v['id'] for v in ads}
        ats = pick('attestation', lambda v: v['at']['repo_ad_id'] in ad_ids)
        at_ids = {v['id'] for v in ats}
        rbs = pick('rebuttal', lambda v: v['ref'] in at_ids)
        recs = pick('record', lambda v: v['ref'] in at_ids)
        sboms, teams, anchors = {}, [], []
        for v in ads:
            ad = v['ad']
            sb = self.items.get(('sbom', ad.get('sbom_digest') or ''))
            if sb is not None:
                sboms[sb['id']] = sb['item']
            if codec.is_team_ad(ad) and ad['polity'] in self.teams:
                text = self.teams[ad['polity']][1]
                if text not in teams:
                    teams.append(text)
            for _i, (_s, text, nodes) in sorted(self.anchors.items()):
                if ad['owner'] in nodes and text not in anchors:
                    anchors.append(text)
        bundle = {'schema': 'stele-bundle-1', 'url': url,
                  'ads': [v['item'] for v in ads], 'attestations': [v['item'] for v in ats],
                  'rebuttals': [v['item'] for v in rbs], 'records': [v['item'] for v in recs],
                  'teams': teams, 'anchors': anchors, 'sboms': sboms}
        return {'op': 'stl_bundle', 'url': url, 'bundle': bundle}

    # ---- the op family ----

    def serve(self, uuid, op, req):
        """Answer one "stl_" op from registrant ``uuid``. Mirrors
        stele_relay_serve."""
        req = req if isinstance(req, dict) else {}
        with self.lock:
            if op not in ('stl_publish', 'stl_search', 'stl_fetch'):
                reply = {'op': 'stl_refused', 'reason': 'unknown_op'}
            elif not self._spend(uuid or ''):
                reply = {'op': 'stl_limited', 'reason': 'rate'}
            elif op == 'stl_publish':
                reply = self._publish(req)
            elif op == 'stl_search':
                reply = self._search(req)
            else:
                reply = self._fetch(req)
        if isinstance(req.get('rid'), str):
            reply['rid'] = req['rid']
        return reply


def serve(store, uuid, op, req):
    """``store.serve``, or not_stele_relay when this relay keeps no store."""
    if store is None:
        reply = {'op': 'stl_refused', 'reason': 'not_stele_relay'}
        if isinstance((req or {}).get('rid'), str):
            reply['rid'] = req['rid']
        return reply
    return store.serve(uuid, op, req)
