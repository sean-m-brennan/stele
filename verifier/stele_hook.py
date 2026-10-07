#!/usr/bin/env python3
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
"""stele_hook: the verifier's side of the forge seam (Stele).

Listens for Forgejo push webhooks, and for each push to a watched repository:

  1. checks the HMAC (X-Forgejo-Signature / X-Gitea-Signature, sha256 of the
     body under the shared secret) -- and treats the hook as a TRIGGER only:
     nothing in it is believed beyond "look at this commit";
  2. finds the owner's ad for that URL and commit among the ads this node
     holds (ROOT/etc/stele/ads), which names the owner's node and carries its
     claims;
  3. clones the repository itself and checks out the pushed commit;
  4. runs the scanner battery against it (scanners.py): each probe scanner in
     `scanners`, then the owner's SBOM against the verifier's own when the ad
     carries one (certificate), then the owner's clean claim against what the
     probes found (self_consistency);
  5. hands each report to `stele_ctl.py attest`, which keeps the report, has
     this node sign an attestation and submits the verifier-attested score
     about the repo OWNER's node, in the scope of that commit.

The owner's CI may run its own scan (forge/workflows/osv.yml); that is the
owner's claim about itself and is not scored on its own. This is the
verifier's.

It also REPLICATES (Phase 2). Every `--replicate-every` seconds, and once with
`replicate`, it looks through the attestations this node holds for probes by
OTHER verifiers that it has not re-run. It re-runs each one only when its own
scanner version and database snapshot are the ones the original named, since
otherwise a disagreement would mean nothing. The result is attested on
`replication`, naming the original, with this verifier's own verdict and
findings digest. AT admits a replication only from a verifier at tier 3 in its
co-signers' view, and the viewer counts a check as confirmed once enough
verifiers agree.

  stele_hook.py --root VERIFIER_ROOT --config hook.json [--port 8098]
                [--replicate-every SEC]
  stele_hook.py replicate --root VERIFIER_ROOT --config hook.json

hook.json:
  {"secret": "<shared webhook secret>",
   "scanners": ["osv-scanner", "gitleaks", "semgrep", "license"],
   "osv_scanner": "/path/to/osv-scanner",
   "osv_db": "/path/to/db-cache",         # holds osv-scalibr/<eco>/all.zip
   "gitleaks": "/path/to/gitleaks",
   "semgrep": "/path/to/semgrep", "semgrep_rules": "/path/to/rules",
   "syft": "/path/to/syft",               # the verifier's own SBOM
   "license_deny": ["AGPL-3.0-only", ...],
   "repos": {"<clone_url>": "<owner node uuid>", ...}}

`scanners` defaults to osv-scanner alone. `repos` is optional: when the node
holds the owner's ad for the pushed URL and commit, the ad names the owner. The
owner's node must have advertised the repo at that commit
(`stele_ctl.py advertise`), or the attest verb refuses.
"""
import glob
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
CTL = os.path.join(HERE, '..', 'tools', 'stele_ctl.py')
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import scanners  # noqa: E402


def signature_ok(secret: str, body: bytes, header: str) -> bool:
    """Forgejo signs the raw body: hex HMAC-SHA256 under the hook's secret."""
    if not secret or not header:
        return False
    want = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header.strip().lower())


def push_target(event: dict):
    """``(clone_url, commit)`` from a push event, or None. A branch deletion
    (all-zero ``after``) is not a commit to scan."""
    repo = event.get('repository') or {}
    url = repo.get('clone_url')
    after = event.get('after') or ''
    if not url or len(after) not in (40, 64) or set(after) == {'0'}:
        return None
    return url, after.lower()


def db_digest(db_dir: str) -> str:
    """sha256 over the database snapshot's files, in path order: names the
    exact snapshot a finding was made against."""
    h = hashlib.sha256()
    for path in sorted(glob.glob(os.path.join(db_dir, '**', '*.zip'), recursive=True)):
        h.update(os.path.relpath(path, db_dir).encode())
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
    return h.hexdigest()


def scanner_version(osv_bin: str) -> str:
    out = subprocess.run([osv_bin, '--version'], capture_output=True, text=True)
    for line in out.stdout.splitlines():
        if line.startswith('osv-scanner version:'):
            return line.split(':', 1)[1].strip()
    return 'unknown'


def _clone(clone_url: str, commit: str, src: str) -> None:
    subprocess.run(['git', 'clone', '--quiet', clone_url, src], check=True)
    subprocess.run(['git', '-C', src, 'checkout', '--quiet', commit], check=True)


def scan_commit(clone_url: str, commit: str, osv_bin: str, osv_db: str) -> dict:
    """Clone `clone_url`, check out `commit`, and return osv-scanner's JSON
    report for it (offline, against `osv_db`). Raises on a clone or checkout
    failure; osv-scanner's own exit status (1 == vulnerabilities found) is not
    an error."""
    with tempfile.TemporaryDirectory(prefix='stele-scan-') as work:
        src = os.path.join(work, 'src')
        _clone(clone_url, commit, src)
        return scanners.run_osv(src, {'osv_scanner': osv_bin, 'osv_db': osv_db})


def find_ad(root: str, url: str, commit: str):
    """The newest ad this node holds for `url` at `commit` (its envelope dict),
    or None. The ad, not the forge, says which node owns the repository."""
    best = None
    for path in glob.glob(os.path.join(root, 'etc', 'stele', 'ads', '*.json')):
        try:
            with open(path) as f:
                ad = json.load(f)
        except (OSError, ValueError):
            continue
        if ad.get('url') == url and ad.get('commit') == commit \
                and (best is None or ad.get('seq', 0) > best.get('seq', 0)):
            best = ad
    return best


def attest(root: str, owner: str, commit: str, report, cfg: dict,
           scanner: str = 'osv-scanner', url: str = None,
           replicates: str = None) -> int:
    """Hand one scanner's report to `stele_ctl.py attest`; with `replicates`,
    as a replication of that attestation."""
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
        json.dump(report, f)
        path = f.name
    channel = 'replication' if replicates else scanners.CHANNELS[scanner]
    argv = [sys.executable, CTL, 'attest', root, owner, commit, path,
            scanners.db_digest_of(scanner, cfg), scanners.version_of(scanner, cfg),
            '--scanner', scanner, '--channel', channel]
    if url:
        argv += ['--url', url]
    if replicates:
        argv += ['--replicates', replicates]
    try:
        return subprocess.run(argv).returncode
    finally:
        os.unlink(path)


PROBE_RUNS = {'osv-scanner': 'run_osv', 'gitleaks': 'run_gitleaks',
              'semgrep': 'run_semgrep'}


def _probe_report(name: str, src: str, cfg: dict, own=None):
    """One probe scanner's report on the checkout at `src`, and the
    verifier's own SBOM if the license check had to make one."""
    if name == 'license':
        own = own or scanners.own_sbom(src, cfg)
        return scanners.check_licenses(
            own, cfg.get('license_deny') or scanners.DEFAULT_LICENSE_DENY), own
    return getattr(scanners, PROBE_RUNS[name])(src, cfg), own


def scan_and_attest(root: str, url: str, commit: str, owner: str, ad, cfg: dict,
                    log=print) -> dict:
    """The battery for one pushed commit; returns {scanner: summary}. A scanner
    that fails is logged and skipped: one broken tool does not silence the
    others."""
    done = {}
    with tempfile.TemporaryDirectory(prefix='stele-scan-') as work:
        src = os.path.join(work, 'src')
        _clone(url, commit, src)
        own = None
        probes = []
        for name in cfg.get('scanners') or ['osv-scanner']:
            try:
                report, own = _probe_report(name, src, cfg, own)
            except (KeyError, RuntimeError, OSError, ValueError) as err:
                log(f'stele_hook: {name} on {commit[:12]} failed: {err}')
                continue
            summary = scanners.SUMMARIES[name](report)
            probes.append((name,) + (summary[0], summary[1], summary[3]))
            attest(root, owner, commit, report, cfg, name, url)
            done[name] = summary
        if ad and ad.get('sbom_digest'):
            try:
                own = own or scanners.own_sbom(src, cfg)
                report = scanners.check_sbom(src, ad['sbom_path'], ad['sbom_digest'], own)
                attest(root, owner, commit, report, cfg, 'sbom', url)
                done['sbom'] = scanners.summarize_sbom(report)
            except (KeyError, RuntimeError, OSError, ValueError) as err:
                log(f'stele_hook: sbom check on {commit[:12]} failed: {err}')
        if ad and ad.get('claim_verdict') == 'clean':
            report = scanners.check_claim('clean', probes)
            if report['contradicted_by']:
                attest(root, owner, commit, report, cfg, 'claim', url)
                done['claim'] = scanners.summarize_claim(report)
    return done


def _held(root: str, kind: str) -> dict:
    """{id: envelope} for what this node holds under etc/stele/<kind>."""
    out = {}
    for path in glob.glob(os.path.join(root, 'etc', 'stele', kind, '*.json')):
        try:
            with open(path) as f:
                out[os.path.basename(path)[:-5]] = json.load(f)
        except (OSError, ValueError):
            continue
    return out


def node_uuid(root: str) -> str:
    with open(os.path.join(root, 'etc', 'at', 'identity.cfg.json')) as f:
        return json.load(f)['uuid']


def pending_replications(root: str, cfg: dict, done=()) -> list:
    """The held probes by other verifiers this node has not replicated (nor
    tried, `done`), oldest first, as (attestation id, attestation, ad)."""
    me = node_uuid(root)
    ads, held = _held(root, 'ads'), _held(root, 'attestations')
    mine = {a.get('replicates') for a in held.values()
            if a.get('verifier') == me and a.get('channel') == 'replication'}
    wanted = set(cfg.get('scanners') or ['osv-scanner'])
    out = []
    for at_id, at in held.items():
        if (at.get('verifier') == me or at_id in mine or at_id in done
                or at.get('channel', 'probe') != 'probe'
                or at.get('scanner') not in wanted
                or at.get('repo_ad_id') not in ads):
            continue
        out.append((at_id, at, ads[at['repo_ad_id']]))
    return sorted(out, key=lambda t: t[1].get('ts', 0))


def replicate_once(root: str, cfg: dict, done: set, log=print) -> dict:
    """Re-run each pending probe whose scanner version and database this
    verifier shares, and attest the result on `replication`. Returns
    {attestation id: verdict, or 'skipped: <why>'}; every id is added to
    `done`, so a check this node cannot reproduce is not retried forever."""
    out = {}
    for at_id, at, ad in pending_replications(root, cfg, done):
        done.add(at_id)
        name = at['scanner']
        try:
            same = (scanners.version_of(name, cfg) == at.get('scanner_version')
                    and scanners.db_digest_of(name, cfg) == at.get('db_digest'))
        except (KeyError, RuntimeError, OSError, ValueError) as err:
            same, err_text = False, str(err)
        else:
            err_text = 'version or database differs'
        if not same:
            log(f'stele_hook: cannot reproduce {at_id[:12]} ({name}): {err_text}')
            out[at_id] = 'skipped: ' + err_text
            continue
        try:
            with tempfile.TemporaryDirectory(prefix='stele-repl-') as work:
                src = os.path.join(work, 'src')
                _clone(ad['url'], at['commit'], src)
                report, _ = _probe_report(name, src, cfg)
        except (subprocess.CalledProcessError, KeyError, RuntimeError, OSError,
                ValueError) as err:
            log(f'stele_hook: replication of {at_id[:12]} failed: {err}')
            out[at_id] = 'skipped: ' + str(err)
            continue
        attest(root, ad['owner'], at['commit'], report, cfg, name, ad['url'],
               replicates=at_id)
        verdict = scanners.SUMMARIES[name](report)[0]
        log(f'stele_hook: replicated {at_id[:12]} ({name}): {verdict}')
        out[at_id] = verdict
    return out


def make_handler(root: str, cfg: dict):
    class Hook(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length') or 0))
            sig = (self.headers.get('X-Forgejo-Signature')
                   or self.headers.get('X-Gitea-Signature') or '')
            if not signature_ok(cfg.get('secret', ''), body, sig):
                self.send_response(401)
                self.end_headers()
                return
            self.send_response(202)
            self.end_headers()
            try:
                target = push_target(json.loads(body or b'{}'))
            except ValueError:
                return
            if target is None:
                return
            url, commit = target
            ad = find_ad(root, url, commit)
            owner = (ad or {}).get('owner') or (cfg.get('repos') or {}).get(url)
            if owner is None:
                print(f'stele_hook: {url} is not watched and no ad names it',
                      flush=True)
                return
            print(f'stele_hook: push {url} @ {commit[:12]}; scanning', flush=True)
            try:
                done = scan_and_attest(root, url, commit, owner, ad, cfg,
                                       log=lambda m: print(m, flush=True))
                for name, (verdict, count, _sev, _d) in done.items():
                    print(f'stele_hook: attested {commit[:12]} {name}: {verdict} '
                          f'({count})', flush=True)
            except (subprocess.CalledProcessError, RuntimeError, ValueError) as err:
                print(f'stele_hook: scan of {commit[:12]} failed: {err}', flush=True)

        def log_message(self, fmt, *args):   # quiet; we print our own lines
            pass
    return Hook


def main(argv):
    import argparse
    import threading
    import time
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('mode', nargs='?', choices=('serve', 'replicate'),
                    default='serve')
    ap.add_argument('--root', required=True, help="the verifier node's root")
    ap.add_argument('--config', required=True)
    ap.add_argument('--host', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=8098)
    ap.add_argument('--replicate-every', type=float, default=0,
                    help='seconds between replication passes (0: none)')
    args = ap.parse_args(argv[1:])
    with open(args.config) as f:
        cfg = json.load(f)
    done = set()
    if args.mode == 'replicate':
        out = replicate_once(args.root, cfg, done,
                             log=lambda m: print(m, flush=True))
        print(json.dumps(out), flush=True)
        return 0
    if args.replicate_every > 0:
        def _loop():
            while True:
                time.sleep(args.replicate_every)
                try:
                    replicate_once(args.root, cfg, done,
                                   log=lambda m: print(m, flush=True))
                except (OSError, ValueError, KeyError) as err:
                    print(f'stele_hook: replication pass failed: {err}', flush=True)
        threading.Thread(target=_loop, daemon=True).start()
    server = HTTPServer((args.host, args.port), make_handler(args.root, cfg))
    print(f'stele_hook: listening on {args.host}:{args.port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
