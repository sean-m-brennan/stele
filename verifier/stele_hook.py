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
"""stele_hook: the verifier's side of the forge seam (Stele Phase 0).

Listens for Forgejo push webhooks, and for each push to a watched repository:

  1. checks the HMAC (X-Forgejo-Signature / X-Gitea-Signature, sha256 of the
     body under the shared secret) -- and treats the hook as a TRIGGER only:
     nothing in it is believed beyond "look at this commit";
  2. clones the repository itself and checks out the pushed commit;
  3. runs osv-scanner against it, offline, with a database snapshot this
     verifier fetched (the db digest names the snapshot);
  4. hands the report to `stele_ctl.py attest`, which has this node sign an
     attestation and submit the verifier-attested score about the repo
     OWNER's node.

The owner's CI may run its own scan (forge/workflows/osv.yml); that is the
owner's claim about itself and is not scored. This is the verifier's.

  stele_hook.py --root VERIFIER_ROOT --config hook.json [--port 8098]

hook.json:
  {"secret": "<shared webhook secret>",
   "osv_scanner": "/path/to/osv-scanner",
   "osv_db": "/path/to/db-cache",         # holds osv-scalibr/<eco>/all.zip
   "repos": {"<clone_url>": "<owner node uuid>", ...}}

`repos` is how the verifier knows which AT node owns a repository: the forge
does not know AT identities. The owner's node must also have advertised the
repo at that commit (`stele_ctl.py advertise`), or the attest verb refuses.
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


def scan_commit(clone_url: str, commit: str, osv_bin: str, osv_db: str) -> dict:
    """Clone `clone_url`, check out `commit`, and return osv-scanner's JSON
    report for it (offline, against `osv_db`). Raises on a clone or checkout
    failure; osv-scanner's own exit status (1 == vulnerabilities found) is not
    an error."""
    with tempfile.TemporaryDirectory(prefix='stele-scan-') as work:
        src = os.path.join(work, 'src')
        subprocess.run(['git', 'clone', '--quiet', clone_url, src], check=True)
        subprocess.run(['git', '-C', src, 'checkout', '--quiet', commit], check=True)
        env = dict(os.environ, OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=osv_db)
        out = subprocess.run([osv_bin, 'scan', 'source', '-r', '--format', 'json',
                              '--offline-vulnerabilities', src],
                             capture_output=True, text=True, env=env)
        if out.returncode not in (0, 1):
            raise RuntimeError('osv-scanner failed (%d): %s'
                               % (out.returncode, out.stderr[-400:]))
        return json.loads(out.stdout or '{}')


def attest(root: str, owner: str, commit: str, report: dict, cfg: dict) -> int:
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
        json.dump(report, f)
        path = f.name
    try:
        return subprocess.run([sys.executable, CTL, 'attest', root, owner, commit, path,
                               db_digest(cfg['osv_db']),
                               scanner_version(cfg['osv_scanner'])]).returncode
    finally:
        os.unlink(path)


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
            owner = (cfg.get('repos') or {}).get(url)
            if owner is None:
                print(f'stele_hook: {url} is not watched', flush=True)
                return
            print(f'stele_hook: push {url} @ {commit[:12]}; scanning', flush=True)
            try:
                report = scan_commit(url, commit, cfg['osv_scanner'], cfg['osv_db'])
                rc = attest(root, owner, commit, report, cfg)
                print(f'stele_hook: attested {commit[:12]} (rc={rc})', flush=True)
            except (subprocess.CalledProcessError, RuntimeError, ValueError) as err:
                print(f'stele_hook: scan of {commit[:12]} failed: {err}', flush=True)

        def log_message(self, fmt, *args):   # quiet; we print our own lines
            pass
    return Hook


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--root', required=True, help="the verifier node's root")
    ap.add_argument('--config', required=True)
    ap.add_argument('--host', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=8098)
    args = ap.parse_args(argv[1:])
    with open(args.config) as f:
        cfg = json.load(f)
    server = HTTPServer((args.host, args.port), make_handler(args.root, cfg))
    print(f'stele_hook: listening on {args.host}:{args.port}', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    sys.exit(main(sys.argv))
