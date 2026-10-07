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
"""stele_ctl: drive a steled node (Stele Phase 0) and check what it holds.

  stele_ctl.py uuid      ROOT
  stele_ctl.py pubkey    ROOT
  stele_ctl.py advertise ROOT NAME URL REF COMMIT [SEQ] [--description TEXT]
                         [--topics A,B] [--sbom PATH_IN_REPO=FILE] [--claim clean|vuln|none]
  stele_ctl.py attest    ROOT OWNER_UUID COMMIT REPORT_JSON DB_DIGEST [SCANNER_VERSION]
                         [--scanner NAME] [--channel CH] [--url CLONED_URL]
                         [--replicates ATTESTATION_ID]
  stele_ctl.py rebut     ROOT ATTESTATION_ID TEXT
  stele_ctl.py reputation ROOT SUBJECT_UUID
  stele_ctl.py verify    ROOT SUBJECT_UUID [--bundle FILE] [--key UUID=PUBHEX ...]
  stele_ctl.py standing  ROOT CLONE_URL [--bundle FILE]
  stele_ctl.py search    ROOT TEXT
  stele_ctl.py bundle    ROOT CLONE_URL

ROOT is the node's $AUTONOMOUS_TRUST_ROOT. `advertise` and `attest` send
at-stele's app verbs through libstele_shim ($STELE_SHIM, default
../native/build/libstele_shim.so). `attest` reads one scanner's JSON report
and reduces it with that scanner's summary (../verifier/scanners.py; the
default is osv-scanner): a verdict, a count, the worst severity, and the
findings digest, sha256 over the report's normalized JSON. The report itself
is kept as ROOT/etc/stele/reports/<findings_digest>.json, so the document an
attestation names can be published and checked. `--channel` is the AT
evidence channel (probe, certificate or self_consistency), `--url` the URL the
verifier cloned, which the node checks against the ad's. `--replicates` names
another verifier's attestation this run re-ran (same commit, scanner, scanner
version and database); it makes the attestation a `replication`, which AT
admits only from a verifier at tier 3 in its co-signers' view. `advertise --sbom`
names the SBOM committed at PATH_IN_REPO and computes its digest from FILE.

`verify` is the "off the owner's hand" check, run on an observer. Without
--key it reads the node's durable attested records (etc/at/attested/*.json),
which AutonomousTrust writes once a quorum-signed checkpoint covers an
attested entry, plus any records in a --bundle, and checks each one about
SUBJECT with AT's own verify_attested_record AGAINST THE NODE'S ROSTER
(etc/at/roster.cfg.json): every key comes from the roster, never from the
record, and the checkpoint must be this group's. Then the entry is in the
checkpoint's window, the checkpoint carries a quorum, and the attestation
carries its verifier plus a strict majority of the other members, the
subject's signature never counted. A node with no roster verifies nothing. It
exits 0 when at least one record about SUBJECT verifies.

`bundle` prints what an owner publishes as `.stele/standing.json` in its
repository: the records this node holds about the repository at CLONE_URL,
with the attestations and ads they name. A viewer believes it only as far as
its records verify against the VIEWER's roster (`verify --bundle`,
`standing --bundle`, or stele_view's POST /verify).

With --key (Phase 0's form, kept for its cohort phases) it reads the
observer's persisted reputation evidence (etc/at/reputation-history.cfg.json)
instead, and checks it against public keys supplied with --key (each node's
own `stele_ctl.py pubkey`):

  1. the chain's hash links verify;
  2. the checkpoint's root is the Merkle root of the entries it covers, and a
     majority of the keyring signed it;
  3. at least one verifier-attested entry about SUBJECT is in the chain, on
     the `probe` channel, and its certificate carries the verifier's own
     signature plus a strict majority of the non-subject members, the
     subject's never counted.

It prints a JSON report and exits 0 when all three hold, 1 otherwise.

`standing` and `search` print what the trust panel shows, folded by
../viewer/stele_view.py from the same records and the node's Stele store:
the standing of the repository advertised at CLONE_URL (exit 1 when the node
has not heard of it), and the heard repositories matching TEXT, best
standing first.
"""
import ctypes
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
VERIFIER = os.path.normpath(os.path.join(HERE, '..', 'verifier'))
AT_PY = os.environ.get('AT_PYTHON') or os.path.normpath(os.path.join(
    HERE, '..', '..', '..', 'lib', 'autonomous_trust', 'src', 'autonomous-trust'))
STELE_PY = os.path.normpath(os.path.join(HERE, '..', 'at-stele', 'python'))
for p in (AT_PY, STELE_PY, VERIFIER):
    if p not in sys.path:
        sys.path.insert(0, p)


def _identity(root):
    with open(os.path.join(root, 'etc', 'at', 'identity.cfg.json')) as f:
        return json.load(f)


def cmd_uuid(root):
    print(_identity(root)['uuid'])
    return 0


def cmd_pubkey(root):
    import ast
    import nacl.signing
    sig = _identity(root)['signature']
    seed = (ast.literal_eval(sig) if isinstance(sig, str) else sig)['hex_seed']
    print(nacl.signing.SigningKey(bytes.fromhex(seed)).verify_key.encode().hex())
    return 0


def _shim(root):
    path = os.environ.get('STELE_SHIM', os.path.join(HERE, '..', 'native', 'build',
                                                     'libstele_shim.so'))
    lib = ctypes.CDLL(path)
    lib.stele_set_root.argtypes = [ctypes.c_char_p]
    lib.stele_open.restype = ctypes.c_void_p
    lib.stele_open.argtypes = [ctypes.c_char_p]
    lib.stele_close.argtypes = [ctypes.c_void_p]
    lib.stele_advertise_repo.argtypes = [ctypes.c_char_p] * 5 + [ctypes.c_int64]
    lib.stele_attest.argtypes = [ctypes.c_char_p] * 8 + [ctypes.c_int64, ctypes.c_char_p]
    lib.stele_advertise_repo2.argtypes = ([ctypes.c_char_p] * 5 + [ctypes.c_int64]
                                          + [ctypes.c_char_p] * 5)
    lib.stele_attest2.argtypes = ([ctypes.c_char_p] * 8 + [ctypes.c_int64]
                                  + [ctypes.c_char_p] * 3)
    lib.stele_attest3.argtypes = ([ctypes.c_char_p] * 8 + [ctypes.c_int64]
                                  + [ctypes.c_char_p] * 4)
    lib.stele_rebut.argtypes = [ctypes.c_char_p] * 3
    lib.stele_set_root(root.encode())
    handle = lib.stele_open(b'at_to_extern')
    if not handle:
        raise SystemExit('cannot open the node\'s app channel (is steled running?)')
    return lib, handle


def _flags(args, names):
    """Split ``args`` into positionals and ``{flag: value}`` for ``names``."""
    pos, flags, it = [], {}, iter(args)
    for a in it:
        if a in names:
            flags[a] = next(it)
        else:
            pos.append(a)
    return pos, flags


def cmd_advertise(root, *args):
    pos, fl = _flags(args, ('--description', '--topics', '--sbom', '--claim'))
    name, url, ref, commit = pos[:4]
    seq = int(pos[4]) if len(pos) > 4 else 1
    sbom_path, sbom_digest = '', ''
    if '--sbom' in fl:
        sbom_path, _, local = fl['--sbom'].partition('=')
        with open(local or sbom_path, 'rb') as f:
            sbom_digest = hashlib.sha256(f.read()).hexdigest()
    lib, h = _shim(root)
    rc = lib.stele_advertise_repo2(
        b'extern_to_at', name.encode(), url.encode(), ref.encode(), commit.encode(),
        seq, fl.get('--description', '').encode(), fl.get('--topics', '').encode(),
        sbom_digest.encode(), sbom_path.encode(), fl.get('--claim', 'none').encode())
    time.sleep(0.5)
    lib.stele_close(h)
    return 0 if rc == 0 else 1


def summarize_osv(report):
    """osv-scanner's summary (scanners.summarize_osv), kept here by name."""
    import scanners
    return scanners.summarize_osv(report)


def keep_report(root, digest, report):
    """Keep a scanner's report as ROOT/etc/stele/reports/<digest>.json, once."""
    d = os.path.join(root, 'etc', 'stele', 'reports')
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, digest + '.json')
    if not os.path.exists(path):
        tmp = path + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(report, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    return path


def cmd_attest(root, owner, commit, report_json, db_digest, *rest):
    import scanners
    pos, fl = _flags(rest, ('--scanner', '--channel', '--url', '--replicates'))
    scanner_version = pos[0] if pos else 'unknown'
    scanner = fl.get('--scanner', 'osv-scanner')
    replicates = fl.get('--replicates')
    channel = fl.get('--channel', 'replication' if replicates
                     else scanners.CHANNELS.get(scanner, 'probe'))
    with open(report_json) as f:
        report = json.load(f)
    verdict, count, max_sev, digest = scanners.SUMMARIES[scanner](report)
    keep_report(root, digest, report)
    lib, h = _shim(root)
    url = fl.get('--url')
    rc = lib.stele_attest3(b'extern_to_at', owner.encode(), commit.encode(),
                           scanner.encode(), scanner_version[:32].encode(),
                           db_digest.encode(), digest.encode(), verdict.encode(),
                           count, max_sev[:16].encode(), channel.encode(),
                           url.encode() if url else None,
                           replicates.encode() if replicates else None)
    time.sleep(0.5)
    lib.stele_close(h)
    print(json.dumps({'scanner': scanner, 'channel': channel, 'verdict': verdict,
                      'count': count, 'max_severity': max_sev,
                      'findings_digest': digest, 'replicates': replicates}))
    return 0 if rc == 0 else 1


def cmd_rebut(root, attestation_id, text):
    lib, h = _shim(root)
    rc = lib.stele_rebut(b'extern_to_at', attestation_id.encode(), text.encode())
    time.sleep(0.5)
    lib.stele_close(h)
    return 0 if rc == 0 else 1


def cmd_reputation(root, subject):
    with open(os.path.join(root, 'etc', 'at', 'reputation.cfg.json')) as f:
        current = (json.load(f) or {}).get('current') or {}
    for k, v in current.items():
        if subject in str(k):
            print(json.dumps({'subject': subject, 'score': v}))
            return 0
    print(json.dumps({'subject': subject, 'score': None}))
    return 1


def _verifier(keys):
    import nacl.signing
    from nacl.exceptions import BadSignatureError

    def ok(voter, message, sig_hex):
        pk = keys.get(str(voter))
        if pk is None:
            return False
        try:
            nacl.signing.VerifyKey(bytes.fromhex(pk)).verify(message, bytes.fromhex(sig_hex))
            return True
        except (BadSignatureError, ValueError, TypeError):
            return False
    return ok


def verify(doc, subject, keys):
    """The check behind `verify`; returns the report dict."""
    from autonomous_trust.core.reputation.reputation import (
        AttestedScore, TransactionHistory, evidence_attest_certs, evidence_from_dict)
    ok_sig = _verifier(keys)
    report = {'subject': subject, 'links': False, 'checkpoint': False,
              'attested': [], 'ok': False}
    chain, signed = evidence_from_dict(doc)
    report['links'] = TransactionHistory.verify_chain_links(chain)
    ckpt = getattr(signed, 'checkpoint', None)
    if ckpt is not None:
        window = sorted((t for t in chain
                         if ckpt.first_index <= t.index < ckpt.first_index + ckpt.count),
                        key=lambda t: t.index)
        root = TransactionHistory._mth([t.entry_hash() for t in window])
        root = root.decode() if isinstance(root, bytes) else root
        want = ckpt.root.decode() if isinstance(ckpt.root, bytes) else ckpt.root
        signers = {v for v, s in (signed.sigs or {}).items()
                   if ok_sig(v, ckpt.designation, s)}
        report['checkpoint_signers'] = len(signers)
        report['checkpoint'] = (root == want and len(window) == ckpt.count
                                and len(signers) > len(keys) // 2)
    certs = evidence_attest_certs(doc)
    for tx in chain:
        if not tx.attested or str(tx.subject_id) != subject:
            continue
        att = AttestedScore.of_transaction(tx)
        sigs = certs.get(tx.task_id) or {}
        voters = {v for v, s in sigs.items()
                  if v != subject and ok_sig(v, att.designation, s)}
        others = len(keys) - (1 if subject in keys else 0)
        report['attested'].append({
            'index': tx.index, 'verifier': str(tx.p1_id), 'score': tx.p1_score,
            'channel': tx.p1_channel, 'evidence_digest': tx.evidence_digest,
            'cosigners': len(voters),
            'certified': str(tx.p1_id) in voters and len(voters) > others // 2,
            'in_checkpoint': ckpt is not None
            and ckpt.first_index <= tx.index < ckpt.first_index + ckpt.count})
    report['ok'] = (report['links'] and report['checkpoint']
                    and any(a['certified'] and a['channel'] == 'probe'
                            and a['in_checkpoint'] for a in report['attested']))
    return report


def verify_records(root, subject, bundle=None):
    """The check behind `verify` without --key, against the node's roster;
    returns the report dict. `bundle` adds records someone else handed over."""
    from autonomous_trust.core.reputation.reputation import (load_anchor,
                                                             verify_attested_record)
    anchor = load_anchor(root)
    report = {'subject': subject, 'records': [], 'unverified': 0, 'ok': False,
              'anchored': anchor is not None}
    adir = os.path.join(root, 'etc', 'at', 'attested')
    names = sorted(os.listdir(adir)) if os.path.isdir(adir) else []
    found = []
    for name in names:
        if not name.endswith('.json'):
            continue
        try:
            with open(os.path.join(adir, name)) as f:
                found.append((name[:-5], 'node', json.load(f)))
        except (OSError, ValueError):
            report['unverified'] += 1
    for rec in (bundle or {}).get('records') or []:
        task = ((rec.get('entry') or {}).get('task_id')
                if isinstance(rec, dict) else None)
        found.append((task, 'bundle', rec))
    for task, source, rec in found:
        entry = (rec.get('entry') or {}) if isinstance(rec, dict) else {}
        if str(entry.get('subject_id')) != subject:
            continue
        details = {}
        if anchor is None:
            ok, reasons = False, ['this node has no roster to verify against']
        else:
            ok, reasons = verify_attested_record(rec, anchor, details)
        report['unverified'] += 0 if ok else 1
        report['records'].append({
            'task': task, 'source': source, 'verified': ok,
            'linked': bool(details.get('linked')), 'reasons': list(reasons),
            'verifier': entry.get('p1_id'), 'score': entry.get('p1_score'),
            'channel': entry.get('p1_channel'),
            'evidence_digest': entry.get('evidence_digest'),
            'scope': entry.get('attest_scope'),
            'epoch': (rec.get('checkpoint') or {}).get('epoch')})
    report['ok'] = any(r['verified'] for r in report['records'])
    return report


def _bundle_arg(rest):
    """The JSON of a `--bundle FILE` among `rest`, or None."""
    it = iter(rest)
    for arg in it:
        if arg == '--bundle':
            with open(next(it)) as f:
                return json.load(f)
    return None


def cmd_verify(root, subject, *rest):
    keys = {}
    it = iter(rest)
    for arg in it:
        if arg == '--key':
            uid, _, pk = next(it).partition('=')
            keys[uid] = pk
    if not keys:
        report = verify_records(root, subject, _bundle_arg(rest))
        print(json.dumps(report, indent=2))
        return 0 if report['ok'] else 1
    with open(os.path.join(root, 'etc', 'at', 'reputation-history.cfg.json')) as f:
        doc = json.load(f)
    report = verify(doc, subject, keys)
    print(json.dumps(report, indent=2))
    return 0 if report['ok'] else 1


def _view(root):
    viewer = os.path.normpath(os.path.join(HERE, '..', 'viewer'))
    if viewer not in sys.path:
        sys.path.insert(0, viewer)
    import stele_view
    return stele_view.NodeView(root)


def cmd_standing(root, url, *rest):
    view = _view(root)
    bundle = _bundle_arg(rest)
    got = view.add_bundle(bundle) if bundle is not None else None
    st = view.standing_by_url(url)
    out = st or {'state': 'unknown', 'heard': False}
    if got is not None:
        out = dict(out, bundle=got)
    print(json.dumps(out, indent=2))
    return 0 if st else 1


def bundle_of(root, url):
    """The records this node holds about the repository at `url`, with the
    attestations and ads they name: what an owner publishes as
    .stele/standing.json. The format is stele_view's BUNDLE_SCHEMA."""
    def load(*parts):
        d = os.path.join(root, 'etc', *parts)
        out = {}
        for name in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if name.endswith('.json'):
                try:
                    with open(os.path.join(d, name)) as f:
                        out[name[:-5]] = json.load(f)
                except (OSError, ValueError):
                    continue
        return out
    ads = {i: a for i, a in load('stele', 'ads').items() if a.get('url') == url}
    ats = {i: a for i, a in load('stele', 'attestations').items()
           if a.get('repo_ad_id') in ads}
    recs = [r for r in load('at', 'attested').values()
            if (r.get('entry') or {}).get('evidence_digest') in ats]
    return {'schema': 'stele-bundle-1', 'url': url, 'records': recs,
            'attestations': list(ats.values()), 'ads': list(ads.values())}


def cmd_bundle(root, url):
    b = bundle_of(root, url)
    print(json.dumps(b, indent=2))
    return 0 if b['records'] else 1


def cmd_search(root, text):
    print(json.dumps({'results': _view(root).search(text)}, indent=2))
    return 0


COMMANDS = {'uuid': cmd_uuid, 'pubkey': cmd_pubkey, 'advertise': cmd_advertise,
            'attest': cmd_attest, 'rebut': cmd_rebut,
            'reputation': cmd_reputation, 'verify': cmd_verify,
            'standing': cmd_standing, 'search': cmd_search, 'bundle': cmd_bundle}


def main(argv):
    if len(argv) < 3 or argv[1] not in COMMANDS:
        print(__doc__, file=sys.stderr)
        return 64
    return COMMANDS[argv[1]](*argv[2:])


if __name__ == '__main__':
    sys.exit(main(sys.argv))
