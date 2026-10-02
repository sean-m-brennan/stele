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
  stele_ctl.py advertise ROOT NAME URL REF COMMIT [SEQ]
  stele_ctl.py attest    ROOT OWNER_UUID COMMIT OSV_JSON DB_DIGEST [SCANNER_VERSION]
  stele_ctl.py reputation ROOT SUBJECT_UUID
  stele_ctl.py verify    ROOT SUBJECT_UUID --key UUID=PUBHEX [--key ...]

ROOT is the node's $AUTONOMOUS_TRUST_ROOT. `advertise` and `attest` send
at-stele's app verbs through libstele_shim ($STELE_SHIM, default
../native/build/libstele_shim.so). `attest` reads an osv-scanner JSON report
(`osv-scanner scan source --format json`): the verdict is `vuln` with the count
of distinct vulnerabilities (after osv-scanner's alias merge) when it lists
any, else `clean`; the findings digest is sha256 over the report's normalized
JSON (see summarize_osv).

`verify` is the "off the owner's hand" check, run on an observer. It reads the
observer's persisted reputation evidence (etc/at/reputation-history.cfg.json)
with AutonomousTrust's own Python reader and checks, against public keys
supplied with --key (each node's own `stele_ctl.py pubkey`):

  1. the chain's hash links verify;
  2. the checkpoint's root is the Merkle root of the entries it covers, and a
     majority of the keyring signed it;
  3. at least one verifier-attested entry about SUBJECT is in the chain, on
     the `probe` channel, and its certificate carries the verifier's own
     signature plus a strict majority of the non-subject members, the
     subject's never counted.

It prints a JSON report and exits 0 when all three hold, 1 otherwise.
"""
import ctypes
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
AT_PY = os.environ.get('AT_PYTHON', os.path.normpath(os.path.join(
    HERE, '..', '..', '..', 'lib', 'autonomous_trust', 'src', 'autonomous-trust')))
STELE_PY = os.path.normpath(os.path.join(HERE, '..', 'at-stele', 'python'))
for p in (AT_PY, STELE_PY):
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
    lib.stele_set_root(root.encode())
    handle = lib.stele_open(b'at_to_extern')
    if not handle:
        raise SystemExit('cannot open the node\'s app channel (is steled running?)')
    return lib, handle


def cmd_advertise(root, name, url, ref, commit, seq='1'):
    lib, h = _shim(root)
    rc = lib.stele_advertise_repo(b'extern_to_at', name.encode(), url.encode(),
                                  ref.encode(), commit.encode(), int(seq))
    time.sleep(0.5)
    lib.stele_close(h)
    return 0 if rc == 0 else 1


def summarize_osv(report):
    """``(verdict, count, max_severity, findings_digest)`` from an osv-scanner
    JSON report.

    The count is distinct vulnerabilities after osv-scanner's alias merge (its
    per-package ``groups``; a GO- id and the GHSA/CVE it aliases are one
    finding), and max_severity the highest CVSS score among them (``groups[].
    max_severity``, e.g. "7.5"), or '' when none is scored. A report written
    without groups falls back to distinct vulnerability ids and the
    database-specific severity labels. The digest is sha256 over the report's
    normalized JSON."""
    groups, ids, labels = 0, set(), set()
    scores = []
    for result in report.get('results') or []:
        for pkg in result.get('packages') or []:
            for g in pkg.get('groups') or []:
                groups += 1
                try:
                    scores.append(float(g.get('max_severity') or ''))
                except ValueError:
                    pass
            for vuln in pkg.get('vulnerabilities') or []:
                if vuln.get('id'):
                    ids.add(vuln['id'])
                sev = (vuln.get('database_specific') or {}).get('severity') or ''
                labels.add(str(sev).upper())
    count = groups if groups else len(ids)
    if scores:
        max_sev = format(max(scores), 'g')
    else:
        order = ['CRITICAL', 'HIGH', 'MODERATE', 'MEDIUM', 'LOW']
        max_sev = next((s for s in order if s in labels), '')
    normalized = json.dumps(report, sort_keys=True, separators=(',', ':')).encode()
    digest = hashlib.sha256(normalized).hexdigest()
    return ('vuln' if count else 'clean'), count, max_sev, digest


def cmd_attest(root, owner, commit, osv_json, db_digest, scanner_version='unknown'):
    with open(osv_json) as f:
        verdict, count, max_sev, digest = summarize_osv(json.load(f))
    lib, h = _shim(root)
    rc = lib.stele_attest(b'extern_to_at', owner.encode(), commit.encode(),
                          b'osv-scanner', scanner_version[:32].encode(),
                          db_digest.encode(), digest.encode(), verdict.encode(),
                          count, max_sev.encode())
    time.sleep(0.5)
    lib.stele_close(h)
    print(json.dumps({'verdict': verdict, 'count': count, 'max_severity': max_sev,
                      'findings_digest': digest}))
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


def cmd_verify(root, subject, *rest):
    keys = {}
    it = iter(rest)
    for arg in it:
        if arg == '--key':
            uid, _, pk = next(it).partition('=')
            keys[uid] = pk
    with open(os.path.join(root, 'etc', 'at', 'reputation-history.cfg.json')) as f:
        doc = json.load(f)
    report = verify(doc, subject, keys)
    print(json.dumps(report, indent=2))
    return 0 if report['ok'] else 1


COMMANDS = {'uuid': cmd_uuid, 'pubkey': cmd_pubkey, 'advertise': cmd_advertise,
            'attest': cmd_attest, 'reputation': cmd_reputation, 'verify': cmd_verify}


def main(argv):
    if len(argv) < 3 or argv[1] not in COMMANDS:
        print(__doc__, file=sys.stderr)
        return 64
    return COMMANDS[argv[1]](*argv[2:])


if __name__ == '__main__':
    sys.exit(main(sys.argv))
