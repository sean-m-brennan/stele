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
                         [--provides PURL]
  stele_ctl.py attest    ROOT OWNER_UUID COMMIT REPORT_JSON DB_DIGEST [SCANNER_VERSION]
                         [--scanner NAME] [--channel CH] [--url CLONED_URL]
                         [--replicates ATTESTATION_ID]
  stele_ctl.py rebut     ROOT ATTESTATION_ID TEXT
  stele_ctl.py consent   ROOT ISSUER_HEX DID
  stele_ctl.py team      ROOT ROSTER_FILE
  stele_ctl.py guardian  ROOT ATTESTATION_ID
  stele_ctl.py team-standing ROOT ISSUER_HEX [--profile NAME]
  stele_ctl.py reputation ROOT SUBJECT_UUID
  stele_ctl.py verify    ROOT SUBJECT_UUID [--bundle FILE] [--key UUID=PUBHEX ...]
  stele_ctl.py standing  ROOT CLONE_URL [--bundle FILE] [--profile NAME]
  stele_ctl.py search    ROOT TEXT [--profile NAME]
  stele_ctl.py bundle    ROOT CLONE_URL [--profile SIGNED_PROFILE_FILE]
  stele_ctl.py profile-show     ROOT [NAME|followed]
  stele_ctl.py profile-follow   ROOT SIGNED_PROFILE_FILE [--replace]
  stele_ctl.py profile-unfollow ROOT
  stele_ctl.py profile-use      ROOT NAME|followed
  stele_ctl.py sbom-add   ROOT FILE
  stele_ctl.py sbom-fetch ROOT CLONE_URL
  stele_ctl.py deps-pin   ROOT PURL CLONE_URL
  stele_ctl.py deps-unpin ROOT PURL [CLONE_URL]
  stele_ctl.py anchor-consent  ROOT ISSUER_HEX GROUP_UUID
  stele_ctl.py anchor-follow   ROOT ANCHOR_FILE
  stele_ctl.py anchor-unfollow ROOT ISSUER_HEX
  stele_ctl.py anchor-show     ROOT [ISSUER_HEX]
  stele_ctl.py anchor-publish  ROOT ANCHOR_FILE
  stele_ctl.py relay-search    ROOT TEXT [--wait SEC]
  stele_ctl.py relay-fetch     ROOT CLONE_URL [--wait SEC]
  stele_ctl.py relay-publish   ROOT
  stele_ctl.py relay-standing  ROOT CLONE_URL [--fresh 0|1] [--profile NAME]
  stele_ctl.py relay-results   ROOT TEXT [--fresh 0|1] [--profile NAME]

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

Teams (Phase 3). `consent` prints this node's consent to being listed on the
team whose root key is ISSUER_HEX as DID: its uuid and its AT key's signature
over "stele-team-member-v1|issuer|did|uuid", for the team's roster.
`team` hands the node a roster file (Ethne's stele_team_roster); the node
holds it once the root signature and every member's consent verify, and
multicasts it. `advertise --polity ISSUER_HEX --release FILE` advertises a
team release with the officer's release authorization (Ethne's
stele_release_authorization); the node must be that officer's. `guardian`
lands the held finding ATTESTATION_ID on the guardian of the machine that
built its team release. `team-standing` prints the team's worst-of standing.

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

Profiles (Phase 4). `--profile` reads a standing under another profile
(../viewer/stele_profile.py): a built-in name (stele-default, stele-strict),
the node operator's own from ROOT/etc/stele/profiles/NAME.json, or `followed`.
Without it the node's preference applies (`profile-use`), else stele-default.
`profile-follow` follows the polity that signed SIGNED_PROFILE_FILE (Ethne's
stele_profile, border artifact #11): it pins the issuer's key, and afterwards
only a higher seq from that key replaces the profile; following a different
polity needs --replace. `profile-show` prints a profile and where it came from.
`bundle --profile` adds a signed profile to the bundle; a viewer takes it only
when it already follows that issuer and the bundle's is newer. Every command
here exits 2 for a profile that cannot be applied.

Supply chain (Phase 4). `advertise --provides PURL` advertises a v4 ad naming
the package the repository publishes as (a purl without a version, e.g.
pkg:golang/forge.local/alice/demo); verifiers check it against the
repository's manifest. A standing lists the repository's dependencies from the
SBOM its ad pins (../viewer/stele_deps.py), which this node must hold:
`advertise --sbom` keeps the owner's, a verifier keeps the ones it checked,
`sbom-add` keeps a file, `sbom-fetch` reads the one the newest ad at CLONE_URL
pins from the forge (Forgejo's raw path at the ad's commit), and a bundle
carries the repository's own. Each is kept only if its bytes hash to the
digest. `deps-pin` resolves a package to repositories of this reader's
choosing in place of every ad that claims it; `deps-unpin` drops that.

Other groups (Phase 4, discovery relays). A record from another AT group
verifies against keys this node does not hold, so it verifies only under a
polity's GROUP ANCHOR (Ethne D43, ../viewer/stele_anchors.py) that this reader
follows. `anchor-consent` prints this node's consent to being listed, under its
own AT key, in the anchor the polity with root ISSUER_HEX mints for the group
GROUP_UUID; the polity collects one from each node. `anchor-follow` follows the
polity that signed ANCHOR_FILE (pinning its root key) or takes its newer anchor;
only a higher seq replaces one. `anchor-unfollow` stops following; `anchor-show`
prints what is followed. `anchor-publish` has this node file ANCHOR_FILE (its
polity's anchor) at its relays from now on.

Discovery relays. `relay-search` and `relay-fetch` ask every relay the node is
connected to (the stl_ op family, at-stele/c/stele/stele_relay.h) and print the
merged answers, which the node writes to
ROOT/etc/stele/relay/<search|fetch>-<rid>.json; `--wait` (default 15) is how
long to wait for them. A relay's answers are claims and its ranking is its own
word: ../viewer/stele_view.py verifies them. `relay-publish` files what the
node holds at its own relays now, as it does whenever it registers.
`relay-standing` and `relay-results` print what the viewer makes of the
relays' answers (stele_view's /relay/standing and /relay/search): with
`--fresh 1` (the default) the node asks again first.
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
    lib.stele_publish_team.argtypes = [ctypes.c_char_p] * 2
    lib.stele_advertise_repo3.argtypes = ([ctypes.c_char_p] * 5 + [ctypes.c_int64]
                                          + [ctypes.c_char_p] * 7)
    lib.stele_attest_guardian.argtypes = [ctypes.c_char_p] * 2
    lib.stele_advertise_repo4.argtypes = ([ctypes.c_char_p] * 5 + [ctypes.c_int64]
                                          + [ctypes.c_char_p] * 8)
    lib.stele_relay_search.argtypes = [ctypes.c_char_p] * 2
    lib.stele_relay_fetch.argtypes = [ctypes.c_char_p] * 2
    lib.stele_relay_publish.argtypes = [ctypes.c_char_p]
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
    pos, fl = _flags(args, ('--description', '--topics', '--sbom', '--claim',
                            '--polity', '--release', '--provides'))
    name, url, ref, commit = pos[:4]
    seq = int(pos[4]) if len(pos) > 4 else 1
    sbom_path, sbom_digest = '', ''
    if '--sbom' in fl:
        sbom_path, _, local = fl['--sbom'].partition('=')
        with open(local or sbom_path, 'rb') as f:
            raw = f.read()
        sbom_digest = hashlib.sha256(raw).hexdigest()
        _deps_module().keep_sbom(root, raw)   # so this node's bundle carries it
    lib, h = _shim(root)
    common = (b'extern_to_at', name.encode(), url.encode(), ref.encode(),
              commit.encode(), seq, fl.get('--description', '').encode(),
              fl.get('--topics', '').encode(), sbom_digest.encode(),
              sbom_path.encode(), fl.get('--claim', 'none').encode())
    release = b''
    if '--polity' in fl or '--release' in fl:
        with open(fl['--release']) as f:
            release = f.read().strip().encode()
    if '--provides' in fl:
        rc = lib.stele_advertise_repo4(*common, fl.get('--polity', '').encode(),
                                       release, fl['--provides'].encode())
    elif release:
        rc = lib.stele_advertise_repo3(*common, fl['--polity'].encode(), release)
    else:
        rc = lib.stele_advertise_repo2(*common)
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


def _signing_key(root):
    import ast
    import nacl.signing
    sig = _identity(root)['signature']
    seed = (ast.literal_eval(sig) if isinstance(sig, str) else sig)['hex_seed']
    return nacl.signing.SigningKey(bytes.fromhex(seed))


def consent(root, issuer, did):
    """This node's consent to being listed on the team `issuer` as `did`."""
    uid = _identity(root)['uuid']
    msg = ('stele-team-member-v1|%s|%s|%s' % (issuer, did, uid)).encode()
    return {'did': did, 'at_uuid': uid,
            'consent': _signing_key(root).sign(msg).signature.hex()}


def cmd_consent(root, issuer, did):
    print(json.dumps(consent(root, issuer, did)))
    return 0


def cmd_team(root, roster_file):
    with open(roster_file) as f:
        roster = f.read().strip()
    lib, h = _shim(root)
    rc = lib.stele_publish_team(b'extern_to_at', roster.encode())
    time.sleep(0.5)
    lib.stele_close(h)
    return 0 if rc == 0 else 1


def cmd_guardian(root, attestation_id):
    lib, h = _shim(root)
    rc = lib.stele_attest_guardian(b'extern_to_at', attestation_id.encode())
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


def _viewer_modules():
    viewer = os.path.normpath(os.path.join(HERE, '..', 'viewer'))
    if viewer not in sys.path:
        sys.path.insert(0, viewer)
    import stele_profile
    import stele_view
    return stele_view, stele_profile


def _deps_module():
    viewer = os.path.normpath(os.path.join(HERE, '..', 'viewer'))
    if viewer not in sys.path:
        sys.path.insert(0, viewer)
    import stele_deps
    return stele_deps


def _flag(rest, name):
    """The value after `name` among `rest`, or None."""
    it = iter(rest)
    for arg in it:
        if arg == name:
            return next(it, None)
    return None


class _ProfileExit(Exception):
    pass


def _view(root, rest=()):
    stele_view, stele_profile = _viewer_modules()
    try:
        return stele_view.NodeView(root, profile=_flag(rest, '--profile'))
    except stele_profile.ProfileError as e:
        print(json.dumps({'error': str(e)}), file=sys.stderr)
        raise _ProfileExit()


def cmd_standing(root, url, *rest):
    view = _view(root, rest)
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
    # The rosters of the teams these releases are attributed to (Phase 3), so
    # a viewer can check the release and leave the teammates out of quorums.
    polities = {a.get('polity') for i, a in load('stele', 'attributions').items()
                if i in ads}
    teams = [t['roster'] for i, t in load('stele', 'teams').items()
             if i in polities and isinstance(t.get('roster'), str)]
    # The SBOMs these ads pin (Phase 4), as their exact text, so a viewer
    # can list the repository's dependencies.
    sd = os.path.join(root, 'etc', 'stele', 'sboms')
    sboms = {}
    for d in sorted({a.get('sbom_digest') for a in ads.values()} - {None, ''}):
        try:
            with open(os.path.join(sd, d + '.json'), 'rb') as f:
                sboms[d] = f.read().decode('utf-8')
        except (OSError, UnicodeDecodeError):
            continue
    return {'schema': 'stele-bundle-1', 'url': url, 'records': recs,
            'attestations': list(ats.values()), 'ads': list(ads.values()),
            'teams': teams, 'sboms': sboms}


def cmd_bundle(root, url, *rest):
    b = bundle_of(root, url)
    signed = _flag(rest, '--profile')
    if signed:
        with open(signed) as f:
            b['profile'] = f.read().strip()
    print(json.dumps(b, indent=2))
    return 0 if b['records'] else 1


def cmd_team_standing(root, issuer, *rest):
    st = _view(root, rest).team_standing(issuer)
    print(json.dumps(st or {'state': 'unknown', 'heard': False}, indent=2))
    return 0 if st else 1


def cmd_search(root, text, *rest):
    print(json.dumps({'results': _view(root, rest).search(text)}, indent=2))
    return 0


def _profile_cmd(fn):
    """Run a profile command, printing its result, exiting 2 on a profile
    that cannot be applied."""
    _sv, stele_profile = _viewer_modules()
    try:
        out = fn(stele_profile)
    except stele_profile.ProfileError as e:
        print(json.dumps({'error': str(e)}), file=sys.stderr)
        return 2
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def cmd_profile_show(root, choice=None):
    def show(sp):
        profile, meta = sp.load(root, choice)
        return {'profile': profile, 'meta': meta}
    return _profile_cmd(show)


def cmd_profile_follow(root, path, *rest):
    def follow(sp):
        with open(path) as f:
            got = sp.follow(root, f.read().strip(), replace='--replace' in rest)
        return {'following': got['issuer'], 'polity': got['polity'],
                'seq': got['seq'], 'profile': got['profile']}
    return _profile_cmd(follow)


def cmd_profile_unfollow(root):
    return _profile_cmd(lambda sp: {'unfollowed': sp.unfollow(root)})


def cmd_profile_use(root, choice):
    def use(sp):
        sp.use(root, choice)
        profile, meta = sp.load(root)
        return {'use': choice, 'profile': profile, 'meta': meta}
    return _profile_cmd(use)


def anchor_consent(root, issuer, group_uuid):
    """This node's consent to being listed in the group anchor `issuer` mints
    for `group_uuid`, under its own AT key."""
    uid = _identity(root)['uuid']
    sk = _signing_key(root)
    pubkey = bytes(sk.verify_key).hex()
    msg = ('stele-anchor-member-v1|%s|%s|%s|%s' % (issuer, group_uuid, uid, pubkey)).encode()
    return {'at_uuid': uid, 'pubkey': pubkey, 'consent': sk.sign(msg).signature.hex()}


def cmd_anchor_consent(root, issuer, group_uuid):
    print(json.dumps(anchor_consent(root, issuer, group_uuid)))
    return 0


def _anchors_module():
    viewer = os.path.normpath(os.path.join(HERE, '..', 'viewer'))
    if viewer not in sys.path:
        sys.path.insert(0, viewer)
    import stele_anchors
    return stele_anchors


def _summary(a):
    return {'issuer': a['issuer'], 'polity': a['polity'], 'seq': a['seq'],
            'group_uuid': a['group_uuid'], 'members': len(a['members']),
            'checkpoints': len(a['checkpoints'])}


def cmd_anchor_follow(root, path):
    sa = _anchors_module()
    with open(path) as f:
        text = f.read().strip()
    try:
        a = sa.follow(root, text)
    except sa.AnchorError as e:
        print(json.dumps({'error': str(e)}), file=sys.stderr)
        return 1
    print(json.dumps({'following': _summary(a)}, indent=2))
    return 0


def cmd_anchor_unfollow(root, issuer):
    print(json.dumps({'unfollowed': _anchors_module().unfollow(root, issuer)}))
    return 0


def cmd_anchor_show(root, issuer=None):
    held = _anchors_module().followed(root)
    out = [_summary(a) for i, (a, _t) in sorted(held.items()) if issuer in (None, i)]
    print(json.dumps({'followed': out}, indent=2))
    return 0 if out or issuer is None else 1


def relay_rid(kind, query):
    """The id a node files a relay answer under: the first 16 hex of
    sha256(kind|query). Mirrors stele_relay_net.c."""
    return hashlib.sha256(('%s|%s' % (kind, query)).encode('utf-8')).hexdigest()[:16]


def relay_result_path(root, kind, query):
    return os.path.join(root, 'etc', 'stele', 'relay',
                        '%s-%s.json' % (kind, relay_rid(kind, query)))


def _relay_ask(root, kind, query, rest):
    wait = float(_flag(rest, '--wait') or 15)
    path = relay_result_path(root, kind, query)
    try:
        os.unlink(path)
    except OSError:
        pass
    lib, h = _shim(root)
    send = lib.stele_relay_search if kind == 'search' else lib.stele_relay_fetch
    rc = send(b'extern_to_at', query.encode())
    deadline = time.time() + wait
    while rc == 0 and not os.path.exists(path) and time.time() < deadline:
        time.sleep(0.25)
    lib.stele_close(h)
    try:
        with open(path) as f:
            doc = json.load(f)
    except (OSError, ValueError):
        print(json.dumps({'error': 'no answer from the node in %gs' % wait}), file=sys.stderr)
        return 1
    print(json.dumps(doc, indent=2))
    return 0


def cmd_relay_search(root, text, *rest):
    return _relay_ask(root, 'search', text, rest)


def cmd_relay_fetch(root, url, *rest):
    return _relay_ask(root, 'fetch', url, rest)


def _relay_view(root, kind, query, rest):
    stele_view, _sp = _viewer_modules()
    fresh = (_flag(rest, '--fresh') or '1') != '0'
    doc = (stele_view.ask_relays(root, kind, query) if fresh
           else stele_view.relay_answer(root, kind, query))
    view = _view(root, rest)
    if kind == 'fetch':
        out = view.relay_standing(doc, query)
        print(json.dumps(out, indent=2))
        return 0 if out['standing'].get('heard', True) else 1
    print(json.dumps(view.relay_search(doc), indent=2))
    return 0


def cmd_relay_standing(root, url, *rest):
    return _relay_view(root, 'fetch', url, rest)


def cmd_relay_results(root, text, *rest):
    return _relay_view(root, 'search', text, rest)


def cmd_relay_publish(root):
    lib, h = _shim(root)
    rc = lib.stele_relay_publish(b'extern_to_at')
    time.sleep(0.5)
    lib.stele_close(h)
    return 0 if rc == 0 else 1


def cmd_anchor_publish(root, path):
    sa = _anchors_module()
    with open(path) as f:
        text = f.read().strip()
    try:
        a = sa.parse(text)
    except sa.AnchorError as e:
        print(json.dumps({'error': str(e)}), file=sys.stderr)
        return 1
    d = os.path.join(root, 'etc', 'stele', 'published-anchors')
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, a['issuer'] + '.json.tmp')
    with open(tmp, 'w') as f:
        json.dump({'text': text}, f)
    os.replace(tmp, os.path.join(d, a['issuer'] + '.json'))
    print(json.dumps({'publishing': _summary(a)}, indent=2))
    return 0


def cmd_sbom_add(root, path):
    with open(path, 'rb') as f:
        digest = _deps_module().keep_sbom(root, f.read())
    print(json.dumps({'kept': digest}))
    return 0 if digest else 1


def _newest_ad(root, url):
    best = None
    d = os.path.join(root, 'etc', 'stele', 'ads')
    for name in os.listdir(d) if os.path.isdir(d) else []:
        try:
            with open(os.path.join(d, name)) as f:
                ad = json.load(f)
        except (OSError, ValueError):
            continue
        if ad.get('url') == url and (best is None or (ad.get('seq', 0), ad.get('ts', 0))
                                     > (best.get('seq', 0), best.get('ts', 0))):
            best = ad
    return best


def raw_sbom_url(ad):
    """Where Forgejo serves the SBOM an ad pins: its raw path at the ad's
    commit."""
    base = ad['url'][:-4] if ad['url'].endswith('.git') else ad['url']
    return '%s/raw/commit/%s/%s' % (base.rstrip('/'), ad['commit'],
                                    ad['sbom_path'].lstrip('/'))


def cmd_sbom_fetch(root, url, *rest):
    import urllib.request
    ad = _newest_ad(root, url)
    if ad is None or not ad.get('sbom_digest'):
        print(json.dumps({'error': 'no held ad at %s pins an SBOM' % url}), file=sys.stderr)
        return 1
    deps = _deps_module()
    try:
        with urllib.request.urlopen(raw_sbom_url(ad), timeout=20) as r:
            raw = r.read(deps.SBOM_MAX + 1)
    except OSError as e:
        print(json.dumps({'error': 'fetch failed: %s' % e}), file=sys.stderr)
        return 1
    if hashlib.sha256(raw).hexdigest() != ad['sbom_digest']:
        print(json.dumps({'error': 'the forge served bytes the ad does not pin'}),
              file=sys.stderr)
        return 1
    print(json.dumps({'kept': deps.keep_sbom(root, raw)}))
    return 0


def cmd_deps_pin(root, purl, url):
    try:
        print(json.dumps(_deps_module().pin(root, purl, url), indent=2, sort_keys=True))
    except ValueError as e:
        print(json.dumps({'error': str(e)}), file=sys.stderr)
        return 1
    return 0


def cmd_deps_unpin(root, purl, url=None):
    print(json.dumps(_deps_module().unpin(root, purl, url), indent=2, sort_keys=True))
    return 0


COMMANDS = {'uuid': cmd_uuid, 'pubkey': cmd_pubkey, 'advertise': cmd_advertise,
            'attest': cmd_attest, 'rebut': cmd_rebut,
            'reputation': cmd_reputation, 'verify': cmd_verify,
            'standing': cmd_standing, 'search': cmd_search, 'bundle': cmd_bundle,
            'consent': cmd_consent, 'team': cmd_team, 'guardian': cmd_guardian,
            'team-standing': cmd_team_standing,
            'profile-show': cmd_profile_show, 'profile-follow': cmd_profile_follow,
            'profile-unfollow': cmd_profile_unfollow, 'profile-use': cmd_profile_use,
            'sbom-add': cmd_sbom_add, 'sbom-fetch': cmd_sbom_fetch,
            'deps-pin': cmd_deps_pin, 'deps-unpin': cmd_deps_unpin,
            'anchor-consent': cmd_anchor_consent, 'anchor-follow': cmd_anchor_follow,
            'anchor-unfollow': cmd_anchor_unfollow, 'anchor-show': cmd_anchor_show,
            'anchor-publish': cmd_anchor_publish, 'relay-search': cmd_relay_search,
            'relay-fetch': cmd_relay_fetch, 'relay-publish': cmd_relay_publish,
            'relay-standing': cmd_relay_standing, 'relay-results': cmd_relay_results}


def main(argv):
    if len(argv) < 3 or argv[1] not in COMMANDS:
        print(__doc__, file=sys.stderr)
        return 64
    try:
        return COMMANDS[argv[1]](*argv[2:])
    except _ProfileExit:
        return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
