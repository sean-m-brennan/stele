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
"""forge_bundle: the owner's forgeries for stele_redteam.sh (Attack 1).

Given the REAL standing bundle the observer would hand out (`stele_ctl.py
bundle`), writes two bundles an owner who wants a green badge could serve from
its forge as .stele/standing.json:

* ``forged.json``: a clean osv-scanner attestation about the owner's own ad,
  "verified" by a key the owner made, certified by that key alone and
  checkpointed by it, with the record saying the group had one member. It
  passes AutonomousTrust's verify_attested_record on its own terms.
* ``tampered.json``: the real bundle with the finding's committed score edited
  up to 0.8 and the attestation's verdict edited to clean.

  forge_bundle.py REAL_BUNDLE OUT_DIR

Prints one line per forgery: its name, and whether it verifies WITHOUT an
anchor (it should, for forged.json; the anchor is what refuses it).
"""
import copy
import json
import os
import sys
import time
from uuid import uuid4

HERE = os.path.dirname(os.path.abspath(__file__))
STELE = os.path.normpath(os.path.join(HERE, '..', '..'))
# `or`, not a get() default: an AT_PYTHON set but empty means "not given".
AT_PY = os.environ.get('AT_PYTHON') or os.path.normpath(os.path.join(
    STELE, '..', '..', 'lib', 'autonomous_trust', 'src', 'autonomous-trust'))
for p in (AT_PY, os.path.join(STELE, 'at-stele', 'python')):
    if p not in sys.path:
        sys.path.insert(0, p)

from nacl.encoding import HexEncoder  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

from autonomous_trust.core.reputation.reputation import (  # noqa: E402
    AttestedScore, Checkpoint, SignedCheckpoint, TransactionHistory,
    attested_record, evidence_to_dict, verify_attested_record)
from autonomous_trust.stele import codec  # noqa: E402


def _sig(key, designation) -> str:
    return key.sign(designation, encoder=HexEncoder).signature.decode('ascii')


def forged(real):
    env = real['ads'][0]
    ad, _ = codec.from_envelope(env, codec.AD_KEYS)
    key, me = SigningKey.generate(), str(uuid4())
    at = {'verifier': me, 'repo_ad_id': codec.repo_ad_id(ad), 'commit': ad['commit'],
          'scanner': 'osv-scanner', 'scanner_version': '2.6.0',
          'db_digest': '00' * 32, 'findings_digest': '11' * 32,
          'verdict': 'clean', 'count': 0, 'max_severity': '', 'ts': int(time.time()),
          'v': 2, 'channel': 'probe',
          'scope': codec.scope(ad['owner'], ad['name'], ad['commit'], 'osv-scanner')}
    at_id = codec.attestation_id(at)
    at_env = dict(at, sig=key.sign(codec.attestation_canonical(at)).signature.hex())
    hist = TransactionHistory()
    att = AttestedScore(verifier_uuid=me, subject_uuid=ad['owner'], score=0.8,
                        evidence_digest=at_id, attest_scope=at['scope'])
    if not hist.append_attested(att.to_transaction(), {me: _sig(key, att.designation)}):
        raise SystemExit('could not build the forged entry')
    window = hist._indexed_window()
    ck = Checkpoint(proposer_uuid=me, root=hist.window_root(), epoch=1,
                    first_index=window[0].index, count=len(window))
    doc = evidence_to_dict(hist, SignedCheckpoint(checkpoint=ck,
                                                  sigs={me: _sig(key, ck.designation)}),
                           hist.attest_certs)
    pk = key.verify_key.encode(encoder=HexEncoder).decode('ascii')
    rec = attested_record(doc, att.task_id, {me: pk}, 1, 1, False)
    return {'schema': real.get('schema', 'stele-bundle-1'), 'url': real.get('url'),
            'records': [rec], 'attestations': [at_env], 'ads': [env]}


def tampered(real):
    out = copy.deepcopy(real)
    for rec in out['records']:
        rec['entry']['p1_score'] = 0.8
    for at in out['attestations']:
        if at.get('verdict') == 'vuln':
            at.update(verdict='clean', count=0, max_severity='')
    return out


def main(argv):
    with open(argv[1]) as f:
        real = json.load(f)
    if not real.get('records') or not real.get('ads'):
        raise SystemExit('the real bundle holds no records')
    os.makedirs(argv[2], exist_ok=True)
    for name, b in (('forged', forged(real)), ('tampered', tampered(real))):
        with open(os.path.join(argv[2], name + '.json'), 'w') as f:
            json.dump(b, f, indent=2)
        alone = all(verify_attested_record(r)[0] for r in b['records'])
        print(f'{name}: verifies on its own terms: {alone}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
