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
"""stele_team: a team's files for Stele (Phase 3), from a team spec.

  stele_team.py roster  SPEC OUT              the team roster, at the spec's seq
  stele_team.py release SPEC REPO URL COMMIT OUT [--built-by NAME]
                                              one release authorization, by the
                                              spec's first officer
  stele_team.py issuer  SPEC                  the team's root key (hex)
  stele_team.py profile SPEC OUT              the polity's signed Stele profile
                                              (Phase 4, Ethne D42), at the
                                              spec's profile_seq
  stele_team.py anchor  SPEC OUT              the polity's group anchor (Phase 4,
                                              Ethne D43), at the spec's anchor_seq

SPEC is JSON:

  {"root": "<file holding the root key's 32-byte seed, hex; made if absent>",
   "members": {"<name>": "<that member's AT node root>", ...},
   "officers": ["<name>"],
   "guardians": {"<machine name>": "<guardian name>"},
   "seq": 1,
   "consent_by": {"<name>": "<name whose node key signs its consent>"},
   "profile": {<a Stele profile: the fields it changes from stele-default>},
   "profile_seq": 1,
   "anchor_from": "<the AT node root whose roster the anchor is read from>",
   "anchor_nodes": {"<name>": "<an AT node root that consents>", ...},
   "anchor_seq": 1}

A member's DID is its AT node's own key (ethne design D33), its node uuid and
consent come from its node root (etc/at/identity.cfg.json), and an officer
signs releases with that key. `consent_by` forges a consent, for the red team.

When an Ethne build with design D41 is importable, the polity is founded in an
Ethne archive (the members ratify, the roll confers ReleaseOfficer, the
guardian edges are designated, the officer authorizes each release) and the
files are Ethne's own emitters' output. Otherwise an equivalent emitter here
writes the same formats (`--builtin` forces it). Either way Stele checks the
files with keys alone.

`profile` writes the polity's Stele profile (border artifact #11). On the
Ethne path the roll amends the profile `profile_seq` times (all members
deciding), so the file's seq is Ethne's count of accepted amendments and
`set_by` is the last amendment's CID. The built-in emitter writes the same
body with a `set_by` it cannot know (`builtin:` plus a digest), which Stele
does not read.

`anchor` writes the polity's group anchor (border artifact #12): the AT group
of the node at `anchor_from`, as its roster holds it (group uuid, each member's
key and tier, the checkpoints), listing the members whose nodes consent. Each
node in `members` and `anchor_nodes` consents with its own AT key; a roster
member with no consent is left out, since the root cannot list a node that
did not agree. Both emitters write the same bytes.
"""
import ast
import json
import os
import sys

import nacl.signing

TEAM_DOMAIN = b'stele-team-v1|'
PROFILE_DOMAIN = b'stele-profile-v1|'
VIEWER = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       '..', 'viewer'))
RELEASE_DOMAIN = b'stele-release-v1|'
_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def did_of(pub: bytes) -> str:
    """did:key for an ed25519 key (multicodec 0xed01, multibase base58btc)."""
    raw = b'\xed\x01' + pub
    n = int.from_bytes(raw, 'big')
    out = ''
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    out = '1' * (len(raw) - len(raw.lstrip(b'\0'))) + out
    return 'did:key:z' + out


def node_key(root):
    """(uuid, signing key) of the AT node at `root`."""
    with open(os.path.join(root, 'etc', 'at', 'identity.cfg.json')) as f:
        ident = json.load(f)
    sig = ident['signature']
    seed = (ast.literal_eval(sig) if isinstance(sig, str) else sig)['hex_seed']
    return ident['uuid'], nacl.signing.SigningKey(bytes.fromhex(seed))


def root_key(spec):
    path = spec['root']
    if not os.path.exists(path):
        with open(path, 'w') as f:
            f.write(os.urandom(32).hex())
    with open(path) as f:
        return nacl.signing.SigningKey(bytes.fromhex(f.read().strip()))


def _members(spec, issuer):
    """[(name, did, uuid, key, consent hex)] for the spec's members."""
    keys = {n: node_key(r) for n, r in spec['members'].items()}
    out = []
    for name, (uid, sk) in keys.items():
        did = did_of(bytes(sk.verify_key))
        signer = keys[(spec.get('consent_by') or {}).get(name, name)][1]
        msg = ('stele-team-member-v1|%s|%s|%s' % (issuer, did, uid)).encode()
        out.append((name, did, uid, sk, signer.sign(msg).signature.hex()))
    return out


def _signed(domain, body, key):
    text = json.dumps(body, separators=(',', ':'))
    return json.dumps({'body': text, 'sig': key.sign(domain + text.encode()).signature.hex()},
                      separators=(',', ':'))


# ---------------- the built-in emitter (the formats of Ethne's `stele` module) ----------------

def builtin_roster(spec):
    root = root_key(spec)
    issuer = bytes(root.verify_key).hex()
    members = _members(spec, issuer)
    did = {n: d for n, d, _u, _k, _c in members}
    body = {'v': 1, 'typename': 'stele-team', 'polity': did_of(bytes(root.verify_key)),
            'issuer': issuer, 'seq': int(spec.get('seq', 1)),
            'members': sorted(({'did': d, 'key': bytes(k.verify_key).hex(), 'at_uuid': u,
                                'consent': c} for _n, d, u, k, c in members),
                              key=lambda m: m['did']),
            'release_officers': sorted(did[o] for o in spec.get('officers', [])),
            'guardians': sorted(({'machine': did[m], 'guardian': did[g]}
                                 for m, g in (spec.get('guardians') or {}).items()),
                                key=lambda e: e['machine'])}
    return _signed(TEAM_DOMAIN, body, root)


ANCHOR_DOMAIN = b'stele-anchor-v1|'


def anchor_inputs(spec, issuer):
    """(group_uuid, [(at_uuid, pubkey, tier, consent)], [(group_uuid, epoch,
    root, first_index, count)]) from the `anchor_from` node's roster, members
    sorted by uuid, as Ethne lists them."""
    with open(os.path.join(spec['anchor_from'], 'etc', 'at', 'roster.cfg.json')) as f:
        roster = json.load(f)
    group = roster['group_uuid']
    signers = {}
    for root in list(spec.get('members', {}).values()) + list(
            (spec.get('anchor_nodes') or {}).values()):
        uid, sk = node_key(root)
        signers[uid] = sk
    members = []
    for uid, m in sorted((roster.get('members') or {}).items()):
        sk = signers.get(uid)
        if not m.get('member') or sk is None or bytes(sk.verify_key).hex() != m.get('pubkey'):
            continue
        msg = ('stele-anchor-member-v1|%s|%s|%s|%s' % (issuer, group, uid, m['pubkey'])).encode()
        members.append((uid, m['pubkey'], int(m.get('tier') or 0),
                        sk.sign(msg).signature.hex()))
    cks = sorted({(c.get('group_uuid') or '', int(c['epoch']), c['root'],
                   int(c['first_index']), int(c['count']))
                  for c in roster.get('checkpoints') or []})
    if len(cks) > 512:   # the newest, across chains (Ethne's ANCHOR_CHECKPOINTS_MAX)
        keep = set(sorted(cks, key=lambda c: -c[1])[:512])
        cks = [c for c in cks if c in keep]
    return group, members, cks


def builtin_anchor(spec):
    root = root_key(spec)
    issuer = bytes(root.verify_key).hex()
    group, members, cks = anchor_inputs(spec, issuer)
    body = {'v': 1, 'typename': 'stele-group-anchor', 'polity': did_of(bytes(root.verify_key)),
            'issuer': issuer, 'seq': int(spec.get('anchor_seq', 1)), 'group_uuid': group,
            'members': [{'at_uuid': u, 'pubkey': k, 'tier': t, 'consent': c}
                        for u, k, t, c in members],
            'checkpoints': [{'group_uuid': g, 'epoch': e, 'root': r, 'first_index': f,
                             'count': n} for g, e, r, f, n in cks]}
    return _signed(ANCHOR_DOMAIN, body, root)


def builtin_release(spec, repo, url, commit, built_by=None):
    root = root_key(spec)
    officer = spec['officers'][0]
    _uid, sk = node_key(spec['members'][officer])
    body = {'v': 1, 'typename': 'stele-release', 'polity': did_of(bytes(root.verify_key)),
            'issuer': bytes(root.verify_key).hex(), 'officer': did_of(bytes(sk.verify_key)),
            'officer_key': bytes(sk.verify_key).hex(), 'repo': repo, 'url': url,
            'commit': commit}
    if built_by:
        body['built_by'] = did_of(bytes(node_key(spec['members'][built_by])[1].verify_key))
    body['authorized_at'] = 300
    return _signed(RELEASE_DOMAIN, body, sk)


def spec_profile(spec):
    """The spec's profile, complete and inside Stele's floors, in the field
    order Ethne serializes it in. Ethne writes ``deps`` only when it is
    ``worst``, so a profile that leaves it at ``show`` keeps D42's bytes."""
    if VIEWER not in sys.path:
        sys.path.insert(0, VIEWER)
    import stele_profile
    p = stele_profile.parse(spec.get('profile') or {})
    return {k: p[k] for k in stele_profile.FIELDS
            if not (k == 'deps' and p[k] == 'show')}


def builtin_profile(spec):
    import hashlib
    root = root_key(spec)
    profile = spec_profile(spec)
    body = {'v': 1, 'typename': 'stele-profile', 'polity': did_of(bytes(root.verify_key)),
            'issuer': bytes(root.verify_key).hex(), 'seq': int(spec.get('profile_seq', 1)),
            'set_by': 'builtin:' + hashlib.sha256(
                json.dumps(profile, separators=(',', ':')).encode()).hexdigest()[:32],
            'profile': profile}
    return _signed(PROFILE_DOMAIN, body, root)


# ---------------- the Ethne path (design D41) ----------------

def _ethne():
    try:
        import ethne
        from ethne import _core
    except ImportError:
        return None
    if not hasattr(ethne, 'stele_team_roster') or not hasattr(_core, 'stele_consent_message'):
        return None
    return ethne


def ethne_polity(spec, releases=()):
    """Found the spec's polity in an Ethne archive: every member ratifies, the
    roll confers ReleaseOfficer and designates the guardian edges, the first
    officer authorizes each of `releases`. Returns (archive, polity did,
    signers by name)."""
    import ethne as e
    from ethne import _core
    from ethne.authoring import (Signer, authorize_release, confer_office,
                                 designate_derived, ratify_charter)
    root = root_key(spec)
    polity = _core.did_from_ed25519_pubkey(bytes(root.verify_key))
    signers = {}
    for name, node_root in spec['members'].items():
        _uid, sk = node_key(node_root)
        signers[name] = Signer(priv=bytes(sk), did=_core.did_from_ed25519_pubkey(
            bytes(sk.verify_key)))
    machines = set((spec.get('guardians') or {}).keys())
    humans = [s for n, s in signers.items() if n not in machines]
    proposal = e.propose_charter(polity, 'stele team', 'answers for what it ships',
                                 member_dids=[s.did for s in signers.values()],
                                 commitments=[], proposed_at=50)
    archive = e.Archive()
    ratify_charter(archive, proposal, list(signers.values()), founded_at=100)
    for m, g in (spec.get('guardians') or {}).items():
        designate_derived(archive, polity, signers[m].did, humans, guardian=signers[g],
                          unbacked_reason='a cohort build machine', decided_at=150)
    for o in spec.get('officers', []):
        confer_office(archive, polity, 'ReleaseOfficer', signers[o], humans,
                      decided_at=200)
    officer = signers[spec['officers'][0]] if spec.get('officers') else None
    for i, (repo, url, commit, built_by) in enumerate(releases):
        authorize_release(archive, polity, officer, repo, url, commit,
                          built_by=signers[built_by].did if built_by else None,
                          authorized_at=300 + i)
    archive.check_authority()
    return archive, polity, signers, root


def ethne_roster(spec):
    import ethne as e
    archive, polity, _signers, root = ethne_polity(spec)
    issuer = bytes(root.verify_key).hex()
    members = [(d, u, c) for _n, d, u, _k, c in _members(spec, issuer)]
    return e.stele_team_roster(archive, polity, members, bytes(root), bytes(root.verify_key),
                               int(spec.get('seq', 1)))


def ethne_release(spec, repo, url, commit, built_by=None):
    import ethne as e
    archive, polity, signers, _root = ethne_polity(spec, [(repo, url, commit, built_by)])
    officers, releases = archive.release_state(polity)
    cid = releases[-1][0]
    _uid, sk = node_key(spec['members'][spec['officers'][0]])
    return e.stele_release_authorization(archive, polity, cid, bytes(sk),
                                         bytes(sk.verify_key))


def ethne_profile(spec):
    """The roll amends the profile `profile_seq` times, then Ethne exports it."""
    import ethne as e
    from ethne.authoring import amend_stele_profile
    archive, polity, signers, root = ethne_polity(spec)
    machines = set((spec.get('guardians') or {}).keys())
    deciders = [s for n, s in signers.items() if n not in machines]
    for i in range(int(spec.get('profile_seq', 1))):
        amend_stele_profile(archive, polity, spec_profile(spec), deciders,
                            rationale='what safe enough means here', decided_at=400 + i)
    archive.check_authority()
    return e.stele_profile(archive, polity, bytes(root), bytes(root.verify_key))


def ethne_anchor(spec):
    import ethne as e
    archive, polity, _signers, root = ethne_polity(spec)
    issuer = bytes(root.verify_key).hex()
    group, members, cks = anchor_inputs(spec, issuer)
    return e.stele_group_anchor(archive, polity, group, members, cks, bytes(root),
                                bytes(root.verify_key), int(spec.get('anchor_seq', 1)))


def main(argv):
    builtin = '--builtin' in argv
    argv = [a for a in argv if a != '--builtin']
    if len(argv) < 3 or argv[1] not in ('roster', 'release', 'issuer', 'profile', 'anchor'):
        print(__doc__, file=sys.stderr)
        return 64
    with open(argv[2]) as f:
        spec = json.load(f)
    use_ethne = not builtin and _ethne() is not None
    if argv[1] in ('profile', 'anchor') and use_ethne:
        import ethne
        use_ethne = hasattr(ethne, 'stele_profile' if argv[1] == 'profile'
                            else 'stele_group_anchor')
    if argv[1] == 'issuer':
        print(bytes(root_key(spec).verify_key).hex())
        return 0
    if argv[1] == 'roster':
        text = ethne_roster(spec) if use_ethne else builtin_roster(spec)
        out = argv[3]
    elif argv[1] == 'profile':
        text = ethne_profile(spec) if use_ethne else builtin_profile(spec)
        out = argv[3]
    elif argv[1] == 'anchor':
        text = ethne_anchor(spec) if use_ethne else builtin_anchor(spec)
        out = argv[3]
    else:
        rest = argv[3:]
        built_by = None
        if '--built-by' in rest:
            i = rest.index('--built-by')
            built_by = rest[i + 1]
            rest = rest[:i] + rest[i + 2:]
        repo, url, commit, out = rest
        text = (ethne_release if use_ethne else builtin_release)(spec, repo, url, commit,
                                                                 built_by)
    with open(out, 'w') as f:
        f.write(text)
    print('stele_team: wrote %s (%s)' % (out, 'ethne' if use_ethne else 'built-in'),
          file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
