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
"""stele_anchors: the other AT groups this reader can check work from
(CODE_SHARING_PLAN §8 Phase 4, discovery relays; Ethne D43).

A reader holds the keys of its own AT group and no other, so a record from
another group verifies against nothing it has. A polity's GROUP ANCHOR (Ethne
border artifact #12) supplies them: the AT group its work is verified in, each
node's key (each node consenting) and tier, and the checkpoints the group
signed, all signed by the polity's root key. The reader FOLLOWS a polity by
pinning that key here; after that only a higher ``seq`` from the same key
replaces the anchor it holds. A reader may follow several polities.

Kept as ``etc/stele/anchors/<issuer>.json`` (``{"text": <the signed file>}``).
An anchor that arrives with a relay's answer is taken for that answer only, and
only when its issuer is followed and its ``seq`` is higher; nothing about an
unfollowed group is ever believed.
"""
import json
import os
import re

HEX64 = re.compile(r'^[0-9a-f]{64}$')


class AnchorError(ValueError):
    """An anchor that cannot be followed: unparseable, unverified, or older."""


def _anchor_module():
    from autonomous_trust.stele import anchor
    return anchor


def _dir(root):
    return os.path.join(root, 'etc', 'stele', 'anchors')


def parse(text):
    """The verified anchor in ``text``, or raise :class:`AnchorError`."""
    got = _anchor_module().parse_anchor(text)
    if got is None:
        raise AnchorError('not a group anchor whose root signature and every '
                          "node's consent verify")
    return got


def followed(root) -> dict:
    """``{issuer: (anchor, text)}`` for every polity this reader follows. A
    stored file that no longer verifies is left out."""
    out = {}
    try:
        names = sorted(os.listdir(_dir(root)))
    except OSError:
        return out
    for name in names:
        issuer = name[:-5]
        if not name.endswith('.json') or not HEX64.match(issuer):
            continue
        try:
            with open(os.path.join(_dir(root), name)) as f:
                text = json.load(f)['text']
            a = parse(text)
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if a['issuer'] == issuer:
            out[issuer] = (a, text)
    return out


def follow(root, text):
    """Follow the polity that signed ``text``, or take its newer anchor. Refuses
    one no newer than the anchor already held from that issuer."""
    a = parse(text)
    have = followed(root).get(a['issuer'])
    if have is not None and a['seq'] <= have[0]['seq']:
        raise AnchorError('already holding seq %d from this issuer; seq %d is not newer'
                          % (have[0]['seq'], a['seq']))
    os.makedirs(_dir(root), exist_ok=True)
    path = os.path.join(_dir(root), a['issuer'] + '.json')
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump({'text': text}, f)
    os.replace(tmp, path)
    return a


def unfollow(root, issuer):
    """Stop following ``issuer``; True when it was followed."""
    if not HEX64.match(str(issuer)):
        return False
    try:
        os.unlink(os.path.join(_dir(root), issuer + '.json'))
        return True
    except OSError:
        return False


def offer(held: dict, text):
    """``held`` (as :func:`followed` returns it) with ``text`` taken in, for one
    answer, when it is a newer anchor from an issuer already followed. Returns
    True when taken."""
    try:
        a = parse(text)
    except AnchorError:
        return False
    have = held.get(a['issuer'])
    if have is None or a['seq'] <= have[0]['seq']:
        return False
    held[a['issuer']] = (a, text)
    return True
