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
"""stele_profile: what "safe enough" means to whoever reads a standing
(CODE_SHARING_PLAN §9 Q4, Phase 4; Ethne D42).

The chain records neutral facts with reasons. A PROFILE is one reading of them:
how many counted verifiers must agree, at what tier a verifier counts, which
checks must be present and which are set aside, how severe a finding must be to
fail a repository, how fast a clean reading fades, whether a team's standing
caps its repositories', and whether a repository's worst resolved dependency
caps it (``deps``, the supply-chain view). A profile never changes a fact, and never hides one: a
set-aside check is still shown, named with the profile that set it aside.

**Floors.** A profile tightens Stele's reading freely and relaxes it only inside
floors no profile may cross. :func:`parse` refuses a profile outside them; it
does not clamp it. The floors match Ethne's ``SteleProfile::check_shape``:

* at least one counted verifier (``replicas`` 1..16), and a counting AT tier
  (``tier`` 1..4). Only records that verify against the reader's own roster
  count, under every profile;
* ``severity_floor`` is at most ``high``, and ``ignore`` never sets aside a
  critical finding: a confirmed critical finding fails a repository under every
  profile, and a finding with no rating always counts;
* a clean reading fades at a visible rate (``onset_days`` 0..30,
  ``half_life_days`` 1..365). A failure never fades, under every profile;
* well-formed ``scanner:channel`` checks, none both required and set aside.

The viewer keeps two more that are not fields: a counted confirmed finding is
never green, and a standing with nothing counted is unknown, never safe.

**Where a profile comes from.** Built in (``stele-default``, Stele's own
reading, and ``stele-strict``); a local file the consumer wrote
(``etc/stele/profiles/<name>.json``); or a polity's signed profile (Ethne
border artifact #11) that the consumer FOLLOWS by pinning its issuer
(``etc/stele/follow.json``). Which applies: an explicit choice, else
``etc/stele/profile.json``'s ``use``, else ``stele-default``.

A signed profile is ``{"body": <exact JSON>, "sig": <hex>}``, the signature by
the polity root key over ``"stele-profile-v1|" + body``. Once an issuer is
followed, only a higher ``seq`` from the same key replaces the profile held.
"""
import json
import os
import re

SCHEMA = 'stele-profile-1'
PROFILE_DOMAIN = b'stele-profile-v1|'
PROFILE_TYPENAME = 'stele-profile'
PROFILE_MAX = 16 << 10
CHANNELS = ('probe', 'certificate', 'self_consistency', 'physical')
SEVERITY_FLOORS = ('low', 'medium', 'high')
TEAM_COUPLINGS = ('show', 'worst')
DEPS_COUPLINGS = ('show', 'worst')
CHECKS_MAX = 16
NAME_RE = re.compile(r'^[a-z0-9._-]{1,64}$')
SCANNER_RE = re.compile(r'^[a-z0-9._-]{1,32}$')
HEX64_RE = re.compile(r'^[0-9a-f]{64}$')

#: Stele's own reading (user decisions 2026-10-05 and -07): two counted
#: verifiers at tier 3 must agree, every check and every finding counts, a
#: clean reading holds a day and then halves every 30, and the team is shown
#: beside a repository without changing it.
STELE_DEFAULT = {
    'name': 'stele-default', 'replicas': 2, 'tier': 3, 'require': [],
    'ignore': [], 'severity_floor': 'low', 'onset_days': 1,
    'half_life_days': 30, 'team': 'show', 'deps': 'show'}

#: A worked example of a tighter reading: three agreeing verifiers, the three
#: core scanners required, a two-week half-life, and a repository no better
#: than its team or its worst resolved dependency.
STELE_STRICT = dict(
    STELE_DEFAULT, name='stele-strict', replicas=3,
    require=['gitleaks:probe', 'license:probe', 'osv-scanner:probe'],
    half_life_days=14, team='worst', deps='worst')

BUILTINS = {p['name']: p for p in (STELE_DEFAULT, STELE_STRICT)}

FIELDS = tuple(STELE_DEFAULT)
#: Fields a signed body may leave out, read as ``show``: Ethne writes ``deps``
#: only when it is ``worst``, so a D42 profile signed before it keeps its bytes.
OPTIONAL_FIELDS = ('deps',)


class ProfileError(ValueError):
    """A profile that cannot be applied: malformed, outside the floors, not
    verified, or not the one followed."""


def _check(check):
    if not isinstance(check, str) or check.count(':') != 1:
        raise ProfileError('check %r is not scanner:channel' % (check,))
    scanner, channel = check.split(':')
    if not SCANNER_RE.match(scanner):
        raise ProfileError('check %r: scanner must be 1..32 of [a-z0-9._-]' % check)
    if channel not in CHANNELS:
        raise ProfileError('check %r: channel must be one of %s'
                           % (check, ', '.join(CHANNELS)))


def _int(d, key, lo, hi):
    v = d[key]
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise ProfileError('%s %r must be an integer %d..%d' % (key, v, lo, hi))
    return v


def parse(obj, complete=False):
    """A profile from ``obj``, checked against the floors and normalized
    (sorted check lists). A local profile names only what it changes: the rest
    is ``stele-default``'s. ``complete`` (a signed body) requires every field.
    Unknown fields are refused, never ignored: a reader cannot honor a rule it
    does not know."""
    if not isinstance(obj, dict):
        raise ProfileError('a profile is a JSON object')
    obj = {k: v for k, v in obj.items() if k != 'schema'}
    unknown = sorted(set(obj) - set(FIELDS))
    if unknown:
        raise ProfileError('unknown profile field(s): %s' % ', '.join(unknown))
    if complete:
        missing = [k for k in FIELDS if k not in obj and k not in OPTIONAL_FIELDS]
        if missing:
            raise ProfileError('missing profile field(s): %s' % ', '.join(missing))
    p = dict(STELE_DEFAULT, **obj)
    if not isinstance(p['name'], str) or not NAME_RE.match(p['name']):
        raise ProfileError('profile name %r must be 1..64 of [a-z0-9._-]' % (p['name'],))
    _int(p, 'replicas', 1, 16)
    _int(p, 'tier', 1, 4)
    _int(p, 'onset_days', 0, 30)
    _int(p, 'half_life_days', 1, 365)
    if p['severity_floor'] not in SEVERITY_FLOORS:
        raise ProfileError('severity_floor %r must be one of %s (a critical finding '
                           'always counts)' % (p['severity_floor'], ', '.join(SEVERITY_FLOORS)))
    if p['team'] not in TEAM_COUPLINGS:
        raise ProfileError('team %r must be one of %s' % (p['team'], ', '.join(TEAM_COUPLINGS)))
    if p['deps'] not in DEPS_COUPLINGS:
        raise ProfileError('deps %r must be one of %s' % (p['deps'], ', '.join(DEPS_COUPLINGS)))
    for key in ('require', 'ignore'):
        if not isinstance(p[key], (list, tuple)):
            raise ProfileError('%s must be a list of scanner:channel' % key)
        if len(p[key]) > CHECKS_MAX:
            raise ProfileError('%s names %d checks, more than %d'
                               % (key, len(p[key]), CHECKS_MAX))
        for c in p[key]:
            _check(c)
        p[key] = sorted(set(p[key]))
    both = set(p['require']) & set(p['ignore'])
    if both:
        raise ProfileError('check %r is both required and set aside' % sorted(both)[0])
    return p


#: A finding's worst severity, as the verifier writes it (verifier/scanners.py),
#: on one scale: 0 low, 1 medium, 2 high, 3 critical. A CVSS score maps by the
#: CVSS v3 bands; OSV, GHSA and semgrep labels by name. Anything else (a leaked
#: secret, an SBOM mismatch, a contradicted claim, a license) is unrated, and an
#: unrated finding counts under every profile.
_LABELS = {'LOW': 0, 'INFO': 0, 'MODERATE': 1, 'MEDIUM': 1, 'WARNING': 1,
           'HIGH': 2, 'ERROR': 2, 'CRITICAL': 3}


CRITICAL = 3


def severity_rank(max_severity):
    """``max_severity`` on the 0..3 scale, or None when it is unrated."""
    s = str(max_severity or '').strip().upper()
    if not s:
        return None
    try:
        score = float(s)
    except ValueError:
        return _LABELS.get(s)
    if score != score or score < 0:
        return None
    return 0 if score < 4.0 else 1 if score < 7.0 else 2 if score < 9.0 else 3


def counts_finding(profile, max_severity):
    """Whether a finding of ``max_severity`` fails a repository under
    ``profile``: an unrated finding always does, a rated one at or above the
    floor does."""
    rank = severity_rank(max_severity)
    return rank is None or rank >= SEVERITY_FLOORS.index(profile['severity_floor'])


def verify_signed(text):
    """A polity's signed profile file, verified: ``{issuer, polity, seq,
    set_by, profile}``. Raises :class:`ProfileError` for anything that does not
    verify under the key the body names, or is not a profile inside the
    floors."""
    import nacl.exceptions
    import nacl.signing
    if not isinstance(text, str) or len(text) > PROFILE_MAX:
        raise ProfileError('not a profile file, or larger than %d bytes' % PROFILE_MAX)
    try:
        outer = json.loads(text)
        body_text, sig = outer['body'], outer['sig']
        body = json.loads(body_text)
    except (ValueError, KeyError, TypeError):
        raise ProfileError('not a signed {body, sig} profile file')
    if not isinstance(body, dict) or body.get('v') != 1 \
            or body.get('typename') != PROFILE_TYPENAME:
        raise ProfileError('not a stele-profile v1 body')
    issuer = body.get('issuer')
    if not isinstance(issuer, str) or not HEX64_RE.match(issuer) \
            or not isinstance(sig, str) or not re.match(r'^[0-9a-f]{128}$', sig):
        raise ProfileError('the issuer key or the signature is malformed')
    try:
        nacl.signing.VerifyKey(bytes.fromhex(issuer)).verify(
            PROFILE_DOMAIN + body_text.encode(), bytes.fromhex(sig))
    except nacl.exceptions.BadSignatureError:
        raise ProfileError('the signature does not verify under the issuer key')
    seq = body.get('seq')
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise ProfileError('seq %r is not a positive integer' % (seq,))
    return {'issuer': issuer, 'polity': body.get('polity'), 'seq': seq,
            'set_by': body.get('set_by'), 'profile': parse(body.get('profile'), complete=True)}


# ---------------- the consumer's own files ----------------

def _stele_dir(root):
    return os.path.join(root, 'etc', 'stele')


def _read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise ProfileError('%s is unreadable: %s' % (path, e))


def _write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(obj, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def followed(root):
    """The verified profile this consumer follows, or None."""
    pin = _read_json(os.path.join(_stele_dir(root), 'follow.json'))
    if pin is None:
        return None
    got = verify_signed(pin.get('text') if isinstance(pin, dict) else None)
    if got['issuer'] != pin.get('issuer'):
        raise ProfileError('follow.json holds a profile from another issuer')
    return got


def follow(root, text, replace=False):
    """Follow the polity that signed ``text``, or take its newer profile.
    Following a DIFFERENT issuer than the one held needs ``replace``: switching
    whose reading you follow is a choice, never a side effect. From the same
    issuer only a higher ``seq`` is taken (an equal one is the same profile).
    Returns the verified profile held afterwards."""
    got = verify_signed(text)
    have = followed(root)
    if have is not None and have['issuer'] != got['issuer'] and not replace:
        raise ProfileError('already following %s; unfollow it first (or replace)'
                           % have['issuer'])
    if have is not None and have['issuer'] == got['issuer'] and got['seq'] <= have['seq']:
        if got['seq'] == have['seq']:
            return have
        raise ProfileError('seq %d is older than the seq %d held'
                           % (got['seq'], have['seq']))
    _write_json(os.path.join(_stele_dir(root), 'follow.json'),
                {'issuer': got['issuer'], 'text': text})
    return got


def unfollow(root):
    """Stop following any polity. Returns whether one was followed."""
    try:
        os.remove(os.path.join(_stele_dir(root), 'follow.json'))
        return True
    except FileNotFoundError:
        return False


def use(root, choice):
    """Set the profile a viewer applies when none is chosen explicitly: a
    built-in name, a local profile's name, or ``followed``. Checked first, so a
    choice that cannot load is never written."""
    load(root, choice)
    _write_json(os.path.join(_stele_dir(root), 'profile.json'), {'use': choice})


def local(root, name):
    """The consumer's own profile ``etc/stele/profiles/<name>.json``."""
    if not NAME_RE.match(name or ''):
        raise ProfileError('profile name %r must be 1..64 of [a-z0-9._-]' % (name,))
    if name in BUILTINS:
        raise ProfileError('%s is built in; a local profile may not take its name' % name)
    obj = _read_json(os.path.join(_stele_dir(root), 'profiles', name + '.json'))
    if obj is None:
        raise ProfileError('no profile named %s' % name)
    p = parse(obj)
    if p['name'] != name:
        raise ProfileError('profiles/%s.json names itself %s' % (name, p['name']))
    return p


def load(root, choice=None):
    """The profile that applies, and where it came from:
    ``(profile, {name, source, issuer?, seq?})``. ``choice`` (a built-in name,
    a local name, or ``followed``) wins; else ``etc/stele/profile.json``'s
    ``use``; else ``stele-default``. A choice that cannot load raises: a viewer
    that silently fell back would show one reading under another's name."""
    if not choice:
        pref = _read_json(os.path.join(_stele_dir(root), 'profile.json'))
        choice = (pref or {}).get('use') if isinstance(pref, dict) else None
    choice = choice or STELE_DEFAULT['name']
    if choice == 'followed':
        got = followed(root)
        if got is None:
            raise ProfileError('no polity is followed')
        return got['profile'], {'name': got['profile']['name'], 'source': 'followed',
                                'issuer': got['issuer'], 'polity': got['polity'],
                                'seq': got['seq']}
    if choice in BUILTINS:
        return parse(BUILTINS[choice]), {'name': choice, 'source': 'builtin'}
    return local(root, choice), {'name': choice, 'source': 'local'}


def offer(meta, text):
    """A signed profile someone handed over (a bundle's), taken for this one
    answer only when the profile applied is FOLLOWED, it is from the followed
    issuer, and it is newer. Returns ``(profile, meta)`` or None. Nothing is
    written: following is the consumer's act, not a bundle's."""
    if not meta or meta.get('source') != 'followed':
        return None
    try:
        got = verify_signed(text)
    except ProfileError:
        return None
    if got['issuer'] != meta.get('issuer') or got['seq'] <= meta.get('seq', 0):
        return None
    return got['profile'], dict(meta, name=got['profile']['name'], seq=got['seq'],
                                polity=got['polity'], via='bundle')
