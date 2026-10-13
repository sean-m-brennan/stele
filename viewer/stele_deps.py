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
"""stele_deps: what a repository is built from (CODE_SHARING_PLAN §8 Phase 4,
the supply-chain view).

A repository's dependencies are the components of the SBOM its owner committed.
The signed ad pins that SBOM by sha256, and verifiers already check it on the
``certificate`` channel against their own SBOM of the commit, so a dependency
the owner leaves out fails the repository itself. The SBOM is content-addressed,
so it may come from anywhere: the verifier that checked it, the forge, a bundle,
a file. This node keeps the ones it has under ``etc/stele/sboms/<sha256>.json``
and takes nothing whose bytes do not hash to that name.

A dependency is named by a purl. A v4 ad says which package its repository
publishes as (``provides``, a purl without a version), and a verifier checks
that against the repository's manifest. The reader may also pin a package to
repositories of its own choosing in ``etc/stele/deps-map.json``
(``{purl_base: [url, ...]}``); a pin replaces every claimant for that package.
"""
import hashlib
import json
import os
import re

SBOM_MAX = 16 * 1024 * 1024
_SHA256 = re.compile(r'^[0-9a-f]{64}$')


# ---------------- purls ----------------

def purl_base(purl: str) -> str:
    """A purl without its version, qualifiers or subpath: what a v4 ad's
    ``provides`` names. ``pkg:golang/golang.org/x/net@v0.1.0`` gives
    ``pkg:golang/golang.org/x/net``; a scoped npm name keeps its ``%40``."""
    base = purl.split('#', 1)[0].split('?', 1)[0]
    head, _, tail = base.rpartition('/')
    return (head + '/' + tail.split('@', 1)[0]) if head else base


def purl_version(purl: str) -> str:
    """The version a purl pins, or '' (also for a component with no purl)."""
    if not purl.startswith('pkg:'):
        return ''
    tail = purl.split('#', 1)[0].split('?', 1)[0].rpartition('/')[2]
    return tail.split('@', 1)[1] if '@' in tail else ''


_PSEUDO = re.compile(r'^v\d+\.\d+\.\d+-(?:.*[.-])?\d{14}-([0-9a-f]{12})(?:\+incompatible)?$')


def version_matches(ref: str, version: str, commit: str = '') -> bool:
    """Whether an ad is the release a dependent pins: the ad's ref's last path
    segment, with or without a leading ``v`` (``refs/tags/v1.2.0`` is ``1.2.0``
    and ``v1.2.0``), or, for a Go pseudo-version
    (``v0.0.0-20241001120000-0123456789ab``), the commit it abbreviates."""
    if not version:
        return False
    m = _PSEUDO.match(version)
    if m and commit and commit.startswith(m.group(1)):
        return True
    if not ref:
        return False
    tag = ref.rstrip('/').rpartition('/')[2]
    return tag == version or tag.lstrip('v') == version.lstrip('v')


def components(sbom) -> list:
    """The components a CycloneDX SBOM lists, as purls (or ``name@version``
    when a component has none), sorted. The root component describing the repo
    itself is not a dependency. The same rule as the verifier's
    ``scanners.sbom_components``, which checks the SBOM is complete."""
    out = set()
    for c in (sbom or {}).get('components') or []:
        if not isinstance(c, dict) or c.get('type') in ('file', 'operating-system'):
            continue
        key = c.get('purl') or ('%s@%s' % (c.get('name', ''), c.get('version', '')))
        if isinstance(key, str) and key.strip('@'):
            out.add(key)
    return sorted(out)


# ---------------- the SBOM store ----------------

def _sbom_dir(root):
    return os.path.join(root, 'etc', 'stele', 'sboms')


def keep_sbom(root, raw: bytes):
    """Keep an SBOM's exact bytes under their sha256; returns the digest, or
    None when they are not a JSON object or are too large to be one."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > SBOM_MAX:
        return None
    try:
        if not isinstance(json.loads(raw), dict):
            return None
    except ValueError:
        return None
    digest = hashlib.sha256(raw).hexdigest()
    d = _sbom_dir(root)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, digest + '.json')
    if not os.path.exists(path):
        tmp = '%s.%d.tmp' % (path, os.getpid())
        with open(tmp, 'wb') as f:
            f.write(raw)
        os.replace(tmp, path)
    return digest


def held_sbom(root, digest):
    """The SBOM held under `digest`, parsed, or None. Bytes that no longer hash
    to their name are not an SBOM this node holds."""
    if not isinstance(digest, str) or not _SHA256.match(digest):
        return None
    try:
        with open(os.path.join(_sbom_dir(root), digest + '.json'), 'rb') as f:
            raw = f.read(SBOM_MAX + 1)
    except OSError:
        return None
    if hashlib.sha256(raw).hexdigest() != digest:
        return None
    try:
        sbom = json.loads(raw)
    except ValueError:
        return None
    return sbom if isinstance(sbom, dict) else None


def held_digests(root) -> set:
    try:
        names = os.listdir(_sbom_dir(root))
    except OSError:
        return set()
    return {n[:-5] for n in names if n.endswith('.json') and _SHA256.match(n[:-5])}


# ---------------- the reader's own map ----------------

def _map_path(root):
    return os.path.join(root, 'etc', 'stele', 'deps-map.json')


def load_map(root) -> dict:
    """``{purl_base: [url, ...]}``: the packages this reader pins. A malformed
    file pins nothing."""
    try:
        with open(_map_path(root)) as f:
            raw = json.load(f)
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    out = {}
    for base, urls in raw.items():
        if isinstance(urls, str):
            urls = [urls]
        if isinstance(base, str) and isinstance(urls, list):
            out[base] = sorted({u for u in urls if isinstance(u, str) and u})
    return {k: v for k, v in out.items() if v}


def _save_map(root, m):
    path = _map_path(root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(m, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def pin(root, purl, url) -> dict:
    """Pin the package `purl` names (its version is dropped) to `url`, beside
    any earlier pin of it."""
    base = purl_base(purl)
    if not base.startswith('pkg:') or not url:
        raise ValueError('pin a purl (pkg:...) to a repository URL')
    m = load_map(root)
    m[base] = sorted(set(m.get(base, [])) | {url})
    _save_map(root, m)
    return m


def unpin(root, purl, url=None) -> dict:
    """Drop the pin of the package `purl` names, or only its `url`."""
    base = purl_base(purl)
    m = load_map(root)
    if base in m:
        m[base] = [u for u in m[base] if url is not None and u != url]
        if not m[base]:
            del m[base]
        _save_map(root, m)
    return m
