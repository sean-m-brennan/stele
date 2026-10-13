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
"""The verifier's scanner battery (Stele Phase 1, CODE_SHARING_PLAN §4.1).

Each scanner runs against the verifier's OWN clone of the pushed commit and
reduces its report to what an attestation carries: a verdict (``vuln`` or
``clean``), a count, the worst severity it saw, and a digest of the report, so
the report itself can be published and checked against the attestation later.
Each also names its tool version and the rules or database it ran against
(``db_digest``), because a finding is only as good as what it was checked
with.

Four scanners attest on AT's ``probe`` channel, because the verifier chose
the question and knows how to read the answer:

* ``osv-scanner``: known vulnerabilities in dependencies, offline, against a
  database snapshot the verifier fetched;
* ``gitleaks``: committed secrets;
* ``semgrep``: code-level findings, against rules the verifier ships;
* ``license``: a dependency under a license the verifier's policy denies,
  read from the verifier's own SBOM of the commit.

Two more check the OWNER'S claims, which a v2 repo ad carries:

* ``sbom`` (``certificate``): the SBOM the owner committed must match the
  digest it advertised, and must list every component the verifier's own SBOM
  finds;
* ``claim`` (``self_consistency``): an owner that claimed its release clean,
  contradicted by any of the probe scanners above;
* ``provides`` (``certificate``, Phase 4): the package a v4 ad says the repo
  publishes as must be one its own manifest names (go.mod, package.json,
  Cargo.toml, pyproject.toml), so an ad cannot claim another repo's package
  and stand in for it in a dependent's supply chain.

The verifier's own SBOM comes from syft (``dir:<src>``, CycloneDX JSON).
"""
import glob
import hashlib
import json
import os
import re
import subprocess
import tempfile
from urllib.parse import quote

try:
    import tomllib   # Python 3.11+; without it Cargo/pyproject names go unread
except ImportError:  # pragma: no cover
    tomllib = None

PROBE, CERTIFICATE, SELF_CONSISTENCY = 'probe', 'certificate', 'self_consistency'

#: Licenses the default policy refuses (SPDX ids). A deployment sets its own
#: with ``license_deny`` in the hook config: the data is neutral, the policy is
#: the verifier's (CODE_SHARING_PLAN §9, question 4).
DEFAULT_LICENSE_DENY = ('AGPL-3.0-only', 'AGPL-3.0-or-later', 'GPL-3.0-only',
                        'GPL-3.0-or-later', 'SSPL-1.0')


def report_digest(report) -> str:
    """sha256 over a report's normalized JSON: the findings digest."""
    normalized = json.dumps(report, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(normalized).hexdigest()


def _files_digest(paths, base) -> str:
    h = hashlib.sha256()
    for path in sorted(paths):
        h.update(os.path.relpath(path, base).encode())
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
    return h.hexdigest()


def _text_digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _tool_version(argv, prefix=None) -> str:
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return 'unknown'
    for line in (out.stdout + out.stderr).splitlines():
        line = line.strip()
        if prefix is None and line:
            return line.split()[-1][:32]
        if prefix is not None and line.startswith(prefix):
            return line.split(':', 1)[1].strip()[:32]
    return 'unknown'


# ---------------- summaries (pure; what the tests pin) ----------------

def summarize_osv(report):
    """``(verdict, count, max_severity, findings_digest)`` from an osv-scanner
    JSON report.

    The count is distinct vulnerabilities after osv-scanner's alias merge (its
    per-package ``groups``; a GO- id and the GHSA/CVE it aliases are one
    finding), and max_severity the highest CVSS score among them (``groups[].
    max_severity``, e.g. "7.5"), or '' when none is scored. A report written
    without groups falls back to distinct vulnerability ids and the
    database-specific severity labels."""
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
    return ('vuln' if count else 'clean'), count, max_sev, report_digest(report)


def summarize_gitleaks(report):
    """gitleaks writes a JSON list of findings; each one is a secret in the
    tree. They carry no severity, so a leak is reported as ``SECRET``."""
    findings = report if isinstance(report, list) else []
    count = len(findings)
    return (('vuln' if count else 'clean'), count, 'SECRET' if count else '',
            report_digest(report))


def summarize_semgrep(report):
    """semgrep's ``results``; the worst ``extra.severity`` (ERROR, WARNING,
    INFO). Every result counts: which rules run is the verifier's choice, made
    when it ships them."""
    results = (report or {}).get('results') or []
    order = ['ERROR', 'WARNING', 'INFO']
    seen = {str((r.get('extra') or {}).get('severity') or '').upper() for r in results}
    max_sev = next((s for s in order if s in seen), '')
    count = len(results)
    return ('vuln' if count else 'clean'), count, max_sev, report_digest(report)


def summarize_license(report):
    """The license check's own report: ``{denied: [{component, license}]}``."""
    denied = (report or {}).get('denied') or []
    count = len(denied)
    max_sev = denied[0]['license'][:16] if count else ''
    return ('vuln' if count else 'clean'), count, max_sev, report_digest(report)


def summarize_sbom(report):
    """The SBOM check's own report: a digest that does not match what the ad
    claimed, or components the verifier found and the owner's SBOM omits, are
    each a finding."""
    count = (0 if report.get('digest_ok') else 1) + len(report.get('missing') or [])
    max_sev = 'MISMATCH' if not report.get('digest_ok') else (
        'INCOMPLETE' if count else '')
    return ('vuln' if count else 'clean'), count, max_sev, report_digest(report)


def summarize_provides(report):
    """The provides check's own report: ``{claimed, found, manifests}``. A
    claim no manifest of the commit names is one finding."""
    ok = report.get('claimed') in (report.get('found') or [])
    return ('clean' if ok else 'vuln'), 0 if ok else 1, '' if ok else 'UNCLAIMED', \
        report_digest(report)


def summarize_claim(report):
    """The claim check's own report: ``{claim, contradicted_by: [...]}``."""
    by = report.get('contradicted_by') or []
    count = sum(int(c.get('count', 0)) for c in by)
    return ('vuln' if count else 'clean'), count, 'CONTRADICTED' if count else '', \
        report_digest(report)


SUMMARIES = {'osv-scanner': summarize_osv, 'gitleaks': summarize_gitleaks,
             'semgrep': summarize_semgrep, 'license': summarize_license,
             'sbom': summarize_sbom, 'claim': summarize_claim,
             'provides': summarize_provides}
CHANNELS = {'osv-scanner': PROBE, 'gitleaks': PROBE, 'semgrep': PROBE,
            'license': PROBE, 'sbom': CERTIFICATE, 'claim': SELF_CONSISTENCY,
            'provides': CERTIFICATE}


# ---------------- SBOM components ----------------

def sbom_components(sbom) -> set:
    """The components a CycloneDX SBOM lists, as purls (or name@version when a
    component has none). The root component describing the repo itself is
    not a dependency and is left out."""
    out = set()
    for c in (sbom or {}).get('components') or []:
        if c.get('type') in ('file', 'operating-system'):
            continue
        key = c.get('purl') or ('%s@%s' % (c.get('name', ''), c.get('version', '')))
        if key.strip('@'):
            out.add(key)
    return out


def sbom_licenses(sbom) -> list:
    """``[(component, spdx id)]`` for every license a CycloneDX SBOM states."""
    out = []
    for c in (sbom or {}).get('components') or []:
        key = c.get('purl') or c.get('name', '')
        for lic in c.get('licenses') or []:
            ident = ((lic.get('license') or {}).get('id')
                     or lic.get('expression') or '')
            if ident:
                out.append((key, ident))
    return out


def check_sbom(src, sbom_path, claimed_digest, own_sbom) -> dict:
    """The owner's committed SBOM against its claimed digest and the
    verifier's own SBOM of the same tree."""
    path = os.path.join(src, sbom_path)
    report = {'sbom_path': sbom_path, 'claimed_digest': claimed_digest,
              'actual_digest': '', 'digest_ok': False, 'missing': []}
    if not os.path.isfile(path) or os.path.realpath(path) != os.path.join(
            os.path.realpath(src), os.path.normpath(sbom_path)):
        return report
    with open(path, 'rb') as f:
        raw = f.read()
    report['actual_digest'] = hashlib.sha256(raw).hexdigest()
    report['digest_ok'] = report['actual_digest'] == claimed_digest
    try:
        theirs = sbom_components(json.loads(raw))
    except ValueError:
        theirs = set()
    report['missing'] = sorted(sbom_components(own_sbom) - theirs)
    return report


def _toml(path):
    if tomllib is None:
        return {}
    try:
        with open(path, 'rb') as f:
            return tomllib.load(f)
    except (OSError, ValueError):   # TOMLDecodeError is a ValueError
        return {}


def manifest_packages(src) -> list:
    """``[(purl base, manifest)]`` for the packages the manifests at the top of
    the checkout publish: a Go module, an npm package, a Cargo crate, a Python
    project. Names are spelled the way syft spells them in a dependent's SBOM."""
    out = []
    gomod = os.path.join(src, 'go.mod')
    if os.path.isfile(gomod):
        with open(gomod, encoding='utf-8', errors='replace') as f:
            m = re.search(r'^\s*module\s+"?([^\s"]+)"?', f.read(), re.M)
        if m:
            out.append(('pkg:golang/' + m.group(1), 'go.mod'))
    pkg = os.path.join(src, 'package.json')
    if os.path.isfile(pkg):
        try:
            with open(pkg, encoding='utf-8') as f:
                name = json.load(f).get('name')
        except (OSError, ValueError, AttributeError):
            name = None
        if isinstance(name, str) and name:
            out.append(('pkg:npm/' + quote(name, safe='/'), 'package.json'))
    crate = (_toml(os.path.join(src, 'Cargo.toml')).get('package') or {}).get('name')
    if isinstance(crate, str) and crate:
        out.append(('pkg:cargo/' + crate, 'Cargo.toml'))
    project = (_toml(os.path.join(src, 'pyproject.toml')).get('project') or {}).get('name')
    if isinstance(project, str) and project:
        out.append(('pkg:pypi/' + re.sub(r'[-_.]+', '-', project).lower(),
                    'pyproject.toml'))
    return out


def check_provides(src, claimed) -> dict:
    """The package a v4 ad claims against the ones the commit's manifests
    publish."""
    found = manifest_packages(src)
    return {'claimed': claimed, 'found': sorted(p for p, _ in found),
            'manifests': sorted({m for _, m in found})}


def check_licenses(own_sbom, deny) -> dict:
    deny = set(deny)
    return {'policy': sorted(deny),
            'denied': [{'component': c, 'license': l}
                       for c, l in sbom_licenses(own_sbom) if l in deny]}


def check_claim(claim, probes) -> dict:
    """``probes`` is ``[(scanner, verdict, count, findings_digest)]``."""
    return {'claim': claim,
            'contradicted_by': [{'scanner': s, 'count': n, 'findings_digest': d}
                                for s, v, n, d in probes
                                if claim == 'clean' and v == 'vuln']}


# ---------------- running the tools ----------------

def relative_paths(report, src):
    """``report`` with the checkout's absolute path taken out of every string:
    ``src`` itself becomes ``.`` and ``src/x`` becomes ``x``. Scanners write the
    path they were given into their reports, and each verifier clones into a
    temporary directory of its own, so without this two verifiers who found
    exactly the same thing would report different findings digests and never
    agree (Stele Phase 2, red-team run rt-1487736)."""
    root = os.path.normpath(src)
    prefix = root + os.sep

    def walk(v):
        if isinstance(v, str):
            if v == root:
                return '.'
            return v.replace(prefix, '')
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, dict):
            return {walk(k): walk(x) for k, x in v.items()}
        return v
    return walk(report)


def run_osv(src, cfg):
    env = dict(os.environ, OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=cfg['osv_db'])
    out = subprocess.run([cfg['osv_scanner'], 'scan', 'source', '-r', '--format',
                          'json', '--offline-vulnerabilities', src],
                         capture_output=True, text=True, env=env)
    if out.returncode not in (0, 1):
        raise RuntimeError('osv-scanner failed (%d): %s'
                           % (out.returncode, out.stderr[-400:]))
    return relative_paths(json.loads(out.stdout or '{}'), src)


def run_gitleaks(src, cfg):
    with tempfile.TemporaryDirectory(prefix='stele-gitleaks-') as work:
        path = os.path.join(work, 'report.json')
        out = subprocess.run([cfg['gitleaks'], 'detect', '--no-git', '--source', src,
                              '--report-format', 'json', '--report-path', path,
                              '--exit-code', '0', '--no-banner'],
                             capture_output=True, text=True)
        if out.returncode != 0:
            raise RuntimeError('gitleaks failed (%d): %s'
                               % (out.returncode, out.stderr[-400:]))
        with open(path) as f:
            return relative_paths(json.load(f), src)


def run_semgrep(src, cfg):
    out = subprocess.run([cfg['semgrep'], 'scan', '--config', cfg['semgrep_rules'],
                          '--json', '--metrics=off', '--disable-version-check',
                          '--quiet', src], capture_output=True, text=True)
    if out.returncode not in (0, 1):
        raise RuntimeError('semgrep failed (%d): %s'
                           % (out.returncode, out.stderr[-400:]))
    return relative_paths(json.loads(out.stdout or '{}'), src)


def own_sbom(src, cfg):
    """The verifier's own SBOM of the tree, from syft."""
    out = subprocess.run([cfg['syft'], 'dir:' + src, '-o', 'cyclonedx-json', '-q'],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError('syft failed (%d): %s' % (out.returncode, out.stderr[-400:]))
    return json.loads(out.stdout or '{}')


def version_of(name, cfg) -> str:
    if name == 'osv-scanner':
        return _tool_version([cfg['osv_scanner'], '--version'], 'osv-scanner version:')
    if name == 'gitleaks':
        return _tool_version([cfg['gitleaks'], 'version'])
    if name == 'semgrep':
        return _tool_version([cfg['semgrep'], '--version'])
    if name in ('license', 'sbom'):
        return _tool_version([cfg['syft'], 'version'], 'Version:')
    return 'stele-1'   # Stele's own checks: claim, provides


def db_digest_of(name, cfg) -> str:
    """What the finding was checked against: the OSV snapshot, the semgrep
    rules, the license policy; for the rest, the tool version."""
    if name == 'osv-scanner':
        db = cfg['osv_db']
        return _files_digest(glob.glob(os.path.join(db, '**', '*.zip'),
                                       recursive=True), db)
    if name == 'semgrep':
        rules = cfg['semgrep_rules']
        if os.path.isdir(rules):
            return _files_digest([p for p in glob.glob(os.path.join(rules, '**', '*'),
                                                       recursive=True)
                                  if os.path.isfile(p)], rules)
        return _text_digest(rules)
    if name == 'license':
        return _text_digest('|'.join(sorted(cfg.get('license_deny')
                                            or DEFAULT_LICENSE_DENY)))
    return _text_digest(name + '|' + version_of(name, cfg))
