/* Stele trust panel: what to show for a standing, as data. No DOM here, so
 * the rules can be tested on their own (tests/panel.test.mjs).
 *
 * The standing comes from the viewer's OWN node (viewer/stele_view.py), which
 * verified every record it folded against its own roster. Even so, only one
 * shape renders positive: state "verified-safe" with at least one check, every
 * check clean and every check confirmed by enough verifiers (Phase 2: no single
 * scanner is authoritative). Anything else, including no answer at all, is
 * unverified, unknown, single-source, aging, disputed or failing, never green.
 *
 * Phase 4: the node reads the standing under a PROFILE (viewer/stele_profile.py)
 * and says which. A profile may set a check aside (ignored, or a finding below
 * its severity floor), and that check is shown but not counted here either.
 * What no profile relaxes is re-checked here: a counted finding is never green,
 * a critical finding always counts, a required check that is absent is never
 * green, and a standing with nothing counted is never green.
 *
 * Phase 4, the supply chain: the standing lists the repository's dependencies
 * that resolve to repositories Stele reads. They are lines, never a reason for
 * green. When the profile holds a repository to its worst dependency
 * (`capped_by_deps`), the panel holds it there too.
 *
 * Phase 4, discovery relays: a repository from another AT group is verified
 * only under the group anchor of a polity the reader follows, and the standing
 * names it (`anchored_by`). A relay's own ranking is its word: shown, labelled,
 * and never a reason for any level. */
(function (root) {
  'use strict';

  const LEVELS = {
    'verified-safe': { badge: 'OK', color: '#1a7f37', title: 'Verified safe' },
    aging: { badge: 'OLD', color: '#9a6700', title: 'Aging' },
    unknown: { badge: '?', color: '#57606a', title: 'Unknown' },
    'single-source': { badge: '1', color: '#57606a', title: 'Single source' },
    disputed: { badge: '!?', color: '#bc4c00', title: 'Disputed' },
    'failing-unconfirmed': { badge: '!', color: '#cf222e', title: 'Failing (unconfirmed)' },
    failing: { badge: '!', color: '#cf222e', title: 'Failing' },
    unverified: { badge: '?', color: '#57606a', title: 'Unverified' },
  };
  const NOT_GREEN_WITH_A_FINDING = ['failing', 'failing-unconfirmed', 'disputed'];
  /* Best to worst, as stele_view.STATE_ORDER. */
  const ORDER = ['verified-safe', 'aging', 'single-source', 'unknown', 'disputed',
                 'failing-unconfirmed', 'failing'];
  function worse(a, b) {
    return ORDER.indexOf(b) > ORDER.indexOf(a) ? b : a;
  }

  /* A finding's worst severity on one scale, as stele_profile.severity_rank:
   * 0 low, 1 medium, 2 high, 3 critical, null unrated. */
  const SEVERITY_LABELS = { LOW: 0, INFO: 0, MODERATE: 1, MEDIUM: 1, WARNING: 1,
                            HIGH: 2, ERROR: 2, CRITICAL: 3 };
  const CRITICAL = 3;
  function severityRank(sev) {
    const s = String(sev == null ? '' : sev).trim().toUpperCase();
    if (!s) return null;
    if (/^[0-9]+(\.[0-9]+)?$/.test(s)) {
      const n = Number(s);
      return n < 4 ? 0 : n < 7 ? 1 : n < 9 ? 2 : 3;
    }
    return Object.prototype.hasOwnProperty.call(SEVERITY_LABELS, s) ? SEVERITY_LABELS[s] : null;
  }

  /* Whether a check counts: unless the profile set it aside, and always when it
   * holds a critical finding (no profile sets one aside). A check from a node
   * that predates profiles has no `counted` and counts. */
  function counts(c) {
    if (c && c.verdict === 'vuln' && severityRank(c.max_severity) === CRITICAL) return true;
    return !(c && c.counted === false);
  }

  /* The profile the node read the standing under, for the panel to name. */
  function profileOf(standing) {
    const p = standing && standing.profile;
    if (!p || typeof p !== 'object' || typeof p.name !== 'string') return null;
    return { name: p.name, source: String(p.source || ''),
             issuer: typeof p.issuer === 'string' ? p.issuer : null };
  }

  function days(seconds) {
    return Math.max(0, Math.floor(seconds / 86400));
  }

  /* {level, badge, color, title, summary, lines: [{text, rebuttal}]} for a
   * standing, or for the absence of one (null, or an error string). */
  function render(standing, error) {
    if (standing == null || error) {
      return Object.assign({ level: 'unverified', lines: [],
        summary: error ? 'Your node did not answer: ' + error
                       : 'No standing from your node.' }, LEVELS.unverified);
    }
    if (standing.heard === false) {
      return Object.assign({ level: 'unknown', lines: [],
        summary: 'Your node has not heard of this repository.' }, LEVELS.unknown);
    }
    const checks = Array.isArray(standing.checks) ? standing.checks : [];
    const counted = checks.filter(counts);
    let level = standing.state;
    if (!LEVELS[level] || level === 'unverified') level = 'unknown';
    const allClean = counted.length > 0 && counted.every(c => c.verdict === 'clean');
    const allConfirmed = counted.every(c => c.state === 'confirmed-clean');
    const missing = Array.isArray(standing.missing_required) ? standing.missing_required : [];
    if (level === 'verified-safe' && (!allClean || missing.length)) level = 'unknown';
    if (level === 'verified-safe' && !allConfirmed) level = 'single-source';
    if (!NOT_GREEN_WITH_A_FINDING.includes(level) && counted.some(c => c.verdict === 'vuln')) {
      level = counted.some(c => c.state === 'confirmed-finding') ? 'failing'
                                                                   : 'failing-unconfirmed';
    }
    // The supply chain: a cap the node applied holds here too, and never lifts.
    const deps = standing.deps && typeof standing.deps === 'object' ? standing.deps : null;
    const ownLevel = level;
    if (deps && standing.capped_by_deps && ORDER.includes(deps.state)) {
      level = worse(level, deps.state);
    }

    const lines = checks.map(c => {
      const aside = !counts(c) && c.set_aside ? ' [set aside: ' + String(c.set_aside) + ']' : '';
      return { text: (c.reason || (c.scanner + ': ' + c.verdict)) + aside,
               rebuttal: c.rebuttal || null,
               failing: c.verdict === 'vuln' && counts(c), set_aside: !!aside };
    });
    for (const m of missing) {
      lines.push({ text: 'Required by the profile, never checked: ' + String(m),
                   rebuttal: null, failing: false });
    }
    if (deps) {
      for (const i of Array.isArray(deps.items) ? deps.items : []) {
        if (!i || i.status !== 'resolved') continue;
        const dl = LEVELS[i.state] && i.state !== 'unverified' ? i.state : 'unknown';
        const from = (Array.isArray(i.claimants) ? i.claimants : [])
          .filter(c => c && c.status === 'resolved')
          .map(c => String(c.url || c.name || '?') + (c.via === 'pin' ? ', pinned by you' : ''));
        lines.push({ text: 'Depends on ' + String(i.purl) + ': ' + LEVELS[dl].title
                       + (from.length ? ' (' + from.join('; ') + ')' : ''),
                     rebuttal: null, dep: true, failing: NOT_GREEN_WITH_A_FINDING.includes(dl) });
      }
      if (deps.unresolved > 0) {
        lines.push({ text: String(deps.unresolved) + ' dependenc'
                       + (deps.unresolved === 1 ? 'y' : 'ies')
                       + ' Stele does not read (not on Stele, a version no release names, '
                       + 'or a claim not confirmed); the OSV check covers their known '
                       + 'vulnerabilities.', rebuttal: null, dep: true, failing: false });
      }
      if (deps.sbom === 'not-held') {
        lines.push({ text: 'Your node does not hold the SBOM this release pins, so its '
                       + 'dependencies are not listed.', rebuttal: null, dep: true,
                     failing: false });
      }
    }
    let summary;
    const oldest = checks.length ? Math.min(...checks.map(c => c.ts || 0)) : 0;
    const asOf = standing.as_of || 0;
    if (level !== ownLevel) {
      summary = 'The profile holds this repository to its worst dependency, which is '
        + LEVELS[level].title.toLowerCase() + '.';
    } else if (level === 'verified-safe') {
      summary = 'Every check of the newest commit is clean, verified by your node '
        + '(last scanned ' + days(asOf - oldest) + ' day(s) ago).';
    } else if (level === 'aging') {
      summary = 'Clean when last scanned, ' + days(asOf - oldest)
        + ' day(s) ago; the standing fades without a fresh scan.';
    } else if (level === 'failing') {
      summary = 'A verified finding against the newest commit, confirmed by '
        + 'independent verifiers.';
    } else if (level === 'failing-unconfirmed') {
      summary = 'A verified finding against the newest commit that no second '
        + 'verifier has confirmed yet.';
    } else if (level === 'disputed') {
      summary = 'Verifiers your node counts disagree about the newest commit.';
    } else if (level === 'single-source') {
      summary = 'Clean, but fewer independent verifiers agree than your node '
        + 'requires.';
    } else if (missing.length) {
      summary = 'A check the profile requires has never been run on the newest commit.';
    } else if (checks.length && !counted.length) {
      summary = 'Every check here is set aside by the profile, so nothing is counted.';
    } else if (Array.isArray(standing.earlier_commits) && standing.earlier_commits.length) {
      summary = 'The newest commit has not been verified; earlier commits were.';
    } else {
      summary = 'Nothing about this repository has been verified yet.';
    }
    // A team release (Phase 3): the team it was released under, and the team's
    // own standing, the worst of its repositories. Never a reason for green.
    const team = standing.team;
    if (team && typeof team === 'object') {
      const tl = LEVELS[team.state] && team.state !== 'unverified' ? team.state : 'unknown';
      lines.unshift({ text: 'Released by team ' + String(team.polity_did || team.polity || '?')
                        + ' (officer ' + String(team.officer || '?') + '); team standing: '
                        + LEVELS[tl].title,
                      rebuttal: null, team: true,
                      failing: NOT_GREEN_WITH_A_FINDING.includes(tl) });
    }
    // Another group's repository: whose word its keys and tiers are.
    const anchored = standing.anchored_by;
    if (anchored && typeof anchored === 'object') {
      lines.unshift({ text: 'Another group, read under the anchor of '
                        + String(anchored.polity || '?') + ' (' + String(anchored.tiers || '')
                        + ')', rebuttal: null, anchor: true, failing: false });
      const ck = standing.checkpoints;
      if (ck && typeof ck === 'object' && ck.not_shown > 0) {
        lines.push({ text: 'That group signed ' + ck.listed + ' checkpoint(s) since the first '
                       + 'record shown; records came from ' + ck.with_records + '.',
                     rebuttal: null, anchor: true, failing: false });
      }
    }
    if (standing.reason === 'group not followed') {
      lines.push({ text: 'Found through a relay, in a group whose polity you do not follow: '
                     + 'nothing about it can be verified.', rebuttal: null, failing: false });
    }
    // The reading this is: the profile, and whose it is when followed.
    const profile = profileOf(standing);
    if (profile) {
      summary += ' Read under ' + profile.name
        + (profile.source === 'followed' && profile.issuer
          ? ' (followed: ' + profile.issuer.slice(0, 12) + '…)' : '') + '.';
    }
    return Object.assign({ level, summary, lines, profile }, LEVELS[level]);
  }

  /* The same view for a TEAM's standing (viewer /team, /teams): the worst of its
   * repositories, with every verified finding, the guardian's included, as a
   * concern. Green only when every repository is verified-safe. */
  function renderTeam(ts, error) {
    if (ts == null || error) {
      return Object.assign({ level: 'unverified', lines: [],
        summary: error ? 'Your node did not answer: ' + error
                       : 'Your node has not heard of this team.' }, LEVELS.unverified);
    }
    const repos = Array.isArray(ts.repos) ? ts.repos : [];
    let level = LEVELS[ts.state] && ts.state !== 'unverified' ? ts.state : 'unknown';
    if (level === 'verified-safe'
        && !(repos.length > 0 && repos.every(r => r && r.state === 'verified-safe'))) {
      level = 'unknown';
    }
    const concerns = (Array.isArray(ts.concerns) ? ts.concerns : []).filter(counts);
    if (!NOT_GREEN_WITH_A_FINDING.includes(level) && concerns.length) {
      level = 'failing-unconfirmed';
    }
    const members = ts.team && Array.isArray(ts.team.members) ? ts.team.members.length : 0;
    const lines = concerns.map(c => ({ text: (c.repo ? c.repo + ': ' : '')
                                         + (c.reason || (c.scanner + ': ' + c.verdict)),
                                       rebuttal: c.rebuttal || null, failing: true }));
    const summary = 'Team ' + String((ts.team && ts.team.polity) || '?') + ': ' + members
      + ' member(s), ' + repos.length + ' repositor' + (repos.length === 1 ? 'y' : 'ies')
      + '; the worst of them stands for the team.';
    return Object.assign({ level, summary, lines }, LEVELS[level]);
  }

  /* The organization a Forgejo or Gitea page belongs to, when the page is an
   * organization's own (one path segment, and the server marked it as an
   * organization page), else null. */
  function orgOf(pathname, isOrgPage) {
    const parts = String(pathname || '').split('/').filter(Boolean);
    return isOrgPage && parts.length === 1 && /^[A-Za-z0-9._-]+$/.test(parts[0])
      ? parts[0] : null;
  }

  function httpUrl(s) {
    const u = String(s || '').trim();
    return /^https?:\/\/\S+$/.test(u) ? u : null;
  }

  /* The clone URL from a repository page, or null when the page is not one:
   * first the go-import meta ("<import path> git <clone url>"), which Gitea
   * serves on every repository page but Forgejo only with ?go-get=1; then the
   * HTTPS clone button's data-link, as Forgejo renders it on the repository
   * home. Both are the server's markup; the clone box's input value is not
   * used, since the page's own script rewrites it. */
  function cloneUrl(goImport, httpsLink) {
    const parts = String(goImport || '').trim().split(/\s+/);
    if (parts.length === 3 && parts[1] === 'git' && httpUrl(parts[2])) return parts[2];
    return httpUrl(httpsLink);
  }

  /* The URLs to ask about, in order: the clone URL as served, then with or
   * without its ".git", since an owner may advertise either. */
  function candidates(url) {
    if (!url) return [];
    return url.endsWith('.git') ? [url, url.slice(0, -4)] : [url, url + '.git'];
  }

  /* Where a repository's owner may publish a standing bundle: in the
   * repository itself, at .stele/standing.json, read raw from the forge on
   * the default branch names a Forgejo or Gitea repository usually has. The
   * forge's bytes are only ever INPUT to the viewer's node, which believes
   * them as far as they verify against its own roster. */
  function bundleUrls(url) {
    if (!url) return [];
    const web = url.endsWith('.git') ? url.slice(0, -4) : url;
    return ['main', 'master'].map(b => web + '/raw/branch/' + b + '/.stele/standing.json');
  }

  /* One relay search result (viewer /relay/search): the reader's own standing
   * when it verified one, else unverified; each relay's word is a line,
   * labelled, and changes no level. */
  function renderRelay(entry) {
    const e = entry && typeof entry === 'object' ? entry : {};
    const base = e.verified ? render(e.verified)
      : Object.assign({ level: 'unverified', lines: [],
          summary: e.reason === 'group not followed'
            ? 'Found through a relay, in a group whose polity you do not follow.'
            : 'Found through a relay; your node has not verified it yet.' },
        LEVELS.unverified);
    const lines = base.lines.slice();
    for (const w of Array.isArray(e.relays) ? e.relays : []) {
      lines.push({ text: 'The relay ' + String(w.relay || '?') + ' says: '
                     + Number(w.findings || 0) + ' finding(s), ' + Number(w.clean || 0)
                     + ' clean, ' + Number(w.verifiers || 0)
                     + ' verifier(s). Its word, not verified.',
                   rebuttal: null, relay: true, failing: false });
    }
    return Object.assign({}, base, { lines, repo: e.repo || null });
  }

  const api = { render, renderTeam, renderRelay, orgOf, cloneUrl, candidates, bundleUrls,
                LEVELS, severityRank, counts, profileOf };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.stelePanel = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
