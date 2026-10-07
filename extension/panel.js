/* Stele trust panel: what to show for a standing, as data. No DOM here, so
 * the rules can be tested on their own (tests/panel.test.mjs).
 *
 * The standing comes from the viewer's OWN node (viewer/stele_view.py), which
 * verified every record it folded against its own roster. Even so, only one
 * shape renders positive: state "verified-safe" with at least one check, every
 * check clean and every check confirmed by enough verifiers (Phase 2: no single
 * scanner is authoritative). Anything else, including no answer at all, is
 * unverified, unknown, single-source, aging, disputed or failing, never green. */
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
    let level = standing.state;
    if (!LEVELS[level] || level === 'unverified') level = 'unknown';
    const allClean = checks.length > 0 && checks.every(c => c.verdict === 'clean');
    const allConfirmed = checks.every(c => c.state === 'confirmed-clean');
    if (level === 'verified-safe' && !allClean) level = 'unknown';
    if (level === 'verified-safe' && !allConfirmed) level = 'single-source';
    if (!NOT_GREEN_WITH_A_FINDING.includes(level) && checks.some(c => c.verdict === 'vuln')) {
      level = checks.some(c => c.state === 'confirmed-finding') ? 'failing'
                                                                  : 'failing-unconfirmed';
    }

    const lines = checks.map(c => ({ text: c.reason || (c.scanner + ': ' + c.verdict),
                                     rebuttal: c.rebuttal || null,
                                     failing: c.verdict === 'vuln' }));
    let summary;
    const oldest = checks.length ? Math.min(...checks.map(c => c.ts || 0)) : 0;
    const asOf = standing.as_of || 0;
    if (level === 'verified-safe') {
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
    } else if (Array.isArray(standing.earlier_commits) && standing.earlier_commits.length) {
      summary = 'The newest commit has not been verified; earlier commits were.';
    } else {
      summary = 'Nothing about this repository has been verified yet.';
    }
    return Object.assign({ level, summary, lines }, LEVELS[level]);
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

  const api = { render, cloneUrl, candidates, bundleUrls, LEVELS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.stelePanel = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
