// node --test tests/panel.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { render } = require('../panel.js');

const clean = { verdict: 'clean', ts: 1000, reason: 'osv-scanner on probe: clean',
                state: 'confirmed-clean' };
const vuln = { verdict: 'vuln', ts: 1000, reason: 'osv-scanner on probe: vuln',
               rebuttal: 'vendored' };

test('no answer from the node is unverified, never green', () => {
  assert.equal(render(null).level, 'unverified');
  assert.equal(render(null, 'connection refused').level, 'unverified');
  assert.equal(render({ state: 'unknown', heard: false }).level, 'unknown');
});

test('only verified-safe with every check clean renders positive', () => {
  assert.equal(render({ state: 'verified-safe', checks: [clean], as_of: 1000 }).level,
               'verified-safe');
  // A standing that claims safe without checks, or with a finding, is not.
  assert.equal(render({ state: 'verified-safe', checks: [] }).level, 'unknown');
  assert.equal(render({ state: 'verified-safe', checks: [clean, vuln] }).level,
               'failing-unconfirmed');
  assert.equal(render({ state: 'green', checks: [clean] }).level, 'unknown');
});

test('a failing standing shows each reason and the owner rebuttal', () => {
  const r = render({ state: 'failing', checks: [vuln] });
  assert.equal(r.badge, '!');
  assert.equal(r.lines[0].text, 'osv-scanner on probe: vuln');
  assert.equal(r.lines[0].rebuttal, 'vendored');
});

test('aging says how long ago it was scanned', () => {
  const r = render({ state: 'aging', checks: [clean], as_of: 1000 + 40 * 86400 });
  assert.match(r.summary, /40 day/);
});

test('the clone URL comes from go-import or the HTTPS clone button, nothing else', () => {
  const { cloneUrl, candidates } = require('../panel.js');
  assert.equal(cloneUrl('localhost:3000/alice/demo git http://localhost:3000/alice/demo.git'),
               'http://localhost:3000/alice/demo.git');
  assert.equal(cloneUrl('localhost:3000/alice/demo mod http://x/y'), null);
  assert.equal(cloneUrl('a git javascript:alert(1)'), null);
  assert.equal(cloneUrl(null), null);
  // Forgejo's repository home: no go-import meta, the HTTPS clone button only.
  assert.equal(cloneUrl(null, 'http://localhost:3000/alice/demo.git'),
               'http://localhost:3000/alice/demo.git');
  assert.equal(cloneUrl('a git http://h/a/b.git', 'http://h/other.git'), 'http://h/a/b.git');
  assert.equal(cloneUrl(null, 'javascript:alert(1)'), null);
  assert.equal(cloneUrl(null, 'git@h:a/b.git'), null);
  assert.deepEqual(candidates('http://h/a/b.git'), ['http://h/a/b.git', 'http://h/a/b']);
  assert.deepEqual(candidates('http://h/a/b'), ['http://h/a/b', 'http://h/a/b.git']);
});

test('green needs every check confirmed by enough verifiers', () => {
  const lone = Object.assign({}, clean, { state: 'single-source' });
  assert.equal(render({ state: 'verified-safe', checks: [clean, lone] }).level,
               'single-source');
  assert.equal(render({ state: 'single-source', checks: [lone] }).badge, '1');
});

test('a finding is failing only once confirmed; disagreement is disputed', () => {
  const confirmed = Object.assign({}, vuln, { state: 'confirmed-finding' });
  assert.equal(render({ state: 'aging', checks: [confirmed] }).level, 'failing');
  assert.equal(render({ state: 'unknown', checks: [vuln] }).level, 'failing-unconfirmed');
  const d = render({ state: 'disputed', checks: [Object.assign({}, vuln,
                                                               { state: 'disputed' })] });
  assert.equal(d.level, 'disputed');
  assert.notEqual(d.color, '#1a7f37');
});

test('the bundle is looked for in the repository, raw from the forge', () => {
  const { bundleUrls } = require('../panel.js');
  assert.deepEqual(bundleUrls('http://h/a/b.git'), [
    'http://h/a/b/raw/branch/main/.stele/standing.json',
    'http://h/a/b/raw/branch/master/.stele/standing.json']);
  assert.deepEqual(bundleUrls(null), []);
});

test('a team release names its team and the team standing, never as green', () => {
  const { render } = require('../panel.js');
  const r = render({ state: 'verified-safe', checks: [clean], as_of: 1000,
                     team: { polity_did: 'did:key:zteam', officer: 'did:key:zo',
                             state: 'failing' } });
  // The repository's own badge follows its own checks; the team's failing
  // standing is the line above them, in red.
  assert.equal(r.level, 'verified-safe');
  assert.equal(r.lines[0].team, true);
  assert.match(r.lines[0].text, /team did:key:zteam .* team standing: Failing/);
  assert.equal(r.lines[0].failing, true);
});

test('a team renders the worst of its repositories, with its concerns', () => {
  const { renderTeam } = require('../panel.js');
  assert.equal(renderTeam(null).level, 'unverified');
  const safe = { state: 'verified-safe', repos: [{ state: 'verified-safe' }],
                 team: { polity: 'did:key:zteam', members: [{}, {}] }, concerns: [] };
  assert.equal(renderTeam(safe).level, 'verified-safe');
  // Claimed safe over a repository that is not: not green.
  assert.equal(renderTeam(Object.assign({}, safe,
    { repos: [{ state: 'verified-safe' }, { state: 'single-source' }] })).level, 'unknown');
  // A concern is never green.
  const withConcern = Object.assign({}, safe, { concerns: [
    { repo: 'demo', reason: 'osv-scanner: did:key:zg answers for did:key:zci' }] });
  const r = renderTeam(withConcern);
  assert.equal(r.level, 'failing-unconfirmed');
  assert.match(r.lines[0].text, /^demo: osv-scanner/);
  assert.match(r.summary, /2 member\(s\), 1 repository/);
  assert.equal(renderTeam(Object.assign({}, safe, { state: 'failing' })).badge, '!');
});

test('an organization page is one path segment the server marked as one', () => {
  const { orgOf } = require('../panel.js');
  assert.equal(orgOf('/stele', true), 'stele');
  assert.equal(orgOf('/stele/', true), 'stele');
  assert.equal(orgOf('/stele', false), null);
  assert.equal(orgOf('/stele/demo', true), null);
  assert.equal(orgOf('/', true), null);
  assert.equal(orgOf('/a b', true), null);
});

// Phase 4: profiles. The node reads the standing under a profile and says so;
// the panel honours what the profile set aside, inside the floors.
const { severityRank, renderTeam } = require('../panel.js');

test('a check the profile set aside is shown but not counted', () => {
  const aside = Object.assign({}, vuln, { counted: false, max_severity: '5.0',
    state: 'confirmed-finding', set_aside: 'below the high severity floor of tolerant' });
  const r = render({ state: 'verified-safe', checks: [clean, aside], as_of: 1000,
                     profile: { name: 'tolerant', source: 'local' } });
  assert.equal(r.level, 'verified-safe');
  assert.match(r.lines[1].text, /\[set aside: below the high severity floor of tolerant\]/);
  assert.equal(r.lines[1].failing, false);
  assert.match(r.summary, /Read under tolerant\./);
  assert.deepEqual(r.profile, { name: 'tolerant', source: 'local', issuer: null });
});

test('no profile sets aside a critical finding, and nothing counted is not green', () => {
  const critical = Object.assign({}, vuln, { counted: false, max_severity: 'CRITICAL',
                                             state: 'confirmed-finding', set_aside: 'x' });
  assert.equal(render({ state: 'verified-safe', checks: [clean, critical] }).level, 'failing');
  const ignored = Object.assign({}, clean, { counted: false, set_aside: 'ignored by p' });
  assert.equal(render({ state: 'verified-safe', checks: [ignored] }).level, 'unknown');
});

test('a required check that is absent is never green', () => {
  const r = render({ state: 'verified-safe', checks: [clean],
                     missing_required: ['gitleaks:probe'] });
  assert.equal(r.level, 'unknown');
  assert.equal(r.lines.at(-1).text, 'Required by the profile, never checked: gitleaks:probe');
});

test('a followed profile is named with its issuer', () => {
  const r = render({ state: 'single-source', checks: [Object.assign({}, clean,
                     { state: 'single-source' })],
                     profile: { name: 'acme', source: 'followed', issuer: 'ab'.repeat(32) } });
  assert.match(r.summary, /Read under acme \(followed: abababababab…\)\./);
});

test('severities land on the same scale as the node', () => {
  for (const [s, n] of [['9.8', 3], ['9.0', 3], ['8.9', 2], ['7.0', 2], ['6.9', 1],
                        ['4.0', 1], ['3.9', 0], ['CRITICAL', 3], ['high', 2],
                        ['MODERATE', 1], ['WARNING', 1], ['INFO', 0], ['SECRET', null],
                        ['', null], [null, null]]) {
    assert.equal(severityRank(s), n, String(s));
  }
});

test('a team concern the profile set aside does not fail the team', () => {
  const repo = { state: 'verified-safe' };
  const aside = { verdict: 'vuln', counted: false, max_severity: '5.0', reason: 'x' };
  assert.equal(renderTeam({ state: 'verified-safe', repos: [repo], concerns: [aside],
                            team: { members: [] } }).level, 'verified-safe');
  const counted = { verdict: 'vuln', reason: 'y' };
  assert.equal(renderTeam({ state: 'verified-safe', repos: [repo], concerns: [counted],
                            team: { members: [] } }).level, 'failing-unconfirmed');
});

// Phase 4: the supply chain. Dependencies are lines; the profile's cap holds.
const libFailing = { purl: 'pkg:golang/forge.local/alice/lib@v1.0.0', status: 'resolved',
                     state: 'failing',
                     claimants: [{ status: 'resolved', url: 'http://f/lib.git', via: 'provides' }] };

test('a dependency is a line beside the repository, never a reason for green', () => {
  const r = render({ state: 'verified-safe', checks: [clean], as_of: 1000,
                     deps: { sbom: 'held', items: [libFailing], state: 'failing',
                             resolved: 1, unresolved: 2 } });
  assert.equal(r.level, 'verified-safe');
  const dep = r.lines.find(l => l.dep && /Depends on/.test(l.text));
  assert.match(dep.text, /lib@v1\.0\.0: Failing \(http:\/\/f\/lib\.git\)/);
  assert.equal(dep.failing, true);
  assert.ok(r.lines.some(l => /2 dependencies Stele does not read/.test(l.text)));
});

test('a cap on the worst dependency holds in the panel too', () => {
  const r = render({ state: 'verified-safe', checks: [clean], as_of: 1000,
                     capped_by_deps: true,
                     deps: { sbom: 'held', items: [libFailing], state: 'failing',
                             resolved: 1, unresolved: 0 } });
  assert.equal(r.level, 'failing');
  assert.match(r.summary, /holds this repository to its worst dependency, which is failing/);
  // A cap never lifts: a clean dependency does not raise a failing repository.
  const own = render({ state: 'failing', checks: [Object.assign({}, vuln, {
                         state: 'confirmed-finding' })], as_of: 1000, capped_by_deps: true,
                       deps: { sbom: 'held', items: [], state: 'verified-safe' } });
  assert.equal(own.level, 'failing');
});

test('an SBOM the node does not hold is said, and a pin is named', () => {
  const r = render({ state: 'verified-safe', checks: [clean], as_of: 1000,
                     deps: { sbom: 'not-held', items: [], state: null } });
  assert.ok(r.lines.some(l => /does not hold the SBOM/.test(l.text)));
  const pinned = Object.assign({}, libFailing, { state: 'verified-safe', claimants: [
    { status: 'resolved', url: 'http://f/lib.git', via: 'pin' }] });
  const p = render({ state: 'verified-safe', checks: [clean], as_of: 1000,
                     deps: { sbom: 'held', items: [pinned], state: 'verified-safe' } });
  assert.ok(p.lines.some(l => /pinned by you/.test(l.text)));
});

// Phase 4: discovery relays. Another group's standing names its anchor; a
// relay's word is a line and never a level.
test('another group is read under the anchor of the polity the reader follows', () => {
  const r = render({ state: 'verified-safe', checks: [clean], as_of: 1000,
                     anchored_by: { polity: 'did:key:zP', tiers: 'tiers as did:key:zP reads them' },
                     checkpoints: { listed: 5, with_records: 2, not_shown: 3 } });
  assert.equal(r.level, 'verified-safe');
  assert.match(r.lines[0].text, /read under the anchor of did:key:zP \(tiers as did:key:zP/);
  assert.ok(r.lines.some(l => /signed 5 checkpoint\(s\).*records came from 2/.test(l.text)));
});

test('a relay result is never green on the relays word', () => {
  const { renderRelay } = require('../panel.js');
  const r = renderRelay({ repo: { name: 'x' }, reason: 'group not followed',
                          relays: [{ relay: 'r:1', findings: 0, clean: 9, verifiers: 3 }] });
  assert.equal(r.level, 'unverified');
  assert.match(r.summary, /do not follow/);
  const v = renderRelay({ verified: { state: 'failing', checks: [Object.assign({}, vuln,
                          { state: 'confirmed-finding' })] },
                          relays: [{ relay: 'r:1', findings: 0, clean: 9, verifiers: 3 }] });
  assert.equal(v.level, 'failing');                 // the reader's, not the relay's
  assert.equal(v.lines[v.lines.length - 1].relay, true);
});
