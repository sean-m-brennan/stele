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
