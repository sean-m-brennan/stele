// node --test tests/background.test.mjs
// The background worker with chrome.* and fetch stubbed: what the toolbar
// badge (the indicator a page cannot forge) says for each answer.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const here = new URL('..', import.meta.url);
const src = f => readFileSync(new URL(f, here), 'utf8');

function worker(fetchImpl) {
  const badges = {};
  let listener;
  const chrome = {
    storage: { local: { get: async d => d } },
    action: {
      setBadgeText: ({ tabId, text }) => { badges[tabId] = text; },
      setBadgeBackgroundColor: () => {}, setTitle: () => {},
    },
    runtime: { onMessage: { addListener: f => { listener = f; } } },
  };
  const ctx = vm.createContext({ chrome, fetch: fetchImpl, encodeURIComponent,
                                 console, Error, Number });
  ctx.globalThis = ctx;
  vm.runInContext(src('panel.js'), ctx);
  vm.runInContext(src('background.js'), ctx);
  const send = msg => new Promise(res => listener(msg, { tab: { id: 7 } }, res));
  return { send, badges };
}

const json = (status, body) => async () => ({ status, ok: status < 300, json: async () => body });

test('a verified-safe standing is the only green badge', async () => {
  const w = worker(json(200, { state: 'verified-safe', as_of: 1000,
                               checks: [{ verdict: 'clean', ts: 1000,
                                          state: 'confirmed-clean' }] }));
  await w.send({ type: 'standing', url: 'http://f/a/b.git' });
  assert.equal(w.badges[7], 'OK');
});

test('an unreachable node is unverified', async () => {
  const w = worker(async () => { throw new Error('connection refused'); });
  const r = await w.send({ type: 'standing', url: 'http://f/a/b.git' });
  assert.equal(r.error, 'connection refused');
  assert.equal(w.badges[7], '?');
});

test('both URL spellings are asked before saying unheard', async () => {
  const asked = [];
  const w = worker(async u => { asked.push(u); return { status: 404, ok: false }; });
  const r = await w.send({ type: 'standing', url: 'http://f/a/b.git' });
  assert.equal(r.standing.heard, false);
  assert.equal(asked.length, 2);
  assert.match(asked[1], /url=http%3A%2F%2Ff%2Fa%2Fb$/);
});

test('a failing standing badges red, whatever else it claims', async () => {
  const w = worker(json(200, { state: 'verified-safe',
                               checks: [{ verdict: 'clean' }, { verdict: 'vuln' }] }));
  await w.send({ type: 'standing', url: 'http://f/a/b.git' });
  assert.equal(w.badges[7], '!');
});

test('a bundle goes to the node to verify, never straight to the badge', async () => {
  const calls = [];
  const w = worker(async (u, opts) => {
    calls.push({ u, method: (opts && opts.method) || 'GET', body: opts && opts.body });
    return { status: 200, ok: true, json: async () => ({
      verified: 0, unverified: [{ reasons: ['checkpoint short of a quorum'] }],
      standing: { state: 'failing-unconfirmed', checks: [{ verdict: 'vuln' }] } }) };
  });
  // The forged bundle claims a clean, confirmed bill of health.
  const forged = { records: [{ entry: {} }], state: 'verified-safe' };
  const r = await w.send({ type: 'standing', url: 'http://f/a/b.git', bundle: forged });
  assert.equal(calls[0].method, 'POST');
  assert.match(calls[0].u, /\/verify\?url=/);
  assert.deepEqual(JSON.parse(calls[0].body), forged);
  assert.equal(r.standing.bundle.unverified, 1);
  assert.equal(w.badges[7], '!');
});
