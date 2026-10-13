/* Stele trust panel, background: the only part that talks to the viewer's
 * node (viewer/stele_view.py on 127.0.0.1). The service sends no CORS
 * headers, so a forge page cannot ask it anything; this worker can.
 *
 * It also sets the toolbar badge for the tab. The page can draw anything it
 * likes inside itself, including a fake panel, but it cannot touch the
 * toolbar, so the badge is the indicator to trust. */
'use strict';
if (typeof importScripts === 'function' && !globalThis.stelePanel) {
  importScripts('panel.js');
}

const DEFAULT_PORT = 8099;

async function port() {
  try {
    const got = await chrome.storage.local.get({ port: DEFAULT_PORT });
    const p = Number(got.port);
    return Number.isInteger(p) && p > 0 && p < 65536 ? p : DEFAULT_PORT;
  } catch (e) {
    return DEFAULT_PORT;
  }
}

/* The profile to read standings under (Phase 4): blank leaves it to the node
 * (its etc/stele/profile.json, else stele-default). Only a name the node could
 * have is sent; the node refuses one it cannot apply, and the panel then shows
 * that error rather than an answer under some other profile. */
async function profile() {
  try {
    const got = await chrome.storage.local.get({ profile: '' });
    const p = String(got.profile || '').trim();
    return /^[a-z0-9._-]{1,64}$/.test(p) ? p : '';
  } catch (e) {
    return '';
  }
}

function withProfile(path, p) {
  return p ? path + (path.includes('?') ? '&' : '?') + 'profile=' + encodeURIComponent(p)
           : path;
}

async function ask(path, body) {
  const base = 'http://127.0.0.1:' + (await port());
  path = withProfile(path, await profile());
  const opts = { cache: 'no-store', credentials: 'omit' };
  if (body !== undefined) {
    opts.method = 'POST';
    opts.headers = { 'Content-Type': 'application/json' };
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(base + path, opts);
  if (resp.status === 404) return null;
  if (!resp.ok) throw new Error('HTTP ' + resp.status);
  return resp.json();
}

/* The standing for the first candidate URL the node has heard of, or an
 * explicit "not heard" when none. A bundle the page found (the owner's
 * .stele/standing.json) goes to the node's POST /verify, which folds in only
 * what verifies against the node's own roster; nothing in it is read here. */
async function standing(url, bundle) {
  for (const u of stelePanel.candidates(url)) {
    if (bundle && typeof bundle === 'object') {
      const r = await ask('/verify?url=' + encodeURIComponent(u), bundle);
      if (r && r.standing && r.standing.heard !== false) {
        return Object.assign({}, r.standing,
          { bundle: { verified: r.verified | 0,
                      unverified: Array.isArray(r.unverified) ? r.unverified.length : 0 } });
      }
      continue;
    }
    const st = await ask('/standing?url=' + encodeURIComponent(u));
    if (st) return st;
  }
  // Not heard in the node's own group: ask its discovery relays (Phase 4). What
  // they hand over is folded in and verified by the node, under the anchor of
  // a polity it follows, or not at all.
  if (!(bundle && typeof bundle === 'object')) {
    for (const u of stelePanel.candidates(url)) {
      const r = await ask('/relay/standing?url=' + encodeURIComponent(u));
      if (r && r.standing && r.standing.heard !== false) {
        return Object.assign({}, r.standing, r.reason ? { reason: r.reason } : {},
          { relays: Array.isArray(r.relays) ? r.relays.length : 0 });
      }
    }
  }
  return { state: 'unknown', heard: false };
}

function badge(tabId, view) {
  if (tabId == null) return;
  chrome.action.setBadgeText({ tabId, text: view.badge });
  chrome.action.setBadgeBackgroundColor({ tabId, color: view.color });
  chrome.action.setTitle({ tabId, title: 'Stele: ' + view.title + '. ' + view.summary });
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg && msg.type === 'standing' && typeof msg.url === 'string') {
    const tabId = sender.tab ? sender.tab.id : null;
    standing(msg.url, msg.bundle)
      .then(st => { badge(tabId, stelePanel.render(st)); reply({ standing: st }); })
      .catch(e => { badge(tabId, stelePanel.render(null, String(e.message || e)));
                    reply({ error: String(e.message || e) }); });
    return true;
  }
  if (msg && msg.type === 'team' && typeof msg.q === 'string') {
    // An organization page: the best-matching team this node holds a roster
    // for (viewer /teams), shown with its worst-of standing.
    const tabId = sender.tab ? sender.tab.id : null;
    ask('/teams?q=' + encodeURIComponent(msg.q))
      .then(r => {
        const ts = (r && Array.isArray(r.results) && r.results[0]) || null;
        if (ts) badge(tabId, stelePanel.renderTeam(ts));
        reply({ team: ts });
      })
      .catch(e => reply({ error: String(e.message || e) }));
    return true;
  }
  if (msg && msg.type === 'relay-search' && typeof msg.q === 'string') {
    // Other groups' repositories, through the node's discovery relays: each
    // relay's word beside what the node verified (viewer /relay/search).
    ask('/relay/search?q=' + encodeURIComponent(msg.q))
      .then(r => reply({ results: ((r && r.results) || []).map(stelePanel.renderRelay) }))
      .catch(e => reply({ error: String(e.message || e) }));
    return true;
  }
  if (msg && msg.type === 'relay-standing' && typeof msg.url === 'string') {
    ask('/relay/standing?url=' + encodeURIComponent(msg.url))
      .then(r => reply({ standing: r && r.standing, relays: r && r.relays }))
      .catch(e => reply({ error: String(e.message || e) }));
    return true;
  }
  if (msg && msg.type === 'search' && typeof msg.q === 'string') {
    ask('/search?q=' + encodeURIComponent(msg.q))
      .then(r => reply({ results: (r && r.results) || [] }))
      .catch(e => reply({ error: String(e.message || e) }));
    return true;
  }
  return false;
});
