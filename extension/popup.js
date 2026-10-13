/* Stele trust panel, popup: discovery over what the viewer's node has heard,
 * best standing first. There is no global index; a repository nobody
 * advertised to this node is not here. */
'use strict';
const q = document.getElementById('q');
const out = document.getElementById('out');
const portBox = document.getElementById('port');

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function show(resp) {
  out.replaceChildren();
  if (!resp || resp.error) {
    out.append(el('div', 'muted', 'Your node did not answer: '
      + (resp ? resp.error : 'no reply')));
    return;
  }
  if (!resp.results.length) out.append(el('div', 'muted', 'Nothing heard matches.'));
  for (const st of resp.results) {
    const view = stelePanel.render(st);
    const hit = el('div', 'hit');
    hit.style.borderLeftColor = view.color;
    hit.append(el('div', 'name', st.repo.name + '  ' + view.title),
               el('div', 'muted', (st.repo.url || '')
                 + (view.profile ? '  (' + view.profile.name + ')' : '')),
               el('div', null, st.repo.description || ''));
    out.append(hit);
  }
}

let timer = null;
q.addEventListener('input', () => {
  clearTimeout(timer);
  timer = setTimeout(() => chrome.runtime.sendMessage({ type: 'search', q: q.value },
                                                      resp => show(resp)), 200);
});

chrome.storage.local.get({ port: 8099 }, got => { portBox.value = got.port; });
/* The profile standings are read under (Phase 4); blank is the node's choice. */
const profileBox = document.getElementById('profile');
chrome.storage.local.get({ profile: '' }, got => { profileBox.value = got.profile; });
profileBox.addEventListener('change', () => {
  const p = profileBox.value.trim();
  if (p === '' || /^[a-z0-9._-]{1,64}$/.test(p)) chrome.storage.local.set({ profile: p });
});
portBox.addEventListener('change', () => {
  const p = Number(portBox.value);
  if (Number.isInteger(p) && p > 0 && p < 65536) chrome.storage.local.set({ port: p });
});
/* Firefox treats MV3 host permissions as opt-in: until they are granted the
 * content script never runs and the node cannot be asked. Chromium grants
 * them at install, so there this stays hidden. */
const NEEDED = { origins: ['http://127.0.0.1/*', 'http://*/*', 'https://*/*'] };
const grant = document.getElementById('grant');
chrome.permissions.contains(NEEDED, ok => { grant.hidden = ok; });
document.getElementById('grant-btn').addEventListener('click', () => {
  chrome.permissions.request(NEEDED, ok => { grant.hidden = ok; });
});
q.focus();
