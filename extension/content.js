/* Stele trust panel, content script: on a Forgejo or Gitea repository page,
 * read the clone URL and show what the viewer's own node says about it.
 *
 * The page supplies only WHICH repository this is, and, if the owner published
 * one, a standing bundle (.stele/standing.json in the repository), which is
 * handed to the viewer's node as INPUT: the node believes it only as far as its
 * records verify against the node's own roster. Nothing the forge serves is
 * shown as evidence. The panel is built with textContent alone, since the
 * reasons and the owner's rebuttal are text other people wrote. */
(function () {
  'use strict';
  const meta = document.querySelector('meta[name="go-import"]');
  const https = document.getElementById('repo-clone-https');
  const url = stelePanel.cloneUrl(meta && meta.getAttribute('content'),
                                  https && https.getAttribute('data-link'));
  if (!url) return;

  function el(tag, style, text) {
    const e = document.createElement(tag);
    if (style) e.setAttribute('style', style);
    if (text != null) e.textContent = text;
    return e;
  }

  function show(view) {
    const host = el('div', 'position:fixed;right:16px;bottom:16px;z-index:2147483647');
    const root = host.attachShadow({ mode: 'closed' });
    const box = el('div', 'font:13px/1.4 system-ui,sans-serif;max-width:360px;'
      + 'background:#fff;color:#1f2328;border:2px solid ' + view.color
      + ';border-radius:8px;padding:10px 12px;box-shadow:0 2px 8px rgba(0,0,0,.2)');
    const head = el('div', 'font-weight:600;color:' + view.color,
                    'Stele: ' + view.title);
    const close = el('button', 'float:right;border:0;background:none;cursor:pointer', 'x');
    close.addEventListener('click', () => host.remove());
    head.prepend(close);
    box.append(head, el('div', 'margin-top:4px', view.summary));
    for (const line of view.lines) {
      const item = el('div', 'margin-top:6px;' + (line.failing ? 'color:#cf222e' : ''),
                      line.text);
      if (line.rebuttal) {
        item.append(el('div', 'margin-top:2px;color:#57606a;font-style:italic',
                       "Owner's response (not scored): " + line.rebuttal));
      }
      box.append(item);
    }
    box.append(el('div', 'margin-top:6px;color:#57606a;font-size:11px',
                  'From your own node. The toolbar badge is the authoritative indicator.'));
    root.append(box);
    document.documentElement.append(host);
  }

  /* The owner's bundle, if the forge serves one: same origin as this page,
   * at most 4 MiB, JSON. Any failure means "no bundle". */
  async function bundle() {
    for (const u of stelePanel.bundleUrls(url)) {
      try {
        const r = await fetch(u, { credentials: 'omit', cache: 'no-store' });
        const len = Number(r.headers.get('Content-Length') || 0);
        if (!r.ok || len > 4 * 1024 * 1024) continue;
        const b = await r.json();
        if (b && typeof b === 'object' && !Array.isArray(b)) return b;
      } catch (e) { /* not there, or not JSON */ }
    }
    return undefined;
  }

  bundle().then(b => chrome.runtime.sendMessage({ type: 'standing', url, bundle: b }, resp => {
    if (chrome.runtime.lastError || !resp) {
      show(stelePanel.render(null, chrome.runtime.lastError
        ? chrome.runtime.lastError.message : 'no reply'));
    } else {
      show(stelePanel.render(resp.standing || null, resp.error));
    }
  }));
})();
