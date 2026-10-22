// EMCON content script: collects page facts, renders badges/warnings, and relays
// Ghost sign-in requests. Holds no secrets; every decision happens in the worker.
(() => {
  if (window.__emconBridge) return;
  window.__emconBridge = true;
  const isTop = window.top === window;

  const send = (msg) => new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(msg, (r) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      r?.error ? reject(new Error(r.error)) : resolve(r?.result);
    });
  });

  // ---------------- UI host (closed shadow root, so the page can't restyle or read it) ----------------
  const host = document.createElement('emcon-ui');
  host.style.cssText = 'position:absolute;top:0;left:0;width:0;height:0;z-index:2147483646;';
  const root = host.attachShadow({ mode: 'closed' });
  root.innerHTML = `<style>
    :host { all: initial; }
    * { box-sizing: border-box; font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
    .badge { position: absolute; display: flex; align-items: center; gap: 5px; padding: 3px 8px; border-radius: 999px; font: 600 12px/1.4 system-ui; color: #fff; cursor: pointer; box-shadow: 0 2px 8px rgba(0,0,0,.3); white-space: nowrap; }
    .verified { background: #12805c; } .recovered { background: #1f6f8b; } .untrusted { background: #8a6d00; } .altered, .forged { background: #c62f2f; } .c2pa { background: #4b5563; }
    .pop { position: absolute; width: 320px; background: #fff; color: #14171c; border-radius: 12px; padding: 14px; box-shadow: 0 10px 40px rgba(0,0,0,.35); font-size: 13px; line-height: 1.45; }
    .pop h4 { margin: 0 0 6px; font-size: 14px; } .pop .k { color: #5d6673; } .pop a { color: #2f5bea; }
    .wall { position: fixed; inset: 0; background: rgba(120, 10, 10, .96); color: #fff; display: grid; place-items: center; padding: 16px; z-index: 2147483647; }
    .wall .box { max-width: 560px; width: 100%; }
    .wall h1 { font-size: 28px; margin: 0 0 8px; } .wall li { margin: 6px 0; }
    .wall button { font: 600 15px system-ui; padding: 11px 18px; border-radius: 10px; border: 0; cursor: pointer; margin: 8px 8px 0 0; }
    .wall .leave { background: #fff; color: #8b1111; } .wall .stay { background: transparent; color: #fff; border: 1px solid rgba(255,255,255,.5); }
    .bar { position: fixed; top: 0; left: 0; right: 0; background: #b26a00; color: #fff; padding: 9px 14px; font: 500 14px system-ui; display: flex; gap: 12px; align-items: center; z-index: 2147483647; }
    .bar button { margin-left: auto; background: rgba(255,255,255,.2); color: #fff; border: 0; border-radius: 6px; padding: 4px 10px; cursor: pointer; }
  </style><div id="layer"></div>`;
  const layer = root.getElementById('layer');
  const mount = () => { if (!host.isConnected) document.documentElement.appendChild(host); };
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ---------------- Ghost bridge ----------------
  document.documentElement.setAttribute('data-emcon', '1');
  window.addEventListener('message', async (e) => {
    if (e.source !== window || e.data?.type !== 'EMCON_GHOST_REQUEST') return;
    const { id, challenge, claims, forceToken } = e.data;
    let reply;
    try { reply = { ok: true, result: await send({ type: 'ghost:request', challenge: String(challenge), claims: Array.isArray(claims) ? claims : [], forceToken: !!forceToken }) }; }
    catch (err) { reply = { ok: false, error: err.message }; }
    window.postMessage({ type: 'EMCON_GHOST_RESPONSE', id, ...reply }, location.origin);
  });

  if (!isTop) return;

  // ---------------- Shield 2: provenance badges ----------------
  const LABEL = {
    verified: (r) => `✔ Verified · ${r.issuerName}`,
    recovered: (r) => `↺ Provenance recovered · ${r.match.issuerName}`,
    untrusted: () => '? Signed · unknown signer',
    altered: () => '✖ Altered after signing',
    forged: () => '✖ Forged provenance',
    c2pa: () => 'ⓘ C2PA credentials present',
  };
  function detail(r) {
    const m = r.manifest;
    switch (r.status) {
      case 'verified': return `<h4>Verified source</h4>Signed by <b>${esc(r.issuerName)}</b>, a key on your trust list. The pixels haven't changed since signing.<br><span class="k">Title:</span> ${esc(m.title)}<br><span class="k">Signed:</span> ${esc(new Date(m.created).toLocaleString())}<br><span class="k">Action:</span> ${esc(m.actions?.[0]?.action)}`;
      case 'recovered': return `<h4>Provenance recovered</h4>This copy has no metadata (platforms usually strip it), but it visually matches an original signed by <b>${esc(r.match.issuerName)}</b> (${64 - r.distance}/64 fingerprint bits).<br><span class="k">Original title:</span> ${esc(r.match.title)}<br><b>Compare it yourself:</b> <a href="${esc(r.match.url)}" target="_blank" rel="noopener">view the signed original</a>. A fingerprint match is strong evidence, not proof.`;
      case 'untrusted': return `<h4>Signed by an unknown key</h4>The signature is valid, but the key (<b>${esc(m.issuer?.name)}</b>, self-declared) isn't on your trust list. Anyone can sign their own content, so treat this like an unsigned image.`;
      case 'altered': return `<h4>Altered after signing</h4>This image carries a valid manifest from <b>${esc(r.issuerName || m.issuer?.name)}</b>, but its pixels no longer match the signed hash. Someone edited the image and kept the original credentials.<br><span class="k">Claimed title:</span> ${esc(m.title)}`;
      case 'forged': return '<h4>Forged provenance</h4>This image claims to have a signature, but the signature doesn\'t verify. Someone may be impersonating a publisher.';
      case 'c2pa': return '<h4>Content Credentials (C2PA)</h4>This file has a C2PA manifest. Check it with a full C2PA validator such as <a href="https://contentcredentials.org/verify" target="_blank" rel="noopener">contentcredentials.org/verify</a>.';
      default: return '';
    }
  }
  const badges = new Map(); // img -> {el, result}
  const seen = new WeakSet();
  let openPop = null;

  function place() {
    for (const [img, b] of badges) {
      if (!img.isConnected) { b.el.remove(); badges.delete(img); continue; }
      const r = img.getBoundingClientRect();
      b.el.style.display = r.width < 40 ? 'none' : 'flex';
      b.el.style.left = `${r.left + scrollX + 8}px`;
      b.el.style.top = `${r.top + scrollY + 8}px`;
    }
    if (openPop) {
      const r = openPop.anchor.getBoundingClientRect();
      openPop.el.style.left = `${r.left + scrollX}px`;
      openPop.el.style.top = `${r.bottom + scrollY + 6}px`;
    }
  }

  async function scanImages() {
    const fresh = [...document.images].filter((i) => !seen.has(i) && i.complete && i.naturalWidth >= 120 && i.naturalHeight >= 120 && /^(https?:|data:image\/(png|jpeg))/.test(i.currentSrc || i.src) && (i.currentSrc || i.src).length < 3e6);
    if (!fresh.length) return;
    fresh.forEach((i) => seen.add(i));
    let results;
    try { results = await send({ type: 'prov:check', urls: fresh.map((i) => i.currentSrc || i.src) }); } catch { return; }
    results.forEach((r, k) => {
      if (!LABEL[r?.status]) return; // "none" gets no badge: missing provenance is not evidence of fakery
      mount();
      const el = document.createElement('div');
      el.className = 'badge ' + r.status;
      el.textContent = LABEL[r.status](r);
      el.onclick = (ev) => {
        ev.stopPropagation();
        openPop?.el.remove();
        if (openPop?.anchor === el) { openPop = null; return; }
        const pop = document.createElement('div');
        pop.className = 'pop';
        pop.innerHTML = detail(r);
        layer.appendChild(pop);
        openPop = { el: pop, anchor: el };
        place();
      };
      layer.appendChild(el);
      badges.set(fresh[k], { el, result: r });
    });
    place();
  }

  // ---------------- Shield 4: phishing / clone analysis ----------------
  let analysed = false;
  function pageFacts() {
    const pwForms = [...document.querySelectorAll('input[type=password]')].map((i) => i.form).filter(Boolean);
    const formHosts = pwForms.map((f) => { try { return new URL(f.getAttribute('action') || location.href, location.href).hostname; } catch { return ''; } });
    return {
      title: document.title,
      text: (document.body?.innerText || '').slice(0, 4000),
      html: document.documentElement.outerHTML.slice(0, 400000),
      hasPassword: !!document.querySelector('input[type=password]'),
      formHosts,
    };
  }

  async function analyse() {
    analysed = true;
    let v;
    try { v = await send({ type: 'wot:analyze', page: pageFacts() }); } catch { return; }
    if (!v) return;
    const dismissed = sessionStorage.getItem('emcon-proceed') === v.domain;
    if (v.level === 'danger' && !dismissed) showWall(v);
    else if (v.level === 'caution' && !dismissed) showBar(v);
  }

  function showWall(v) {
    mount();
    const wall = document.createElement('div');
    wall.className = 'wall';
    wall.innerHTML = `<div class="box">
      <h1>🛡️ EMCON blocked this page</h1>
      <p>This page shows strong signs of being a scam or a phishing clone. <b>Don't enter passwords, card numbers or one-time codes.</b></p>
      <ul>${v.signals.filter((s) => s.pts > 0).map((s) => `<li>${esc(s.text)}</li>`).join('')}</ul>
      <p style="opacity:.8;font-size:13px">Risk ${v.risk}/100 · ${esc(v.domain)} · verdict from deterministic checks and your own web of trust. No AI was used.</p>
      <button class="leave">Get me out of here</button><button class="stay">I understand the risk, continue</button>
    </div>`;
    wall.querySelector('.leave').onclick = () => { history.length > 1 ? history.back() : (location.href = 'about:blank'); };
    wall.querySelector('.stay').onclick = () => { sessionStorage.setItem('emcon-proceed', v.domain); wall.remove(); };
    layer.appendChild(wall);
    // keep keystrokes out of the page while the warning is up
    document.activeElement?.blur?.();
  }

  function showBar(v) {
    mount();
    const bar = document.createElement('div');
    bar.className = 'bar';
    bar.innerHTML = `⚠️ EMCON: be careful on ${esc(v.domain)}. ${esc(v.signals.filter((s) => s.pts > 0).map((s) => s.text).join(' · '))}<button>Dismiss</button>`;
    bar.querySelector('button').onclick = () => { sessionStorage.setItem('emcon-proceed', v.domain); bar.remove(); };
    layer.appendChild(bar);
  }

  // ---------------- wiring ----------------
  let t;
  const schedule = () => { clearTimeout(t); t = setTimeout(() => { scanImages(); if (!analysed) analyse(); }, 600); };
  // Re-analyse if a password field appears later (SPA phishing kits inject the form after load).
  new MutationObserver((muts) => {
    schedule();
    if (analysed && muts.some((m) => [...m.addedNodes].some((n) => n.nodeType === 1 && (n.matches?.('input[type=password]') || n.querySelector?.('input[type=password]'))))) analyse();
  }).observe(document.documentElement, { childList: true, subtree: true });
  document.addEventListener('load', (e) => { if (e.target.tagName === 'IMG') schedule(); }, true);
  addEventListener('scroll', () => requestAnimationFrame(place), { passive: true });
  addEventListener('resize', () => requestAnimationFrame(place));
  document.addEventListener('click', () => { openPop?.el.remove(); openPop = null; });
  schedule();
})();
