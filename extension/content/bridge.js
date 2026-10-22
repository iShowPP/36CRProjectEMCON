// EMCON content script: collects page facts, relays privacy observations, renders
// badges and warnings, and relays Ghost sign-in requests. Holds no secrets; every
// decision happens in the service worker. Runs in every frame; the UI only in the top one.
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

  // ---------------- Privacy monitor relay (every frame) ----------------
  const counts = {};
  let featTimer;
  const flushFeatures = () => { clearTimeout(featTimer); featTimer = setTimeout(() => send({ type: 'privacy:features', counts }).catch(() => {}), 400); };
  const take = (obj) => { for (const [f, n] of Object.entries(obj)) counts[f] = Math.max(counts[f] || 0, Number(n) || 0); flushFeatures(); };
  document.addEventListener('emcon:feature', (e) => { try { const { f, n } = JSON.parse(e.detail); take({ [f]: n }); } catch { /* ignore */ } });
  document.addEventListener('emcon:feature-snapshot', (e) => { try { take(JSON.parse(e.detail)); } catch { /* ignore */ } });
  document.dispatchEvent(new CustomEvent('emcon:feature-dump')); // totals from before this script loaded

  // Consent decisions: the user clicking a cookie banner's reject/accept button.
  const DENY = /^(reject( all)?|decline( all)?|deny( all)?|refuse( all)?|disagree|only (necessary|essential)( cookies)?|(use )?necessary (cookies )?only|continue without accepting|reject and close|do not (sell|share)( my (personal )?(info|information|data))?)$/i;
  const ACCEPT = /^(accept( all)?( cookies)?|allow( all)?( cookies)?|agree|i agree|i accept|got it|agree and close)$/i;
  document.addEventListener('click', (e) => {
    const el = e.target?.closest?.('button, a, [role="button"], input[type="button"], input[type="submit"]');
    if (!el) return;
    const text = (el.innerText || el.value || el.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim();
    if (!text || text.length > 60) return;
    const state = DENY.test(text) ? 'denied' : ACCEPT.test(text) ? 'granted' : null;
    if (state) send({ type: 'privacy:consent', state, how: `you clicked “${text}”` }).catch(() => {});
  }, true);

  if (!isTop) return;

  // ---------------- UI host (closed shadow root: the page can't restyle or read it) ----------------
  const host = document.createElement('emcon-ui');
  host.style.cssText = 'position:absolute;top:0;left:0;width:0;height:0;z-index:2147483646;';
  const root = host.attachShadow({ mode: 'closed' });
  root.innerHTML = `<style>
    :host { all: initial; }
    .t { --paper:#f5f2eb; --sheet:#fffdf8; --ink:#17171a; --ink2:#46423b; --muted:#77716a; --rule:#ddd6c8;
         --ok:#1f6f43; --warn:#946200; --bad:#b42318; --unk:#6b6b6b;
         --serif:"Iowan Old Style","Palatino Linotype",Palatino,"Book Antiqua",Georgia,serif;
         --sans:"Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",Arial,sans-serif;
         --mono:ui-monospace,"Cascadia Mono","SF Mono",Consolas,"Liberation Mono",monospace; }
    @media (prefers-color-scheme: dark) { .t { --paper:#151514; --sheet:#1c1c1a; --ink:#ece6d9; --ink2:#cbc4b5; --muted:#938c80; --rule:#34312c; --ok:#6cc292; --warn:#e2a93f; --bad:#f2786f; --unk:#9a9a9a; } }
    * { box-sizing: border-box; }
    .badge { position: absolute; display: flex; align-items: center; gap: 6px; padding: 3px 8px 3px 7px; background: #17171a; color: #f5f2eb;
             font: 600 10.5px/1.5 var(--mono); letter-spacing: .04em; text-transform: uppercase; border-left: 3px solid var(--unk); border-radius: 2px; cursor: pointer; white-space: nowrap; }
    .badge.verified, .badge.recovered { border-left-color: #3fa36b; } .badge.untrusted, .badge.c2pa { border-left-color: #d29a2a; } .badge.altered, .badge.forged { border-left-color: #e5534b; }
    .pop { position: absolute; width: 340px; background: var(--sheet); color: var(--ink); border: 1px solid var(--rule); border-top: 3px solid var(--ink); padding: 14px 16px; font: 13px/1.5 var(--sans); }
    .pop h4 { margin: 0 0 6px; font: 600 16px/1.3 var(--serif); }
    .pop .k { color: var(--muted); } .pop a { color: inherit; }
    .pop button { margin-top: 10px; }
    .kicker { font: 600 10.5px/1.4 var(--mono); letter-spacing: .1em; text-transform: uppercase; color: var(--muted); }
    .scrim { position: fixed; inset: 0; background: rgba(12,12,12,.78); display: grid; place-items: center; padding: 16px; z-index: 2147483647; overflow: auto; }
    .sheet { width: 100%; max-width: 640px; background: var(--sheet); color: var(--ink); border-top: 6px solid var(--bad); padding: 26px 28px 22px; font: 14px/1.55 var(--sans); }
    .sheet h1 { font: 600 28px/1.15 var(--serif); margin: 6px 0 8px; letter-spacing: -.01em; }
    .sheet .lede { margin: 0 0 14px; color: var(--ink2); }
    .rows { list-style: none; margin: 0; padding: 0; border-top: 1px solid var(--rule); }
    .row { display: grid; grid-template-columns: 78px 1fr; gap: 12px; padding: 9px 0; border-bottom: 1px solid var(--rule); }
    .tag { font: 600 10px/1.9 var(--mono); letter-spacing: .08em; text-transform: uppercase; color: var(--unk); }
    .row.found .tag { color: var(--bad); } .row.good .tag { color: var(--ok); } .row.unknown .tag { color: var(--warn); }
    .row b { display: block; font-weight: 600; } .row span { color: var(--ink2); }
    .chain { margin: 14px 0 0; padding: 10px 12px; background: var(--paper); font: 12px/1.6 var(--mono); color: var(--ink2); overflow-wrap: anywhere; }
    .chain i { font-style: normal; color: var(--muted); }
    .foot { margin-top: 12px; font: 11px/1.5 var(--mono); color: var(--muted); }
    .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 16px; }
    button { font: 600 13px var(--sans); padding: 9px 14px; border-radius: 3px; cursor: pointer; border: 1px solid var(--ink); background: transparent; color: var(--ink); }
    button.primary { background: var(--ink); color: var(--sheet); }
    .bar { position: fixed; top: 0; left: 0; right: 0; display: flex; gap: 14px; align-items: flex-start; padding: 10px 16px; background: var(--sheet); color: var(--ink);
           border-bottom: 1px solid var(--rule); border-left: 6px solid var(--warn); font: 13px/1.5 var(--sans); z-index: 2147483647; }
    .bar .msg { flex: 1; } .bar b { font-weight: 600; } .bar button { padding: 5px 10px; }
  </style><div class="t" id="layer"></div>`;
  const layer = root.getElementById('layer');
  const mount = () => { if (!host.isConnected) document.documentElement.appendChild(host); };

  // ---------------- Provenance badges ----------------
  const LABEL = {
    verified: (r) => `Verified · ${r.issuerName}`,
    recovered: (r) => `Recovered · ${r.match.issuerName}`,
    untrusted: () => 'Signed · unknown signer',
    altered: () => 'Altered after signing',
    forged: () => 'Forged provenance',
    c2pa: () => 'C2PA credentials',
  };
  function detail(r) {
    const m = r.manifest;
    switch (r.status) {
      case 'verified': return `<div class="kicker">Verified source</div><h4>Signed by ${esc(r.issuerName)}</h4>The signing key is on your trust list and the pixels haven't changed since signing.<br><span class="k">Title</span> ${esc(m.title)}<br><span class="k">Signed</span> ${esc(new Date(m.created).toLocaleString())}`;
      case 'recovered': return `<div class="kicker">Provenance recovered</div><h4>Matches an original by ${esc(r.match.issuerName)}</h4>This copy has no metadata (platforms usually strip it), but it visually matches a signed original (${64 - r.distance}/64 fingerprint bits).<br><span class="k">Original</span> ${esc(r.match.title)}. <a href="${esc(r.match.url)}" target="_blank" rel="noopener">Compare with the signed original</a>. A visual match is strong evidence, not proof.`;
      case 'untrusted': return `<div class="kicker">Signed, unknown signer</div><h4>${esc(m.issuer?.name)} (self-declared)</h4>The signature is valid, but the key isn't on your trust list. Anyone can sign their own content, so treat this like an unsigned image.`;
      case 'altered': return `<div class="kicker">Altered after signing</div><h4>Edited copy of a signed image</h4>The file carries a valid label from ${esc(r.issuerName || m.issuer?.name)}, but its pixels no longer match the signed hash.<br><span class="k">Claimed title</span> ${esc(m.title)}`;
      case 'forged': return '<div class="kicker">Forged provenance</div><h4>The signature does not verify</h4>The file claims a publisher signature that fails verification. Someone may be impersonating a publisher.';
      case 'c2pa': return '<div class="kicker">Content Credentials</div><h4>C2PA manifest present</h4>Check it with a full validator such as <a href="https://contentcredentials.org/verify" target="_blank" rel="noopener">contentcredentials.org/verify</a>.';
      default: return '';
    }
  }
  const badges = new Map();
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
      const src = fresh[k].currentSrc || fresh[k].src;
      const el = document.createElement('div');
      el.className = 'badge ' + r.status;
      el.textContent = LABEL[r.status](r);
      el.onclick = (ev) => {
        ev.stopPropagation();
        openPop?.el.remove();
        if (openPop?.anchor === el) { openPop = null; return; }
        const pop = document.createElement('div');
        pop.className = 'pop';
        pop.innerHTML = detail(r) + '<div><button class="receipt">Export evidence receipt</button></div>';
        pop.querySelector('.receipt').onclick = (e2) => { e2.stopPropagation(); send({ type: 'receipt:open', image: src }).catch(() => {}); };
        pop.onclick = (e2) => e2.stopPropagation();
        layer.appendChild(pop);
        openPop = { el: pop, anchor: el };
        place();
      };
      layer.appendChild(el);
      badges.set(fresh[k], { el, result: r });
    });
    place();
  }

  // ---------------- Page facts for the site analysis ----------------
  const FIELD_KINDS = [
    ['password', (el, t) => el.type === 'password' && !/\bpin\b|mpin/.test(t)],
    ['card number', (el, t) => el.autocomplete === 'cc-number' || /card.?(num|no\b)|cc.?num|credit.?card|debit.?card/.test(t)],
    ['CVV', (el, t) => el.autocomplete === 'cc-csc' || /\bcvv|\bcvc|security code|\bcsc\b/.test(t)],
    ['card expiry', (el, t) => /^cc-exp/.test(el.autocomplete) || /expir|exp.?date|mm\s*\/\s*yy/.test(t)],
    ['one-time code (OTP)', (el, t) => el.autocomplete === 'one-time-code' || /\botp\b|one.?time|verification code/.test(t)],
    ['PIN', (el, t) => /\bpin\b|mpin|upi.?pin|atm.?pin/.test(t)],
    ['ID number (Aadhaar / PAN / SSN)', (el, t) => /aadh?aar|\bpan\b|pan.?card|\bssn\b|social security|passport/.test(t)],
    ['bank account', (el, t) => /account.?(no\b|num)|ifsc|iban|routing/.test(t)],
    ['date of birth', (el, t) => el.autocomplete === 'bday' || /date of birth|\bdob\b|birth.?date/.test(t)],
    ['phone number', (el, t) => el.type === 'tel' || /phone|mobile/.test(t)],
  ];
  function sensitiveFields() {
    const found = new Set();
    for (const el of document.querySelectorAll('input, select, textarea')) {
      if (el.type === 'hidden' || el.disabled || !el.getClientRects().length) continue;
      const label = el.id ? document.querySelector(`label[for="${CSS.escape(el.id)}"]`)?.innerText : el.closest('label')?.innerText;
      const t = [el.name, el.id, el.placeholder, el.getAttribute('aria-label'), el.autocomplete, label].filter(Boolean).join(' ').toLowerCase();
      for (const [kind, test] of FIELD_KINDS) if (test(el, t)) { found.add(kind); break; }
    }
    return [...found];
  }

  function pageFacts() {
    const pwForms = [...document.querySelectorAll('input[type=password]')].map((i) => i.form).filter(Boolean);
    const formHosts = pwForms.map((f) => { try { return new URL(f.getAttribute('action') || location.href, location.href).hostname; } catch { return ''; } });
    const promise = document.querySelector('meta[name="privacy-promise"]')?.content || '';
    return {
      title: document.title,
      text: (document.body?.innerText || '').slice(0, 4000),
      html: document.documentElement.outerHTML.slice(0, 400000),
      hasPassword: !!document.querySelector('input[type=password]'),
      formHosts,
      fields: sensitiveFields(),
      privacyPromise: promise ? promise.toLowerCase().split(/[\s,]+/).filter((t) => /^[a-z-]{3,40}$/.test(t)).slice(0, 10) : null,
    };
  }

  // ---------------- Warnings ----------------
  let analysed = false;
  let shown = null;
  const ORDER = { found: 0, unknown: 1, good: 2, note: 3, clear: 4, na: 5 };
  const STATUS = { found: 'Found', unknown: 'Unknown', good: 'Good', note: 'Note', clear: 'Clear', na: 'N/A' };
  const rowsHtml = (checks) => checks.map((c) => `<li class="row ${c.status}"><div class="tag">${STATUS[c.status] || c.status}</div><div><b>${esc(c.label)}</b><span>${esc(c.detail)}</span></div></li>`).join('');
  const chainHtml = (v) => (v.chain?.length > 1 ? `<div class="chain"><span class="kicker">How you got here</span><br>${v.chain.map((h, i) => `${i ? ` <i>→ ${esc(h.via)} →</i> ` : ''}${esc(h.label || h.host)}`).join('')}</div>` : '');

  async function analyse() {
    analysed = true;
    let v;
    try { v = await send({ type: 'wot:analyze', page: pageFacts() }); } catch { return; }
    show(v);
  }

  function show(v) {
    if (!v) return;
    const dismissed = sessionStorage.getItem('emcon-proceed') === v.domain;
    if (dismissed || v.level === shown) return;
    if (v.level === 'danger') showWall(v);
    else if (v.level === 'caution') showBar(v);
  }

  function clearWarnings() { layer.querySelectorAll('.scrim, .bar').forEach((n) => n.remove()); }

  function showWall(v) {
    mount();
    clearWarnings();
    shown = 'danger';
    const sorted = [...v.checks].sort((a, b) => ORDER[a.status] - ORDER[b.status]);
    const warn = sorted.filter((c) => c.status === 'found' || c.status === 'unknown');
    const rest = sorted.length - warn.length;
    const wall = document.createElement('div');
    wall.className = 'scrim wall';
    wall.innerHTML = `<div class="sheet">
      <div class="kicker">EMCON blocked this page · risk ${v.risk}/100</div>
      <h1>This page is very likely a scam.</h1>
      <p class="lede">Don't enter passwords, card numbers or one-time codes on <b>${esc(v.domain)}</b>. This is the evidence EMCON found:</p>
      <ol class="rows">${rowsHtml(warn)}</ol>
      ${chainHtml(v)}
      <div class="foot">${rest} other check(s) found nothing. Every row comes from a deterministic check or a signed report. No AI involved. Export a signed receipt from the EMCON toolbar icon.</div>
      <div class="actions"><button class="primary leave">Leave this page</button><button class="stay">I understand the risk, continue</button></div>
    </div>`;
    wall.querySelector('.leave').onclick = () => { history.length > 1 ? history.back() : (location.href = 'about:blank'); };
    wall.querySelector('.stay').onclick = () => { sessionStorage.setItem('emcon-proceed', v.domain); wall.remove(); };
    layer.appendChild(wall);
    document.activeElement?.blur?.(); // keep keystrokes out of the page while the warning is up
  }

  function showBar(v) {
    mount();
    clearWarnings();
    shown = 'caution';
    const found = v.checks.filter((c) => c.status === 'found');
    const bar = document.createElement('div');
    bar.className = 'bar';
    bar.innerHTML = `<div class="msg"><span class="kicker">EMCON · be careful on ${esc(v.domain)} · risk ${v.risk}/100</span><br>${found.map((c) => `<b>${esc(c.label)}:</b> ${esc(c.detail)}`).join(' · ')}</div><button>Dismiss</button>`;
    bar.querySelector('button').onclick = () => { sessionStorage.setItem('emcon-proceed', v.domain); bar.remove(); };
    layer.appendChild(bar);
  }

  // The popup can re-run the analysis (e.g. after you paste the message that sent you here).
  chrome.runtime.onMessage.addListener((m) => { if (m?.type === 'emcon:verdict') show(m.verdict); });

  // ---------------- wiring ----------------
  let t;
  const schedule = () => { clearTimeout(t); t = setTimeout(() => { scanImages(); if (!analysed) analyse(); }, 600); };
  // Re-analyse when a password/payment field appears later (SPA phishing kits inject the form after load).
  new MutationObserver((muts) => {
    schedule();
    if (analysed && muts.some((m) => [...m.addedNodes].some((n) => n.nodeType === 1 && (n.matches?.('input, form') || n.querySelector?.('input'))))) {
      clearTimeout(analyse.t);
      analyse.t = setTimeout(analyse, 800);
    }
  }).observe(document.documentElement, { childList: true, subtree: true });
  document.addEventListener('load', (e) => { if (e.target.tagName === 'IMG') schedule(); }, true);
  addEventListener('scroll', () => requestAnimationFrame(place), { passive: true });
  addEventListener('resize', () => requestAnimationFrame(place));
  document.addEventListener('click', () => { openPop?.el.remove(); openPop = null; });
  schedule();
})();
