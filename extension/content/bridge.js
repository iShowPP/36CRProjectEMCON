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
  // Same design system as the extension pages (pages/pages.css, docs/ui-research.md).
  const ICON = {
    stop: '<path d="M8.3 3h7.4L21 8.3v7.4L15.7 21H8.3L3 15.7V8.3z"/><path d="M9.5 9.5l5 5M14.5 9.5l-5 5"/>',
    alert: '<path d="M12 4 2.8 19.5h18.4z"/><path d="M12 10v4.5"/><path d="M12 17.3v.2"/>',
    help: '<circle cx="12" cy="12" r="9"/><path d="M9.6 9.6a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.5v.6"/><path d="M12 16.9v.2"/>',
    check: '<circle cx="12" cy="12" r="9"/><path d="M8 12.3l2.8 2.8L16 9.6"/>',
    xCircle: '<circle cx="12" cy="12" r="9"/><path d="M9.2 9.2l5.6 5.6M14.8 9.2l-5.6 5.6"/>',
    recover: '<path d="M20 12a8 8 0 1 1-2.4-5.7"/><path d="M20 4.5V9h-4.5"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5"/><path d="M12 7.6v.2"/>',
    back: '<path d="M19 12H5"/><path d="M11 6l-6 6 6 6"/>',
    receipt: '<path d="M6 3h8.5L19 7.5V21H6z"/><path d="M14 3v5h5"/><path d="M9 12.5h6M9 16.5h6"/>',
    shield: '<path d="M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6z"/>',
    x: '<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>',
  };
  const ic = (n, s = 18) => `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON[n]}</svg>`;

  const host = document.createElement('emcon-ui');
  host.style.cssText = 'position:absolute;top:0;left:0;width:0;height:0;z-index:2147483646;';
  const root = host.attachShadow({ mode: 'closed' });
  root.innerHTML = `<style>
    :host { all: initial; }
    .t { --surface:#fff; --surface2:#f8fafc; --border:#e3e8ef; --text:#101828; --text2:#475467; --text3:#667085; --primary:#1d4ed8;
         --safe:#067647; --safeT:#ecfdf3; --caution:#b54708; --cautionT:#fffaeb; --cautionL:#fedf89; --danger:#b42318; --dangerT:#fef3f2; --dangerL:#fecdca; --calm:#1d4ed8; --calmT:#eff4ff;
         --font:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,Roboto,"Noto Sans","Helvetica Neue",Arial,sans-serif;
         --shadow:0 12px 32px rgba(16,24,40,.18), 0 2px 6px rgba(16,24,40,.08); }
    @media (prefers-color-scheme: dark) { .t { --surface:#161b26; --surface2:#1b2130; --border:#262d3d; --text:#f5f5f6; --text2:#cecfd2; --text3:#94969c; --primary:#528bff;
         --safe:#47cd89; --safeT:#053321; --caution:#fdb022; --cautionT:#4e1d09; --cautionL:#93370d; --danger:#f97066; --dangerT:#55160c; --dangerL:#912018; --calm:#84adff; --calmT:#172554; --shadow:0 12px 32px rgba(0,0,0,.55); } }
    * { box-sizing: border-box; }
    svg { display: block; flex: none; }
    button { font: 600 14px/1.2 var(--font); cursor: pointer; border-radius: 10px; }

    /* photo labels: a white pill readable on any image */
    .badge { position: absolute; display: flex; align-items: center; gap: 5px; padding: 4px 10px 4px 7px; background: #fff; color: #101828; border: 1px solid rgba(16,24,40,.12);
             border-radius: 999px; box-shadow: 0 2px 8px rgba(16,24,40,.22); font: 600 12.5px/1.4 var(--font); cursor: pointer; white-space: nowrap; }
    .badge:hover { box-shadow: 0 4px 14px rgba(16,24,40,.3); }
    .badge svg { color: #475467; }
    .badge.verified svg, .badge.recovered svg { color: #067647; } .badge.untrusted svg { color: #b54708; } .badge.c2pa svg { color: #1d4ed8; } .badge.altered svg, .badge.forged svg { color: #b42318; }
    .pop { position: absolute; width: 360px; max-width: calc(100vw - 24px); background: var(--surface); color: var(--text); border: 1px solid var(--border); border-radius: 14px; box-shadow: var(--shadow); padding: 16px 18px; font: 14px/1.55 var(--font); }
    .pop h4 { margin: 8px 0 6px; font: 700 17px/1.3 var(--font); }
    .pop p { margin: 0 0 8px; color: var(--text2); }
    .pop dl { display: grid; grid-template-columns: auto 1fr; gap: 3px 12px; margin: 8px 0 4px; font-size: 13.5px; } .pop dt { color: var(--text3); } .pop dd { margin: 0; overflow-wrap: anywhere; }
    .pop a { color: var(--primary); }
    .pop .acts { display: flex; gap: 8px; margin-top: 12px; }
    .pop button { display: inline-flex; align-items: center; gap: 6px; padding: 8px 12px; border: 1px solid var(--border); background: var(--surface); color: var(--text); font-size: 13.5px; }
    .tagp { display: inline-flex; align-items: center; gap: 4px; padding: 2px 9px 2px 7px; border-radius: 999px; font: 650 12px/1.5 var(--font); background: var(--calmT); color: var(--calm); }
    .tagp.ok { background: var(--safeT); color: var(--safe); } .tagp.warn { background: var(--cautionT); color: var(--caution); } .tagp.bad { background: var(--dangerT); color: var(--danger); }

    /* danger: full page, as familiar as the browser's own red warning */
    .scrim { position: fixed; inset: 0; z-index: 2147483647; overflow: auto; background: #b42318; color: #fff; font: 15px/1.55 var(--font); }
    @media (prefers-color-scheme: dark) { .scrim { background: #7a1a12; } }
    .wi { max-width: 720px; margin: 0 auto; padding: 56px 24px 44px; }
    .wi .stopic { width: 64px; height: 64px; }
    .wi .kick { margin: 18px 0 6px; font-weight: 650; font-size: 15px; color: rgba(255,255,255,.88); }
    .wi h1 { margin: 0 0 10px; font: 750 36px/1.15 var(--font); letter-spacing: -.015em; color: #fff; }
    .wi .lede { margin: 0 0 22px; font-size: 18px; color: rgba(255,255,255,.94); max-width: 40em; }
    .safety { display: inline-flex; align-items: center; gap: 8px; padding: 13px 22px; border: 0; background: #fff; color: #b42318; font-size: 16px; box-shadow: 0 2px 10px rgba(0,0,0,.18); }
    .safety:hover { background: #fef3f2; }
    .brake { margin-top: 22px; padding: 20px 22px; border-radius: 16px; background: rgba(255,255,255,.10); border: 1px solid rgba(255,255,255,.28); }
    .brake h2 { margin: 0 0 4px; font: 700 19px/1.3 var(--font); color: #fff; }
    .brake p { margin: 0; color: rgba(255,255,255,.92); }
    .brake .brow { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 14px; }
    .brake button { padding: 11px 16px; border: 1px solid rgba(255,255,255,.7); background: transparent; color: #fff; font-size: 15px; }
    .brake button.ask { background: #fff; color: #b42318; border-color: #fff; }
    .brake button:disabled { opacity: .6; cursor: default; }
    .brake .bmsg { margin-top: 10px; font-weight: 600; min-height: 1em; }
    .safety:focus-visible, .stay:focus-visible { outline: 3px solid rgba(255,255,255,.75); outline-offset: 3px; }
    .safety:focus:not(:focus-visible) { outline: none; }
    .sheet { margin-top: 28px; background: var(--surface); color: var(--text); border-radius: 16px; padding: 22px 24px 18px; box-shadow: 0 10px 30px rgba(0,0,0,.18); }
    .sheet h2 { margin: 0 0 4px; font: 700 18px/1.3 var(--font); }
    .why { list-style: none; margin: 0; padding: 0; }
    .why li { display: flex; gap: 12px; padding: 12px 0; border-bottom: 1px solid var(--border); }
    .why li:last-child { border-bottom: 0; }
    .why .ri { display: grid; place-items: center; width: 32px; height: 32px; border-radius: 50%; background: var(--dangerT); color: var(--danger); flex: none; }
    .why li.unknown .ri { background: var(--cautionT); color: var(--caution); }
    .why b { display: block; font-weight: 650; } .why span { color: var(--text2); overflow-wrap: anywhere; }
    .steps { list-style: none; margin: 8px 0 0; padding: 0; }
    .steps li { position: relative; padding: 0 0 12px 26px; font-size: 14px; }
    .steps li::before { content: ""; position: absolute; left: 4px; top: 5px; width: 10px; height: 10px; border-radius: 50%; border: 2px solid var(--text3); background: var(--surface); }
    .steps li::after { content: ""; position: absolute; left: 9px; top: 19px; bottom: 0; width: 2px; background: var(--border); }
    .steps li:last-child { padding-bottom: 0; } .steps li:last-child::after { display: none; }
    .steps li.end::before { border-color: var(--danger); background: var(--danger); }
    .steps b { font-weight: 600; overflow-wrap: anywhere; } .steps i { display: block; font-style: normal; font-size: 12.5px; color: var(--text3); }
    .sub { margin: 18px 0 2px; font: 650 13px/1.4 var(--font); color: var(--text2); }
    .foot { margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--border); font-size: 13px; color: var(--text3); }
    .stay { margin-top: 22px; padding: 6px 0; border: 0; background: none; color: rgba(255,255,255,.88); font-weight: 500; font-size: 14px; text-decoration: underline; text-underline-offset: 3px; }

    /* caution: a banner that doesn't block */
    .bar { position: fixed; top: 12px; left: 50%; transform: translateX(-50%); width: min(780px, calc(100vw - 24px)); display: flex; gap: 14px; align-items: flex-start; padding: 14px 16px;
           background: var(--surface); color: var(--text); border: 1px solid var(--cautionL); border-left: 6px solid var(--caution); border-radius: 12px; box-shadow: var(--shadow); font: 14px/1.5 var(--font); z-index: 2147483647; }
    .bar .bi { display: grid; place-items: center; width: 40px; height: 40px; border-radius: 50%; background: var(--cautionT); color: var(--caution); flex: none; }
    .bar .cb-msg { flex: 1; min-width: 0; }
    .bar .cb-title { font: 700 16px/1.35 var(--font); margin-bottom: 2px; }
    .bar .cb-why { color: var(--text2); overflow-wrap: anywhere; } .bar .cb-why b { color: var(--text); font-weight: 600; }
    .bar .cb-do { margin-top: 6px; font-weight: 600; }
    .bar button { padding: 8px 14px; border: 1px solid var(--border); background: var(--surface); color: var(--text); }
  </style><div class="t" id="layer"></div>`;
  const layer = root.getElementById('layer');
  const mount = () => { if (!host.isConnected) document.documentElement.appendChild(host); };

  // ---------------- Provenance badges ----------------
  const LABEL = {
    verified: (r) => `Verified · ${r.issuerName}`,
    recovered: (r) => `Recovered · ${r.match.issuerName}`,
    untrusted: (r) => (r.source === 'c2pa' ? 'Content Credentials · unknown signer' : 'Signed · unknown signer'),
    altered: () => 'Altered after signing',
    forged: () => 'Forged provenance',
    c2pa: (r) => (r.c2pa?.signer ? `Content Credentials · ${r.c2pa.signer}` : 'Content Credentials'),
  };
  const BADGE_ICON = { verified: 'check', recovered: 'recover', untrusted: 'help', altered: 'xCircle', forged: 'xCircle', c2pa: 'info' };
  const TAG = { verified: ['ok', 'Verified'], recovered: ['ok', 'Recovered'], untrusted: ['warn', 'Unknown signer'], altered: ['bad', 'Altered'], forged: ['bad', 'Forged'], c2pa: ['', 'Content Credentials'] };
  const dl = (pairs) => `<dl>${pairs.filter(([, v]) => v).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('')}</dl>`;
  const step = (a) => a.replace(/^c2pa\./, '').replace(/[._]/g, ' ');
  function c2paDetail(r, head) {
    const c = r.c2pa;
    const facts = dl([['Signed by', esc(c.signer)], ['Organisation', esc(c.signerOrg !== c.signer ? c.signerOrg : '')], ['Certificate from', esc(c.issuerOrg || c.issuer)], ['Made with', esc(c.generator)], ['Signed', c.signedAt ? esc(new Date(c.signedAt).toLocaleString()) : ''], ['Steps recorded', esc((c.actions || []).map(step).join(', '))]]);
    switch (r.status) {
      case 'verified': return `${head}<h4>Content Credentials from ${esc(r.issuerName)}</h4><p>The signature is valid, the image is exactly what was signed, and the signer's certificate chains to the official C2PA trust list.</p>${facts}`;
      case 'untrusted': return `${head}<h4>Signed by “${esc(c.signer)}”, not a trusted signer</h4><p>The Content Credentials are intact, but the certificate is not on the C2PA trust list. Anyone can make a certificate with any name, so treat it like an unsigned image.</p>${facts}`;
      case 'altered': return `${head}<h4>Changed after it was signed</h4><p>These Content Credentials are genuine, but the image no longer matches what ${esc(r.issuerName)} signed. Someone edited the file afterwards.</p>${facts}`;
      case 'forged': return `${head}<h4>The Content Credentials don't verify</h4><p>${c.signature !== 'valid' ? 'The signature over the credentials fails.' : 'Part of the credentials was changed after signing.'} Don't trust what they claim.</p>${facts}`;
      default: return `${head}<h4>${esc(c.signer ? `Signed by ${c.signer}` : 'Has Content Credentials')}</h4>${facts}<p style="font-size:13px">EMCON can't check this file's image hash yet. Full check: <a href="https://contentcredentials.org/verify" target="_blank" rel="noopener">contentcredentials.org/verify</a>.</p>`;
    }
  }
  function detail(r) {
    const m = r.manifest;
    const [cls, word] = TAG[r.status] || ['', r.status];
    const head = `<span class="tagp ${cls}">${ic(BADGE_ICON[r.status] || 'info', 13)}${esc(word)}</span>`;
    if (r.source === 'c2pa') return c2paDetail(r, head);
    switch (r.status) {
      case 'verified': return `${head}<h4>Signed by ${esc(r.issuerName)}</h4><p>This photo is exactly as the publisher signed it. Their key is on your trust list.</p>${dl([['Title', esc(m.title)], ['Signed', esc(new Date(m.created).toLocaleString())]])}`;
      case 'recovered': return `${head}<h4>Matches a photo signed by ${esc(r.match.issuerName)}</h4><p>This copy lost its ${r.match.source === 'c2pa' ? 'Content Credentials' : 'label'} (sites usually strip it), but it looks the same as a signed original: ${64 - r.distance}/64 fingerprint points match. Strong evidence, not proof.</p>${dl([['Original', `${esc(r.match.title)} · <a href="${esc(r.match.url)}" target="_blank" rel="noopener">compare</a>`]])}`;
      case 'untrusted': return `${head}<h4>Signed by “${esc(m.issuer?.name)}”, who you don't follow</h4><p>The signature is valid, but anyone can sign their own photos. Treat it like an unsigned image.</p>`;
      case 'altered': return `${head}<h4>Changed after it was signed</h4><p>This file carries a real label from ${esc(r.issuerName || m.issuer?.name)}, but its pixels no longer match what was signed. Someone edited it.</p>${dl([['Claimed title', esc(m.title)]])}`;
      case 'forged': return `${head}<h4>The publisher signature is fake</h4><p>The file claims a publisher signature that fails verification. Someone may be impersonating a publisher.</p>`;
      case 'c2pa': {
        const c = r.c2pa || {};
        return `${head}<h4>${esc(c.signer ? `Signed by ${c.signer}` : 'Has Content Credentials')}</h4>${dl([['Certificate from', esc(c.issuer)], ['Made with', esc(c.generator)], ['Title', esc(c.title)], ['Timestamp by', esc(c.timestampAuthority)]])}<p style="font-size:13px">EMCON reads these details but doesn't validate the certificate chain. Full check: <a href="https://contentcredentials.org/verify" target="_blank" rel="noopener">contentcredentials.org/verify</a>.</p>`;
      }
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
      openPop.el.style.left = `${Math.min(r.left, innerWidth - 384) + scrollX}px`;
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
      el.innerHTML = `${ic(BADGE_ICON[r.status], 15)}<span>${esc(LABEL[r.status](r))}</span>`;
      el.title = 'EMCON: click for details';
      el.onclick = (ev) => {
        ev.stopPropagation();
        openPop?.el.remove();
        if (openPop?.anchor === el) { openPop = null; return; }
        const pop = document.createElement('div');
        pop.className = 'pop';
        const canRemember = r.source === 'c2pa' && r.status === 'verified';
        pop.innerHTML = detail(r) + `<div class="acts"><button class="receipt">${ic('receipt', 16)}Save signed proof</button>${canRemember ? `<button class="remember">${ic('recover', 16)}Recognise copies</button>` : ''}</div><p class="rmsg" style="font-size:13px;margin:8px 0 0"></p>`;
        pop.querySelector('.receipt').onclick = (e2) => { e2.stopPropagation(); send({ type: 'receipt:open', image: src }).catch(() => {}); };
        const rem = pop.querySelector('.remember');
        if (rem) {
          rem.onclick = async (e2) => {
            e2.stopPropagation();
            rem.disabled = true;
            const msg = pop.querySelector('.rmsg');
            msg.textContent = 'Checking the photo on the EMCON server…';
            try {
              await send({ type: 'prov:remember', url: src });
              msg.textContent = 'Saved. Copies of this photo with the credentials stripped now show “Recovered” for everyone using EMCON.';
            } catch (err) { msg.textContent = String(err.message || err); rem.disabled = false; }
          };
        }
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

  const CARD = new Set(['card number', 'CVV', 'card expiry']);
  const LOAD_ID = Math.random().toString(36).slice(2) + Date.now().toString(36); // this page load: the checkout alarm learns for the whole first visit
  // Card fields hosted by a payment provider in an iframe (Stripe, Braintree, Adyen, Shopify…):
  // the page around them is still where a skimmer injects its script or a fake card form.
  const PAY_FRAME = /(^|\.)(stripe\.com|braintreegateway\.com|adyen\.com|razorpay\.com|checkout\.com|squarecdn\.com|shopifyinc\.com|juspay\.in|cashfree\.com|payu\.in)$/;
  const paymentFrames = () => [...document.querySelectorAll('iframe[src]')].some((f) => {
    try { const u = new URL(f.src, location.href); return PAY_FRAME.test(u.hostname) && /card|field|element|secure|hosted|checkout/i.test(u.pathname + ' ' + f.name + ' ' + f.title); } catch { return false; }
  });
  function pageFacts() {
    const fields = sensitiveFields();
    const isPayment = fields.some((f) => CARD.has(f)) || paymentFrames();
    const pwForms = [...document.querySelectorAll('input[type=password]')].map((i) => i.form).filter(Boolean);
    const formHosts = pwForms.map((f) => { try { return new URL(f.getAttribute('action') || location.href, location.href).hostname; } catch { return ''; } });
    const promise = document.querySelector('meta[name="privacy-promise"]')?.content || '';
    return {
      title: document.title,
      text: (document.body?.innerText || '').slice(0, 4000),
      html: document.documentElement.outerHTML.slice(0, 400000),
      hasPassword: !!document.querySelector('input[type=password]'),
      formHosts,
      fields,
      payment: isPayment,
      loadId: LOAD_ID,
      scripts: isPayment ? [...document.scripts].map((s) => s.src).filter(Boolean).slice(0, 80) : null,
      privacyPromise: promise ? promise.toLowerCase().split(/[\s,]+/).filter((t) => /^[a-z-]{3,40}$/.test(t)).slice(0, 10) : null,
    };
  }

  // ---------------- Warnings ----------------
  let analysed = false;
  let shown = null;
  const ORDER = { found: 0, unknown: 1, good: 2, note: 3, clear: 4, na: 5 };
  const VIA = { typed: 'You opened it', link: 'You followed a link', redirect: 'Redirected automatically', 'page redirect': 'The page sent you on', form: 'After a form was sent', reload: 'Reloaded', 'new tab': 'Opened in a new tab', message: 'From the message you pasted' };
  const reasonsHtml = (checks) => checks.map((c) => `<li class="${c.status}"><span class="ri">${ic(c.status === 'unknown' ? 'help' : 'alert', 16)}</span><div><b>${esc(c.label)}</b><span>${esc(c.detail)}</span></div></li>`).join('');
  const stepsHtml = (v) => (v.chain?.length > 1 ? `<div class="sub">How you got here</div><ol class="steps">${v.chain.map((h, i) => `<li class="${i === v.chain.length - 1 ? 'end' : ''}"><b>${esc(h.label || h.host)}</b><i>${esc(i === 0 ? VIA[h.via] || 'Start' : VIA[h.via] || h.via)}${i === v.chain.length - 1 ? ' · this page' : ''}</i></li>`).join('')}</ol>` : '');

  async function analyse() {
    analysed = true;
    let v;
    try { v = await send({ type: 'wot:analyze', page: pageFacts() }); } catch { return; }
    show(v);
  }

  let lastVerdict = null;
  function show(v) {
    if (!v) return;
    lastVerdict = v;
    // the script alarm must reach you before card entry, even if you dismissed an earlier warning
    if (v.level !== 'danger' && v.checks?.some((c) => c.id === 'scripts' && c.status === 'found')) { showBar(v); return; }
    const dismissed = sessionStorage.getItem('emcon-proceed') === v.domain;
    if (dismissed || v.level === shown) return;
    if (v.level === 'danger') showWall(v);
    else if (v.level === 'caution') showBar(v);
  }

  function clearWarnings() { layer.querySelectorAll('.scrim, .bar').forEach((n) => n.remove()); }

  const BRAKE_FIELDS = new Set(['card number', 'CVV', 'card expiry', 'one-time code (OTP)', 'PIN', 'bank account']);
  const BRAKE_MS = 5 * 60e3;
  function paymentBrake(wall, v, warn, proceed) {
    const wait = wall.querySelector('.wait'), ask = wall.querySelector('.ask'), msg = wall.querySelector('.bmsg');
    // the 5 minutes survive a reload of the page
    const key = 'emcon-brake-' + v.domain;
    const start = Number(sessionStorage.getItem(key)) || Date.now();
    sessionStorage.setItem(key, String(start));
    let stopped = false;
    const tick = () => {
      if (stopped || !wall.isConnected) return clearInterval(timer);
      const left = Math.max(0, BRAKE_MS - (Date.now() - start));
      if (left > 0) { wait.textContent = `Continue in ${Math.floor(left / 60000)}:${String(Math.floor(left / 1000) % 60).padStart(2, '0')}`; return; }
      clearInterval(timer);
      wait.disabled = false;
      wait.textContent = `Continue to ${v.domain} (unsafe)`;
    };
    const timer = setInterval(tick, 1000);
    tick();
    wait.onclick = () => { if (!wait.disabled) proceed(); };
    send({ type: 'brake:info' }).then((info) => {
      if (!info?.connected) return;
      ask.hidden = false;
      ask.textContent = `Ask ${info.account} to check it`;
      ask.onclick = async () => {
        ask.disabled = true;
        try {
          const r = await send({ type: 'brake:request', domain: v.domain, reasons: warn.slice(0, 5).map((c) => `${c.label}: ${c.detail}`) });
          msg.textContent = `Waiting for ${r.account} to check it on their EMCON dashboard…`;
          const poll = setInterval(async () => {
            if (!wall.isConnected) return clearInterval(poll);
            const s = await send({ type: 'brake:status', id: r.id }).catch(() => null);
            if (s?.status === 'approved') { clearInterval(poll); stopped = true; msg.textContent = `${r.account} checked it and said you can continue.`; wait.disabled = false; wait.textContent = `Continue to ${v.domain}`; }
            else if (s?.status === 'denied') { clearInterval(poll); stopped = true; msg.textContent = `${r.account} says: don't pay on this page.${s.note ? ' “' + s.note + '”' : ''}`; wait.disabled = true; wait.textContent = 'Blocked by your family'; }
          }, 4000);
        } catch (e) { msg.textContent = e.message; ask.disabled = false; }
      };
    }).catch(() => {});
  }

  function showWall(v) {
    mount();
    clearWarnings();
    shown = 'danger';
    const sorted = [...v.checks].sort((a, b) => ORDER[a.status] - ORDER[b.status] || Math.abs(b.pts || 0) - Math.abs(a.pts || 0));
    const warn = sorted.filter((c) => c.status === 'found' || c.status === 'unknown');
    const rest = sorted.length - warn.length;
    // On a page that asks for money details, continuing is slowed down: the payment brake.
    const payment = sensitiveFields().some((f) => BRAKE_FIELDS.has(f));
    const wall = document.createElement('div');
    wall.className = 'scrim wall';
    wall.setAttribute('role', 'alertdialog');
    wall.setAttribute('aria-label', 'EMCON blocked this page');
    wall.innerHTML = `<div class="wi">
      <div class="stopic">${ic('stop', 64)}</div>
      <div class="kick">EMCON blocked this page</div>
      <h1>This page is very likely a scam</h1>
      <p class="lede">Don't enter passwords, card numbers, UPI PIN or one-time codes (OTP) on <b>${esc(v.domain)}</b>.</p>
      <button class="safety leave">${ic('back', 20)}Back to safety</button>
      <div class="sheet">
        <h2>Why EMCON blocked it</h2>
        <ol class="why">${reasonsHtml(warn)}</ol>
        ${stepsHtml(v)}
        <div class="foot">${rest} other check(s) found nothing. Every reason above is a deterministic check or a signed report, no AI guesses. Save signed proof from the EMCON icon in your toolbar.</div>
      </div>
      ${payment ? `<div class="brake">
        <h2>Need to pay here anyway?</h2>
        <p>Scammers rush you. Wait 5 minutes, or ask someone you trust to check this page first.</p>
        <div class="brow"><button class="ask" hidden>Ask a family member to check it</button><button class="wait" disabled>Continue in 5:00</button></div>
        <p class="bmsg" role="status"></p>
      </div>` : `<button class="stay">I understand the risk. Continue to ${esc(v.domain)} (unsafe)</button>`}
    </div>`;
    wall.querySelector('.leave').onclick = () => { history.length > 1 ? history.back() : (location.href = 'about:blank'); };
    const proceed = () => { sessionStorage.setItem('emcon-proceed', v.domain); wall.remove(); };
    if (!payment) wall.querySelector('.stay').onclick = proceed;
    else paymentBrake(wall, v, warn, proceed);
    layer.appendChild(wall);
    document.activeElement?.blur?.(); // keep keystrokes out of the page while the warning is up
    wall.querySelector('.leave').focus();
  }

  function showBar(v) {
    mount();
    clearWarnings();
    shown = 'caution';
    const found = v.checks.filter((c) => c.status === 'found');
    const scriptAlarm = found.some((c) => c.id === 'scripts');
    const bar = document.createElement('div');
    bar.className = 'bar';
    bar.setAttribute('role', 'alert');
    bar.innerHTML = `<span class="bi">${ic('alert', 22)}</span>
      <div class="cb-msg"><div class="cb-title">Be careful on ${esc(v.domain)}</div>
        <div class="cb-why">${found.map((c) => `<b>${esc(c.label)}:</b> ${esc(c.detail)}`).join('<br>')}</div>
        <div class="cb-do">${scriptAlarm ? "Don't type card details here until you're sure this change is legitimate." : "Don't sign in or pay here unless you're sure this is the real site."}</div></div>
      ${scriptAlarm ? '<button class="trust" title="Only if you know why this script was added">Trust this change</button>' : ''}<button class="got">Got it</button>`;
    bar.querySelector('.got').onclick = () => { sessionStorage.setItem('emcon-proceed', v.domain); bar.remove(); };
    const trust = bar.querySelector('.trust');
    if (trust) trust.onclick = () => { send({ type: 'checkout:accept', url: location.href }).catch(() => {}); bar.remove(); };
    layer.appendChild(bar);
  }

  // Clicking into a card field brings the script alarm back if it was dismissed.
  document.addEventListener('focusin', (e) => {
    const el = e.target;
    if (!lastVerdict || layer.querySelector('.bar, .scrim') || !el?.matches?.('input')) return;
    const t = [el.name, el.id, el.placeholder, el.autocomplete, el.getAttribute('aria-label')].filter(Boolean).join(' ').toLowerCase();
    if (!/^cc-|card|cvv|cvc|expir/.test(t)) return;
    if (lastVerdict.checks?.some((c) => c.id === 'scripts' && c.status === 'found')) showBar(lastVerdict);
  }, true);

  // The popup can re-run the analysis (e.g. after you paste the message that sent you here).
  chrome.runtime.onMessage.addListener((m) => { if (m?.type === 'emcon:verdict') show(m.verdict); });

  // ---------------- wiring ----------------
  let t, firstAt = 0;
  const run = () => { firstAt = 0; scanImages(); if (!analysed) analyse(); };
  // Wait for a burst of DOM changes to settle, but never more than 2 s: video players and
  // live tickers change the page constantly and would otherwise postpone checks forever.
  const schedule = () => {
    clearTimeout(t);
    firstAt ||= Date.now();
    t = setTimeout(run, Date.now() - firstAt > 2000 ? 0 : 600);
  };
  // Re-analyse when a password/payment field appears later (SPA phishing kits inject the form after load).
  new MutationObserver((muts) => {
    schedule();
    // a skimmer is usually injected after load: re-check when a form field or a script appears
    if (analysed && muts.some((m) => [...m.addedNodes].some((n) => n.nodeType === 1 && (n.matches?.('input, form, script[src]') || n.querySelector?.('input'))))) {
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
