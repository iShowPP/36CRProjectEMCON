// EMCON service worker: owns all secrets and does every security decision.
// Content scripts only collect page facts and render UI; they never see keys.

import { toHex, fromHex, toB64u, randomBytes, sha256, hmacSha256, ed25519FromSeed, ed25519Sign, didKeyFromPub, pubFromDidKey, hamming } from './lib/util.js';
import * as brsa from './lib/blindrsa.js';
import { verifyImageBytes } from './lib/provenance.js';
import { dhash } from './lib/dhash.js';
import { domTokens, simhash64 } from './lib/simhash.js';
import { computeTrust, scoreDomain } from './lib/trustgraph.js';
import { signCredential, verifyCredential, VC_CONTEXT } from './lib/vc.js';
import { farble } from './lib/farble.js';

const DEFAULTS = { server: 'http://localhost:8787', farble: true, farbleExceptions: [], provenance: true, provRecovery: true, wot: true };
const local = {
  get: async (k) => (await chrome.storage.local.get(k))[k],
  set: (k, v) => chrome.storage.local.set({ [k]: v }),
};
const settings = async () => ({ ...DEFAULTS, ...(await local.get('settings')) });

async function api(path, { method = 'GET', body } = {}) {
  const { server } = await settings();
  const r = await fetch(server + path, { method, headers: { 'content-type': 'application/json' }, body: body && JSON.stringify(body), credentials: 'omit' });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `server error ${r.status}`);
  return j;
}

function cached(ttlMs, fn) {
  let at = 0, val;
  return async () => {
    if (!val || Date.now() - at > ttlMs) { val = fn().catch((e) => { val = null; throw e; }); at = Date.now(); }
    return val;
  };
}

// One random master secret; every other key is derived from it with a label.
let masterP;
function master() {
  return (masterP ||= (async () => {
    let m = await local.get('master');
    if (!m) { m = toHex(randomBytes(32)); await local.set('master', m); }
    return fromHex(m);
  })());
}
const derive = async (label) => hmacSha256(await master(), label);

// =====================================================================
// Shield 1a: Ghost identities (blind tokens + per-site keys)
// =====================================================================
async function ghost() { return (await local.get('ghost')) || null; }

async function siteKey(g, origin) {
  const epoch = g.epochs?.[origin] || 0; // bump to get a brand-new unlinkable identity for that site
  return ed25519FromSeed(await derive(`emcon/ghost/site|${origin}|${epoch}`));
}

async function ghostStatus() {
  const g = await ghost();
  if (!g) return { enrolled: false };
  return {
    enrolled: true,
    unlock: g.credId ? 'passkey' : g.pinHash ? 'pin' : 'none',
    bundles: g.bundles,
    tokens: Object.fromEntries(g.bundles.map((b) => [b, g.tokens[b]?.length || 0])),
    sites: g.sites,
    pinnedKeys: Object.fromEntries(Object.entries(g.pinnedKeys || {}).map(([b, k]) => [b, k.keyId])),
  };
}

const pinHash = async (pin) => toHex(await sha256('emcon-local-pin|' + pin));

async function ghostEnroll({ dob, credId, pin }) {
  if (!credId && !(pin && String(pin).length >= 4)) throw new Error('set up a passkey or a PIN of 4+ digits');
  const { enrollmentId, bundles } = await api('/api/issuer/enroll', { method: 'POST', body: { dob } });
  await local.set('ghost', { enrollmentId, bundles, tokens: {}, sites: {}, epochs: {}, pinnedKeys: {}, credId: credId || null, pinHash: credId ? null : await pinHash(pin) });
  for (const b of bundles) await refill({ bundle: b });
  return ghostStatus();
}

let refilling = Promise.resolve();
function refill({ bundle, count = 5 }) {
  return (refilling = refilling.then(async () => {
    const g = await ghost();
    if (!g) throw new Error('not enrolled');
    const keys = await api('/api/issuer/keys');
    const key = keys[bundle];
    if (!key) throw new Error('issuer has no key for ' + bundle);
    // Key pinning: an issuer that serves *you* a different key than everyone else could tag you.
    const pinned = g.pinnedKeys[bundle];
    if (pinned && pinned.keyId !== key.keyId) throw new Error(`Issuer key for "${bundle}" changed since enrolment. Refusing: this could be a user-tagging attack.`);
    const keyId = toHex(await sha256(fromHex(key.n))).slice(0, 16);
    if (keyId !== key.keyId) throw new Error('issuer keyId does not match its modulus');
    const pub = { n: BigInt('0x' + key.n), e: BigInt('0x' + key.e) };
    const pending = [];
    for (let i = 0; i < count; i++) {
      const t = randomBytes(32);
      pending.push({ t, ...(await brsa.blind(t, pub)) });
    }
    const { signatures } = await api('/api/issuer/issue', { method: 'POST', body: { enrollmentId: g.enrollmentId, bundle, keyId, blinded: pending.map((p) => p.blinded.toString(16)) } });
    const fresh = [];
    for (let i = 0; i < pending.length; i++) {
      const s = brsa.unblind(BigInt('0x' + signatures[i]), pending[i].r, pub.n);
      if (!(await brsa.verify(pending[i].t, s, pub))) throw new Error('issuer returned an invalid signature');
      fresh.push({ t: toHex(pending[i].t), s: s.toString(16), keyId });
    }
    const latest = await ghost();
    latest.pinnedKeys[bundle] = { keyId };
    latest.tokens[bundle] = [...(latest.tokens[bundle] || []), ...fresh];
    await local.set('ghost', latest);
    return ghostStatus();
  }));
}

const approvals = new Map(); // id -> {resolve, origin, claims, windowId, ...}

async function ghostRequest(msg, sender) {
  const origin = sender.origin; // provided by Chrome, cannot be spoofed by the page
  if (!origin || !/^https?:\/\//.test(origin)) throw new Error('Ghost sign-in only works on http(s) pages');
  const claims = [...new Set((msg.claims || []).filter((c) => c === 'human' || c === 'over18'))];
  if (!claims.includes('human')) claims.unshift('human');
  const bundle = claims.includes('over18') ? 'human+18' : 'human'; // data minimisation: weakest bundle that suffices
  const g = await ghost();
  if (!g) throw new Error('EMCON Ghost is not set up yet. Open the EMCON popup → Ghost.');
  if (!g.bundles.includes(bundle)) throw new Error('Your verified profile cannot prove: ' + claims.join(', '));
  const isNewSite = !g.sites[origin] || msg.forceToken;
  if (isNewSite && !g.tokens[bundle]?.length) throw new Error('Out of humanity tokens. Open the popup to refill.');

  const id = toHex(randomBytes(8));
  const ok = await new Promise(async (resolve) => {
    approvals.set(id, { resolve, origin, claims, bundle, isNewSite, unlock: g.credId ? 'passkey' : 'pin', credId: g.credId });
    const w = await chrome.windows.create({ url: chrome.runtime.getURL(`pages/approve.html?id=${id}`), type: 'popup', width: 440, height: 600 });
    approvals.get(id).windowId = w.id;
  });
  approvals.delete(id);
  if (!ok) throw new Error('You declined the sign-in request.');

  const latest = await ghost();
  const { privateKey, pub } = await siteKey(latest, origin);
  let token = null;
  if (isNewSite) {
    token = latest.tokens[bundle].shift(); // single use, never shown to two sites (that would link them)
    if (!token) throw new Error('Out of humanity tokens.');
  }
  const challenge = String(msg.challenge || '').slice(0, 200);
  const sig = await ed25519Sign(privateKey, `EMCON-GHOST-v1|${origin}|${challenge}|${token ? token.t : ''}`);
  latest.sites[origin] = { ...(latest.sites[origin] || { firstSeen: Date.now() }), lastUsed: Date.now(), claims, pseudonym: toB64u(pub).slice(0, 12) };
  await local.set('ghost', latest);
  if ((latest.tokens[bundle]?.length || 0) < 2) refill({ bundle }).catch(() => {});
  return { pseudonym: toB64u(pub), claims, token: token && { t: token.t, s: token.s, keyId: token.keyId }, sig: toB64u(sig) };
}

chrome.windows.onRemoved.addListener((windowId) => {
  for (const a of approvals.values()) if (a.windowId === windowId) a.resolve(false);
});

async function ghostApprove({ id, ok, pin }) {
  const a = approvals.get(id);
  if (!a) throw new Error('request expired');
  if (ok && a.unlock === 'pin') {
    const g = await ghost();
    if ((await pinHash(pin || '')) !== g.pinHash) throw new Error('wrong PIN');
  }
  a.resolve(!!ok);
  return true;
}

async function ghostResetSite({ origin }) {
  const g = await ghost();
  g.epochs[origin] = (g.epochs[origin] || 0) + 1;
  delete g.sites[origin];
  await local.set('ghost', g);
  return ghostStatus();
}

// =====================================================================
// Shield 1b: anti-fingerprinting, injected before page scripts run
// =====================================================================
const topOrigins = new Map();
chrome.webNavigation.onCommitted.addListener(async (d) => {
  if (!/^https?:/.test(d.url)) return;
  const origin = new URL(d.url).origin;
  if (d.frameId === 0) topOrigins.set(d.tabId, origin);
  const st = await settings();
  if (!st.farble) return;
  const top = d.frameId === 0 ? origin : topOrigins.get(d.tabId) || origin;
  if (st.farbleExceptions.includes(new URL(top).hostname)) return;
  // seed differs per (top site, frame origin): a tracker iframe gets a different device on every site
  const seed = toHex(await derive(`emcon/farble|${top}|${origin}`)).slice(0, 16);
  chrome.scripting.executeScript({ target: { tabId: d.tabId, frameIds: [d.frameId] }, world: 'MAIN', injectImmediately: true, func: farble, args: [seed] }).catch(() => {});
});
chrome.tabs.onRemoved.addListener((tabId) => topOrigins.delete(tabId));

// =====================================================================
// Shield 2: media provenance
// =====================================================================
const trustList = cached(10 * 60e3, () => api('/api/prov/trust-list'));
const provCache = new Map();

function provCheck(url) {
  if (provCache.has(url)) return provCache.get(url);
  const p = (async () => {
    const res = await fetch(url, { credentials: 'omit' });
    if (!res.ok) return { status: 'error' };
    if (Number(res.headers.get('content-length')) > 15e6) return { status: 'skipped' };
    const bytes = new Uint8Array(await res.arrayBuffer());
    let trust = [];
    try { trust = await trustList(); } catch { /* offline: signatures still checked, nothing "trusted" */ }
    let result = await verifyImageBytes(bytes, trust);
    if (result.status === 'none' && (await settings()).provRecovery) {
      try {
        const bmp = await createImageBitmap(new Blob([bytes]));
        const h = await dhash(bmp);
        bmp.close();
        const m = await api('/api/prov/lookup?dhash=' + h);
        if (m.match) result = { status: 'recovered', format: result.format, match: { ...m.match, url: new URL(m.match.url, (await settings()).server).href }, distance: m.distance };
      } catch { /* recovery is best-effort */ }
    }
    return result;
  })().catch((e) => ({ status: 'error', error: String(e.message || e) }));
  provCache.set(url, p);
  if (provCache.size > 400) provCache.delete(provCache.keys().next().value);
  return p;
}

// =====================================================================
// Shield 4: Web of Trust + clone detection
// =====================================================================
async function wotIdentity() {
  const { privateKey, pub } = await ed25519FromSeed(await derive('emcon/wot/identity'));
  return { privateKey, did: didKeyFromPub(pub) };
}

async function wotState() {
  const w = (await local.get('wot')) || { roots: [], initialized: false };
  if (!w.initialized) {
    try {
      const groups = await api('/api/wot/groups');
      w.roots = groups.map((g) => ({ did: g.did, weight: g.defaultWeight ?? 0.8, label: g.name, kind: 'group' }));
      w.initialized = true;
      await local.set('wot', w);
    } catch { /* server offline; retry next time */ }
  }
  return w;
}

async function trustMap() {
  const w = await wotState();
  const { did: me } = await wotIdentity();
  const roots = [{ did: me, weight: 1, label: 'You' }, ...w.roots];
  let vouches = [];
  try {
    const res = await api('/api/wot/vouches?issuers=' + encodeURIComponent(roots.map((r) => r.did).join(',')));
    for (const vc of res.vouches) {
      if (await verifyCredential(vc)) vouches.push({ issuer: vc.issuer, subject: vc.credentialSubject.id, weight: vc.credentialSubject.weight });
    }
  } catch { /* offline */ }
  return computeTrust(roots, vouches);
}

const normDomain = (host) => host.toLowerCase().replace(/^www\./, '');

async function domainAttestations(domain) {
  // k-anonymity: only a 5-hex-char hash prefix leaves the browser (~1 in a million buckets)
  const prefix = toHex(await sha256(domain)).slice(0, 5);
  const { attestations } = await api('/api/wot/domain?prefix=' + prefix);
  const out = [];
  for (const vc of attestations) {
    if (vc.credentialSubject?.domain !== domain || !(await verifyCredential(vc))) continue;
    out.push({ issuer: vc.issuer, verdict: vc.credentialSubject.verdict, transacted: vc.credentialSubject.transacted, note: vc.credentialSubject.note, issued: vc.validFrom });
  }
  return out;
}

const TWO_LEVEL = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'co.in', 'net.in', 'co.jp', 'com.br', 'co.nz', 'co.za', 'com.mx', 'com.sg']);
const registrable = (host) => {
  const p = host.split('.');
  if (p.length <= 2) return host;
  return TWO_LEVEL.has(p.slice(-2).join('.')) ? p.slice(-3).join('.') : p.slice(-2).join('.');
};
const isIp = (h) => /^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(':') || h.startsWith('[');
const isLocal = (h) => h === 'localhost' || /\.(localhost|local|test|internal|example)$/.test(h) || isIp(h);

async function domainAgeDays(host) {
  if (isLocal(host)) return null;
  const d = registrable(host);
  const cache = (await local.get('rdap')) || {};
  let created = cache[d]?.created;
  if (!cache[d] || Date.now() - cache[d].at > 7 * 864e5) {
    try {
      const r = await fetch(`https://rdap.org/domain/${d}`, { credentials: 'omit' });
      if (r.ok) {
        const j = await r.json();
        created = (j.events || []).find((e) => e.eventAction === 'registration')?.eventDate || null;
        cache[d] = { created, at: Date.now() };
        await local.set('rdap', cache);
      }
    } catch { return null; }
  }
  return created ? Math.floor((Date.now() - Date.parse(created)) / 864e5) : null;
}

const brandList = cached(10 * 60e3, () => api('/api/wot/brands'));

async function wotAnalyze(page, sender) {
  if (!(await settings()).wot) return null;
  const url = new URL(sender.url);
  const host = url.hostname;
  const domain = normDomain(host);
  const signals = [];
  let risk = 0;
  const add = (pts, kind, text) => { risk += pts; signals.push({ pts, kind, text }); };

  // 1. People and groups you trust
  let s = { pos: 0, neg: 0, ignored: 0, evidence: [] };
  try { s = scoreDomain(await domainAttestations(domain), await trustMap()); } catch { signals.push({ pts: 0, kind: 'wot', text: 'Trust network unreachable' }); }
  if (s.neg > 0) add(Math.round(70 * Math.min(1, s.neg)), 'wot', `Reported as a scam by ${s.evidence.filter((e) => e.verdict === 'scam').length} source(s) in your web of trust`);
  if (s.pos > 0) add(-Math.round(40 * Math.min(1, s.pos)), 'wot', `Vouched for by ${s.evidence.filter((e) => e.verdict === 'trusted').length} source(s) in your web of trust`);
  if (s.ignored) signals.push({ pts: 0, kind: 'wot', text: `${s.ignored} attestation(s) from strangers outside your web of trust were ignored (Sybil protection)` });

  // 2. Domain age (RDAP, public registry data)
  const age = await domainAgeDays(host);
  if (age !== null && age < 30) add(35, 'age', `Domain registered only ${age} day(s) ago`);
  else if (age !== null && age < 180) add(10, 'age', `Domain is young (${age} days)`);

  // 3. Brand clone: structure + brand mention + credential form, never structure alone
  const sh = simhash64(domTokens(page.html || ''));
  const text = `${page.title} ${page.text}`.toLowerCase();
  try {
    for (const b of await brandList()) {
      if (b.domains.some((d) => domain === d || domain.endsWith('.' + d))) continue;
      const dist = hamming(sh, b.simhash);
      const mention = b.keywords.some((k) => text.includes(k));
      if (dist <= 12 && (mention || page.hasPassword)) { add(45, 'clone', `Page layout matches ${b.name}'s real login page (${64 - dist}/64 structural bits), but this site is not ${b.domains[0]}`); break; }
      if (mention && page.hasPassword) { add(20, 'brand', `Asks for a password and mentions ${b.name}, but isn't an official ${b.name} domain`); break; }
    }
  } catch { /* brand list unavailable */ }

  // 4. Credential-form heuristics
  if (page.hasPassword) {
    const foreign = (page.formHosts || []).filter((h) => h && normDomain(h) !== domain);
    if (foreign.length) add(15, 'form', `Password form submits to a different site: ${foreign[0]}`);
    if (isIp(host)) add(15, 'form', 'Login form on a raw IP address');
    if (url.protocol === 'http:' && !isLocal(host)) add(10, 'form', 'Password requested over unencrypted HTTP');
  }

  risk = Math.max(0, Math.min(100, risk));
  const level = risk >= 60 ? 'danger' : risk >= 30 ? 'caution' : s.pos >= 0.5 ? 'trusted' : 'unknown';
  const verdict = { domain, risk, level, signals, evidence: s.evidence, at: Date.now() };
  if (sender.tab?.id != null) {
    await chrome.storage.session.set({ ['verdict_' + sender.tab.id]: verdict });
    const [text, color] = { danger: ['!', '#c62f2f'], caution: ['?', '#b26a00'], trusted: ['✓', '#12805c'], unknown: ['', '#5d6673'] }[level];
    chrome.action.setBadgeText({ tabId: sender.tab.id, text });
    chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color });
  }
  return verdict;
}

async function wotAttest({ domain, verdict, transacted, note }) {
  domain = normDomain(String(domain || ''));
  if (!domain || !['trusted', 'scam'].includes(verdict)) throw new Error('bad attestation');
  const { privateKey, did } = await wotIdentity();
  const vc = await signCredential({
    '@context': VC_CONTEXT,
    type: ['VerifiableCredential', 'EmconDomainAttestation'],
    issuer: did,
    validFrom: new Date().toISOString(),
    credentialSubject: { id: 'dns:' + domain, domain, verdict, transacted: !!transacted, note: String(note || '').slice(0, 200) },
  }, privateKey, did);
  await api('/api/wot/attest', { method: 'POST', body: vc });
  return true;
}

async function wotTrust({ did, weight, label, publish }) {
  pubFromDidKey(did); // throws if malformed
  const me = await wotIdentity();
  if (did === me.did) throw new Error("that's you");
  const w = await wotState();
  w.roots = w.roots.filter((r) => r.did !== did);
  w.roots.push({ did, weight: Math.min(1, Math.max(0.05, Number(weight) || 0.5)), label: String(label || 'Friend').slice(0, 40), kind: 'person' });
  await local.set('wot', w);
  if (publish) {
    const vc = await signCredential({
      '@context': VC_CONTEXT,
      type: ['VerifiableCredential', 'EmconPersonVouch'],
      issuer: me.did,
      validFrom: new Date().toISOString(),
      credentialSubject: { id: did, weight: Math.min(1, Number(weight) || 0.5) },
    }, me.privateKey, me.did);
    await api('/api/wot/vouch', { method: 'POST', body: vc });
  }
  return w.roots;
}

async function wotUntrust({ did }) {
  const w = await wotState();
  w.roots = w.roots.filter((r) => r.did !== did);
  await local.set('wot', w);
  return w.roots;
}

// =====================================================================
// Messaging
// =====================================================================
const HANDLERS = {
  // callable from web pages' content scripts
  'ghost:request': ghostRequest,
  'prov:check': async (m) => ((await settings()).provenance ? Promise.all((m.urls || []).slice(0, 40).map(provCheck)) : []),
  'wot:analyze': (m, sender) => wotAnalyze(m.page, sender),
  // extension pages only
  'ghost:status': ghostStatus,
  'ghost:enroll': ghostEnroll,
  'ghost:refill': refill,
  'ghost:reset-site': ghostResetSite,
  'ghost:approval-info': ({ id }) => { const a = approvals.get(id); if (!a) throw new Error('request expired'); const { resolve, ...info } = a; return info; },
  'ghost:approve': ghostApprove,
  'wot:tab': async ({ tabId }) => (await chrome.storage.session.get('verdict_' + tabId))['verdict_' + tabId] || null,
  'wot:me': async () => ({ did: (await wotIdentity()).did, roots: (await wotState()).roots }),
  'wot:attest': wotAttest,
  'wot:trust': wotTrust,
  'wot:untrust': wotUntrust,
  'settings:get': settings,
  'settings:set': async ({ patch }) => { const s = { ...(await settings()), ...patch }; await local.set('settings', s); return s; },
};
const CONTENT_ALLOWED = new Set(['ghost:request', 'prov:check', 'wot:analyze']);

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  const fromExtensionPage = sender.id === chrome.runtime.id && sender.url?.startsWith(chrome.runtime.getURL(''));
  const handler = HANDLERS[msg?.type];
  if (!handler || (!fromExtensionPage && !CONTENT_ALLOWED.has(msg.type))) {
    reply({ error: 'not allowed' });
    return false;
  }
  Promise.resolve()
    .then(() => handler(msg, sender))
    .then((result) => reply({ result }), (e) => reply({ error: e?.message || String(e) }));
  return true;
});
