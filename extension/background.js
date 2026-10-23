// EMCON service worker: owns all secrets and does every security decision.
// Content scripts only collect page facts and render UI; they never see keys.

import { toHex, fromHex, toB64u, randomBytes, sha256, hmacSha256, ed25519FromSeed, ed25519Sign, didKeyFromPub, pubFromDidKey, hamming } from './lib/util.js';
import * as brsa from './lib/blindrsa.js';
import { verifyImageBytes } from './lib/provenance.js';
import { dhash } from './lib/dhash.js';
import { domTokens, simhash64 } from './lib/simhash.js';
import { computeTrust, scoreDomain } from './lib/trustgraph.js';
import { signCredential, verifyCredential, VC_CONTEXT } from './lib/vc.js';
import { normDomain, isIp, isLocal, registrable, sameSite, imitation } from './lib/domains.js';
import { lureFindings, urlsIn, STRONG_LURE, SENSITIVE_FIELDS } from './lib/signals.js';
import { receiptDigest } from './lib/receipt.js';
import { encodeQr, decodeQr, makeContact, makeAttestation, verifyQr } from './lib/qrtrust.js';
import { initWatch, tabState, persist, recordPageFacts, chainReport, linkChainReport, privacyReport, markConsent, setGpc, watchHooks } from './watch.js';
import { DEFAULT_SERVER } from './config.js';

const VERSION = chrome.runtime.getManifest().version;
const DEFAULTS = { server: DEFAULT_SERVER, farble: true, farbleExceptions: [], provenance: true, provRecovery: true, wot: true, privacy: true, gpc: true };
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

const caches = []; // everything fetched from the server; cleared when the user switches servers
function cached(ttlMs, fn) {
  let at = 0, val;
  const get = async () => {
    if (!val || Date.now() - at > ttlMs) { val = fn().catch((e) => { val = null; throw e; }); at = Date.now(); }
    return val;
  };
  get.reset = () => { val = null; };
  caches.push(get);
  return get;
}

// "This week" tally shown in the popup: what EMCON did for you. Counts only, no addresses.
let statsQueue = Promise.resolve();
function bumpStat(key, n = 1) {
  statsQueue = statsQueue.then(async () => {
    const day = new Date().toISOString().slice(0, 10);
    const s = (await local.get('stats')) || {};
    (s[day] ||= {})[key] = (s[day][key] || 0) + n;
    for (const d of Object.keys(s).sort().slice(0, -7)) delete s[d];
    await local.set('stats', s);
    reportStats();
  }).catch(() => {});
}
async function weekStats() {
  const t = {};
  for (const day of Object.values((await local.get('stats')) || {})) for (const [k, n] of Object.entries(day)) t[k] = (t[k] || 0) + n;
  return t;
}
watchHooks({ onNewTracker: () => bumpStat('trackers') });

// Optional EMCON account link: this browser reports its weekly counts (never addresses) to
// the dashboard of the account it was paired with, at most every 15 minutes.
let lastReport = 0;
async function reportStats(force = false) {
  const dev = await local.get('device');
  if (!dev || (!force && Date.now() - lastReport < 15 * 60e3)) return;
  lastReport = Date.now();
  try { await api('/api/devices/report', { method: 'POST', body: { token: dev.token, stats: await weekStats(), version: VERSION } }); }
  catch (e) { if (/no longer connected/.test(e.message)) await chrome.storage.local.remove('device'); }
}
async function accountPair({ code }) {
  const ua = navigator.userAgent;
  const name = `${/Edg\//.test(ua) ? 'Edge' : /Brave/.test(ua) || navigator.brave ? 'Brave' : 'Chrome'} on ${/Windows/.test(ua) ? 'Windows' : /Mac/.test(ua) ? 'Mac' : /Android/.test(ua) ? 'Android' : /Linux/.test(ua) ? 'Linux' : 'this computer'}`;
  const r = await api('/api/devices/pair', { method: 'POST', body: { code: String(code || ''), name } });
  await local.set('device', { token: r.deviceToken, account: r.account.name, owner: r.owner, name, at: Date.now() });
  await reportStats(true);
  return accountStatus();
}
// Payment brake: ask the account owner to check a blocked payment page first.
async function brakeInfo() {
  const d = await local.get('device');
  return d ? { connected: true, account: d.account, owner: d.owner } : { connected: false };
}
async function brakeRequest({ domain, reasons }) {
  const d = await local.get('device');
  if (!d) throw new Error('Connect this browser to an EMCON account first (More → Settings → EMCON account).');
  return api('/api/devices/approval', { method: 'POST', body: { token: d.token, domain: String(domain || ''), reasons: (reasons || []).slice(0, 5) } });
}
async function brakeStatus({ id }) {
  const d = await local.get('device');
  if (!d) throw new Error('not connected');
  const { server } = await settings();
  const r = await fetch(`${server}/api/devices/approval/${encodeURIComponent(String(id))}`, { headers: { 'x-device-token': d.token }, credentials: 'omit' });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || 'request failed');
  return j;
}
async function accountStatus() {
  const d = await local.get('device');
  return d ? { connected: true, account: d.account, owner: d.owner, name: d.name } : { connected: false };
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
  let resolve;
  const decision = new Promise((r) => { resolve = r; });
  approvals.set(id, { resolve, origin, claims, bundle, isNewSite, unlock: g.credId ? 'passkey' : 'pin', credId: g.credId });
  try {
    const w = await chrome.windows.create({ url: chrome.runtime.getURL(`pages/approve.html?id=${id}`), type: 'popup', width: 440, height: 620 });
    approvals.get(id).windowId = w.id;
  } catch (e) {
    approvals.delete(id);
    throw new Error('Could not open the EMCON consent window: ' + e.message);
  }
  const ok = await decision;
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
// Shield 1b + privacy monitor + Global Privacy Control
// =====================================================================
// content/guard.js is registered as a MAIN-world document_start script, so Chrome runs it
// before any page script (an injection from here, after the navigation commits, loses
// that race on real sites). Its flags are the content/cfg/*.js files listed before it.
initWatch();
const GPC_RULE = {
  id: 1, priority: 1,
  action: { type: 'modifyHeaders', requestHeaders: [{ header: 'Sec-GPC', operation: 'set', value: '1' }] },
  condition: { resourceTypes: ['main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping', 'media', 'websocket', 'other'] },
};
const scriptSig = (list) => JSON.stringify(list.map(({ id, js, matches, excludeMatches }) => [id, js, matches, excludeMatches?.length ? excludeMatches : []]).sort());
async function applyGuard() {
  const st = await settings();
  setGpc(st.gpc);
  const flags = [st.privacy && 'content/cfg/watch.js', st.gpc && 'content/cfg/gpc.js'].filter(Boolean);
  const off = st.farbleExceptions.map((h) => `*://${h}/*`);
  const base = { matches: ['http://*/*', 'https://*/*'], runAt: 'document_start', allFrames: true, matchOriginAsFallback: true, world: 'MAIN' };
  const want = [];
  if (st.farble) want.push({ ...base, id: 'emcon-guard', excludeMatches: off, js: [...flags, 'content/cfg/noise.js', 'content/guard.js'] });
  // sites where the user turned fingerprint protection off still get the monitor and GPC
  if (flags.length && (!st.farble || off.length)) want.push({ ...base, id: 'emcon-guard-lite', matches: st.farble ? off : base.matches, js: [...flags, 'content/guard.js'] });
  const have = await chrome.scripting.getRegisteredContentScripts();
  if (scriptSig(have) !== scriptSig(want)) {
    if (have.length) await chrome.scripting.unregisterContentScripts();
    if (want.length) await chrome.scripting.registerContentScripts(want);
  }
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [GPC_RULE.id], addRules: st.gpc ? [GPC_RULE] : [] });
}
let guardQueue = Promise.resolve();
const syncGuard = () => (guardQueue = guardQueue.then(applyGuard).catch((e) => console.warn('EMCON guard:', e)));
syncGuard();
chrome.tabs.onRemoved.addListener((tabId) => { lastFacts.delete(tabId); tabImages.delete(tabId); });

// =====================================================================
// Shield 2: media provenance
// =====================================================================
const trustList = cached(10 * 60e3, () => api('/api/prov/trust-list'));
const registry = cached(10 * 60e3, () => api('/api/prov/registry'));
const provCache = new Map();
const tabImages = new Map(); // tabId -> { url, counts: { verified: 2, … } } for the popup
const LABELLED = new Set(['verified', 'recovered', 'untrusted', 'altered', 'forged', 'c2pa']);

function provCheck(url) {
  if (provCache.has(url)) return provCache.get(url);
  const p = (async () => {
    const res = await fetch(url, { credentials: 'omit' });
    if (!res.ok) return { status: 'error', error: `HTTP ${res.status}` };
    if (Number(res.headers.get('content-length')) > 15e6) return { status: 'skipped' };
    const bytes = new Uint8Array(await res.arrayBuffer());
    let trust = [], trustOk = true;
    try { trust = await trustList(); } catch { trustOk = false; /* offline: signatures still checked, nothing "trusted" */ }
    let result = { ...(await verifyImageBytes(bytes, trust)), trustListLoaded: trustOk };
    if (result.status === 'none' && (await settings()).provRecovery) {
      try {
        const bmp = await createImageBitmap(new Blob([bytes]));
        const h = await dhash(bmp);
        bmp.close();
        // Matched locally against the downloaded registry: the server never learns which images you view.
        let best = null;
        for (const r of await registry()) {
          const d = hamming(h, r.dhash);
          if (d <= 10 && (!best || d < best.distance)) best = { match: r, distance: d };
        }
        result = best ? { ...result, status: 'recovered', ...best } : { ...result, registryChecked: true };
      } catch { result.registryChecked = false; /* recovery is best-effort */ }
    }
    return { ...result, checkedAt: Date.now() };
  })().catch((e) => ({ status: 'error', error: String(e.message || e) }));
  provCache.set(url, p);
  if (provCache.size > 400) provCache.delete(provCache.keys().next().value);
  return p;
}

// Evidence rows for one image (used by receipts).
function imageChecks(r) {
  const rows = [];
  const row = (label, status, detail) => rows.push({ label, status, detail });
  if (['error', 'unsupported', 'skipped'].includes(r.status)) {
    row('Image could be inspected', 'unknown', r.status === 'unsupported' ? 'Not a PNG or JPEG file' : r.error || 'The image could not be downloaded');
    return rows;
  }
  const m = r.manifest;
  if (m) {
    row('Signed provenance label in the file', 'note', `Label names publisher “${m.issuer?.name}”, title “${m.title}”, created ${m.created}`);
    if (r.status === 'forged') { row('Signature', 'found', 'The signature does not verify: the label was faked or edited'); return rows; }
    row('Signature', 'good', 'The signature verifies');
    row('Pixels unchanged since signing', r.status === 'altered' ? 'found' : 'good', r.status === 'altered' ? 'The pixel hash differs from the signed hash: the image was edited after signing' : 'The pixel hash matches the signed hash');
    const trusted = r.status === 'verified' || (r.status === 'altered' && r.trusted);
    row('Signer on your trust list', r.trustListLoaded === false ? 'unknown' : trusted ? 'good' : 'found', r.trustListLoaded === false ? 'Trust list could not be loaded' : trusted ? `Yes: ${r.issuerName}` : 'No: the signer is self-declared');
  } else {
    row('Signed provenance label in the file', r.status === 'c2pa' ? 'note' : 'clear', r.status === 'c2pa' ? 'No EMCON label, but a C2PA (Content Credentials) manifest is present' : 'No label in this file (common: most images are unsigned)');
    if (r.status === 'c2pa') {
      const c = r.c2pa || {};
      row('C2PA signer (read, not validated)', 'note', [c.signer && `signed by ${c.signer}`, c.issuer && `certificate issued by ${c.issuer}`, c.generator && `made with ${c.generator}`, c.timestampAuthority && `timestamped by ${c.timestampAuthority}`].filter(Boolean).join('; ') || 'No readable signer details');
      return rows;
    }
    if (r.status === 'recovered') row('Visual match with a signed original', 'good', `Matches “${r.match.title}” by ${r.match.issuerName} (${64 - r.distance}/64 fingerprint bits): ${r.match.url}`);
    else row('Visual match with a signed original', r.registryChecked === false ? 'unknown' : 'clear', r.registryChecked === false ? 'The registry could not be checked' : 'No signed original looks like this image');
  }
  return rows;
}

const IMAGE_VERDICT = { verified: 'Verified source', recovered: 'Provenance recovered', untrusted: 'Signed by an unknown key', altered: 'Altered after signing', forged: 'Forged provenance', c2pa: 'C2PA credentials present', none: 'No provenance information' };

// =====================================================================
// Shield 4: Web of Trust, clone + look-alike detection, scam chains
// =====================================================================
async function wotIdentity() {
  const { privateKey, pub } = await ed25519FromSeed(await derive('emcon/wot/identity'));
  return { privateKey, did: didKeyFromPub(pub) };
}

const serverGroups = cached(60 * 60e3, () => api('/api/wot/groups'));

// Built-in sources (security group, live phishing feed) are followed by default,
// including ones the server adds later, unless the user removed them.
async function wotState() {
  const w = (await local.get('wot')) || { roots: [], dismissed: [] };
  w.dismissed ||= [];
  try {
    const known = new Set([...w.roots.map((r) => r.did), ...w.dismissed]);
    const fresh = (await serverGroups()).filter((g) => !known.has(g.did));
    if (fresh.length) {
      w.roots.push(...fresh.map((g) => ({ did: g.did, weight: g.defaultWeight ?? 0.8, label: g.name, kind: 'group' })));
      await local.set('wot', w);
      trustMapCached.reset();
    }
  } catch { /* server offline; retry next time */ }
  return w;
}

const trustMapCached = cached(5 * 60e3, trustMap);

async function trustMap() {
  const w = await wotState();
  const { did: me } = await wotIdentity();
  const roots = [{ did: me, weight: 1, label: 'You' }, ...w.roots];
  const vouches = [];
  try {
    const res = await api('/api/wot/vouches?issuers=' + encodeURIComponent(roots.map((r) => r.did).join(',')));
    for (const vc of res.vouches) {
      if (await verifyCredential(vc)) vouches.push({ issuer: vc.issuer, subject: vc.credentialSubject.id, weight: vc.credentialSubject.weight });
    }
  } catch { /* offline */ }
  const trust = computeTrust(roots, vouches);
  trust.labels = new Map(roots.map((r) => [r.did, r.label]));
  return trust;
}

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

async function domainAgeDays(host) {
  const d = registrable(host);
  const cache = (await local.get('rdap')) || {};
  let created = cache[d]?.created;
  if (!cache[d] || Date.now() - cache[d].at > 7 * 864e5) {
    try {
      const r = await fetch(`https://rdap.org/domain/${d}`, { credentials: 'omit' });
      if (!r.ok) return null;
      const j = await r.json();
      created = (j.events || []).find((e) => e.eventAction === 'registration')?.eventDate || null;
      cache[d] = { created, at: Date.now() };
      await local.set('rdap', cache);
    } catch { return null; }
  }
  return created ? Math.floor((Date.now() - Date.parse(created)) / 864e5) : null;
}

const brandList = cached(10 * 60e3, () => api('/api/wot/brands'));

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const list = (xs) => (xs.length <= 1 ? xs.join('') : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}`);
const ago = (days) => (days >= 730 ? `${Math.floor(days / 365)} years` : `${days} days`);

const lastFacts = new Map(); // tabId -> {page, sender}: lets a pasted message re-run the analysis
const countedPages = new Set(); // tab|url already counted in the weekly tally

/**
 * Every check becomes an evidence row: found (warning evidence), good (positive evidence),
 * clear (checked, nothing found), unknown (could not be checked), note (neutral fact), na.
 * The score is the sum of the rows' points; nothing else.
 */
async function wotAnalyze(page, sender) {
  if (!(await settings()).wot) return null;
  const tabId = sender.tab?.id;
  if (tabId != null) lastFacts.set(tabId, { page, sender });
  const url = new URL(sender.url);
  const host = url.hostname;
  const domain = normDomain(host);
  const checks = [];
  let risk = 0;
  const check = (id, label, status, detail, pts = 0) => { checks.push({ id, label, status, detail, pts }); risk += pts; };
  const strong = []; // site-level evidence that turns a lure + data request into a scam chain
  const fields = (page.fields || []).slice(0, 12);
  const sensitive = fields.filter((f) => SENSITIVE_FIELDS.has(f));
  const asksFor = sensitive.length ? list(sensitive) : 'a password';

  // 1. Reports from people and sources you trust (includes the live phishing feed)
  let s = null;
  try { s = scoreDomain([...(await domainAttestations(domain)), ...(await qrAttestationsFor(domain))], await trustMapCached()); } catch { /* unreachable */ }
  if (!s) check('reports', 'Scam and phishing reports', 'unknown', 'The trust network could not be reached, so reports were not checked');
  else {
    const labels = (await trustMapCached()).labels;
    const who = (e) => (e.hops === 1 ? labels.get(e.issuer) || 'a source you follow' : 'someone your network trusts');
    const scams = s.evidence.filter((e) => e.verdict === 'scam');
    const goods = s.evidence.filter((e) => e.verdict === 'trusted');
    const ignored = s.ignored ? ` ${s.ignored} report(s) from strangers were ignored (Sybil protection).` : '';
    if (scams.length) {
      check('reports', 'Scam and phishing reports', 'found', `Reported as a scam by ${scams.length} source(s) in your web of trust: ${list([...new Set(scams.map(who))])}${scams[0].note ? ` (“${scams[0].note}”)` : ''}.${ignored}`, Math.round(70 * Math.min(1, s.neg)));
      strong.push('reported as a scam');
    }
    if (goods.length) check('reports', 'Scam and phishing reports', 'good', `Vouched for by ${goods.length} source(s) in your web of trust: ${list([...new Set(goods.map(who))])}.${ignored}`, -Math.round(40 * Math.min(1, s.pos)));
    if (!scams.length && !goods.length) check('reports', 'Scam and phishing reports', 'clear', `No reports from the sources you follow, including the live phishing feed.${ignored}`);
  }

  // 1b. Crowd ratings from verified people (small weight: crowds can be wrong, never decisive)
  try {
    const sum = summarise(await ratingsFor(domain), await trustMapCached(), (await wotIdentity()).did);
    const v = sum.verified;
    const topTags = v.tags.slice(0, 2).map(([t, n]) => `"${t}" (${n})`).join(', ');
    if (v.count >= 3 && v.avg <= 2) check('ratings', 'Ratings from verified people', 'found', `Rated ${v.avg}/5 by ${v.count} verified people${topTags ? ': ' + topTags : ''}`, 15);
    else if (v.count >= 3 && v.avg >= 4) check('ratings', 'Ratings from verified people', 'good', `Rated ${v.avg}/5 by ${v.count} verified people${topTags ? ': ' + topTags : ''}`, -8);
    else if (v.count) check('ratings', 'Ratings from verified people', 'note', `${v.count} verified ${v.count === 1 ? 'person has' : 'people have'} rated it ${v.avg}/5: not enough to count yet`);
    else check('ratings', 'Ratings from verified people', 'clear', sum.unverified ? `No verified ratings yet (${sum.unverified} unverified not counted)` : 'Nobody has rated this site yet');
  } catch { /* ratings are optional */ }

  // 1c. Checkout script-change alarm (payment pages only)
  if (tabId != null && page.payment && Array.isArray(page.scripts)) {
    const c = await checkoutScripts(sender.url, page.scripts).catch(() => null);
    const since = (t) => new Date(t).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
    if (c?.status === 'first') check('scripts', 'Payment page scripts', 'note', `First visit to this payment page: EMCON recorded its ${c.count} scripts and will warn you if a new outside script appears before you pay`);
    else if (c?.status === 'alarm') {
      check('scripts', 'Payment page scripts', 'found', `A script from ${list(c.newHosts)} appeared on this payment page since your visit on ${since(c.since)}. A new outside script can read card details as you type them (a "Magecart" skimming attack). Don't enter card details unless you know why it changed.`, 30);
      strong.push('a new outside script on the payment page');
    } else if (c?.status === 'changed') check('scripts', 'Payment page scripts', 'note', `${c.added.length ? `${c.added.length} new script(s) from domains this page already used` : ''}${c.added.length && c.changed.length ? ', and ' : ''}${c.changed.length ? `${c.changed.length} script(s) with changed content` : ''} since ${since(c.since)}. Sites update their scripts often, so this alone isn't a warning`);
    else if (c) check('scripts', 'Payment page scripts', 'clear', `The same ${c.count} scripts as on your first visit (${since(c.since)})`);
  }

  // 2. Domain age (public RDAP registry)
  if (isLocal(host)) check('age', 'Domain age (public registry)', 'na', 'Local or IP address: there is no public registration to look up');
  else {
    const age = await domainAgeDays(host);
    if (age === null) check('age', 'Domain age (public registry)', 'unknown', `The public registry (RDAP) gave no registration date for ${registrable(host)}`);
    else if (age < 30) { check('age', 'Domain age (public registry)', 'found', `${registrable(host)} was registered only ${age} day(s) ago`, 35); strong.push('a brand-new domain'); }
    else if (age < 180) check('age', 'Domain age (public registry)', 'found', `${registrable(host)} is fairly new: registered ${age} days ago`, 10);
    else check('age', 'Domain age (public registry)', 'clear', `${registrable(host)} was registered ${ago(age)} ago`);
  }

  // 3. Brand impersonation: layout clone, look-alike address, or brand + sensitive fields on a
  //    non-official domain. Never layout alone, never a brand mention alone.
  let brands = null;
  try { brands = await brandList(); } catch { /* unavailable */ }
  if (!brands) check('brand', 'Brand impersonation', 'unknown', 'The protected-brand list could not be loaded');
  else {
    const sh = simhash64(domTokens(page.html || ''));
    const text = `${page.title} ${page.text}`.toLowerCase();
    const others = brands.filter((b) => !b.domains.some((d) => domain === d || domain.endsWith('.' + d)));
    const mentions = (b) => b.keywords.some((k) => new RegExp(`\\b${escapeRe(k)}\\b`).test(text));
    let hit = false;
    for (const b of others) {
      if (!b.simhash) continue;
      const dist = hamming(sh, b.simhash);
      if (dist <= 12 && (mentions(b) || page.hasPassword)) {
        check('clone', 'Copies a known brand’s page', 'found', `Page layout matches ${b.name}'s real login page (${64 - dist}/64 structural bits), but this site is not ${b.domains[0]}`, 45);
        strong.push(`a copy of ${b.name}'s page`);
        hit = true;
        break;
      }
    }
    for (const b of hit ? [] : others) {
      const im = imitation(domain, b);
      if (!im) continue;
      check('lookalike', 'Look-alike web address', 'found', `This address ${im.text}, but it is not an official ${b.name} domain`, im.strong ? 45 : 25);
      if (page.hasPassword || sensitive.length) check('lookalike', 'Look-alike web address', 'found', `It asks for ${asksFor} on that look-alike address`, 20);
      strong.push(`a look-alike of ${b.name}`);
      hit = true;
      break;
    }
    if (!hit && (page.hasPassword || sensitive.length)) {
      const b = others.find(mentions);
      if (b) {
        check('brand', 'Brand name on an unofficial site', 'found', `Asks for ${asksFor} and mentions ${b.name}, but isn't an official ${b.name} domain`, 20);
        strong.push(`${b.name}'s name on an unofficial site`);
        hit = true;
      }
    }
    if (!hit) check('brand', 'Brand impersonation', 'clear', sender.linkCheck ? `The address doesn't imitate any of the ${brands.length} protected brands (page layout not checked without opening it)` : `Doesn't copy or imitate any of the ${brands.length} protected brands`);
  }

  // 4. What the page asks for, and where it would send it
  if (sender.linkCheck) check('data', 'Details this page asks for', 'unknown', 'Not checked: EMCON followed the link without opening the page in your browser');
  else if (fields.length) check('data', 'Details this page asks for', 'note', `Asks for: ${list(fields)}`);
  else check('data', 'Details this page asks for', 'clear', 'No password, payment or ID fields on this page');
  if (page.hasPassword) {
    let issue = false;
    const foreign = (page.formHosts || []).filter((h) => h && normDomain(h) !== domain);
    if (foreign.length) { check('form', 'Login form safety', 'found', `Password form submits to a different site: ${foreign[0]}`, 15); issue = true; }
    if (isIp(host)) { check('form', 'Login form safety', 'found', 'Login form on a raw IP address', 15); issue = true; }
    if (url.protocol === 'http:' && !isLocal(host)) { check('form', 'Login form safety', 'found', 'Password requested over unencrypted HTTP', 10); issue = true; }
    if (domain.split('.').some((l) => l.startsWith('xn--'))) { check('form', 'Login form safety', 'found', 'Internationalised domain name asking for a password (a common way to fake letters)', 15); issue = true; }
    if (!issue) check('form', 'Login form safety', 'clear', `The password form submits to this site${url.protocol === 'https:' ? ' over HTTPS' : ''}`);
  }

  // 5. Scam chain: how you got here and what was said along the way
  const pageLure = lureFindings(`${page.title}\n${page.text}`);
  let ch = null;
  if (tabId != null) {
    const st = await tabState(tabId);
    recordPageFacts(st, sender.url, pageLure, fields);
    if (page.privacyPromise && st.privacy) st.privacy.promise = { tokens: page.privacyPromise, source: 'declared by the site' };
    persist(tabId);
    ch = chainReport(st, sender.url, pageLure);
  } else if (sender.linkCheck) {
    ch = linkChainReport(sender.linkCheck);
    if (!sender.linkCheck.complete) check('path', 'How the link redirects', 'unknown', sender.linkCheck.error || 'EMCON could not follow the link to its end (the site did not answer)');
  }
  const lure = ch ? ch.lure : pageLure.map((l) => ({ ...l, where: 'this page' }));
  if (ch && ch.hops.length > 1) {
    const pts = Math.min(15, (ch.redirects >= 2 ? 5 : 0) + (ch.shorteners.length ? 10 : 0) + (ch.sites.length >= 3 ? 5 : 0));
    const bits = [`${ch.hops.length} steps`];
    if (ch.redirects) bits.push(`${ch.redirects} automatic redirect(s)`);
    if (ch.shorteners.length) bits.push(`link shortener ${list(ch.shorteners)}`);
    bits.push(`${ch.sites.length} site(s)`);
    // redirects alone are routine (sign-in flows, brand short links): a note; a shortener hiding the address is a finding
    check('path', 'How you got here', pts >= 10 ? 'found' : pts ? 'note' : 'clear', `${bits.join(', ')}: ${ch.hops.map((h) => h.label).join(' → ')}`, pts);
  } else if (sender.linkCheck) check('path', 'How you got here', 'clear', `The link goes straight to ${ch.hops[0]?.label}, with no redirects`);
  else check('path', 'How you got here', 'clear', 'You opened this page directly');
  if (ch?.message) {
    check('message', 'The message you pasted', ch.message.lure ? 'found' : 'clear', `${ch.message.lure ? `${ch.message.lure} scam-style phrase(s)` : 'No scam-style wording'}${ch.message.urls.length ? `; its link ${ch.message.linked ? 'leads into this chain' : 'does not appear in this chain'}` : '; it contains no link'}`);
  }
  const strongLure = lure.filter(STRONG_LURE);
  if (lure.length) check('lure', 'Scam-style wording along the way', 'found', lure.slice(0, 4).map((l) => `“${l.phrase}” (${l.where})`).join(', '), strongLure.length ? 10 : 5);
  else check('lure', 'Scam-style wording along the way', 'clear', 'No prize, threat, fee or urgency wording found');
  if (strongLure.length && strong.length && (sensitive.length || sender.linkCheck)) {
    const stages = [`${strongLure[0].kind} wording (“${strongLure[0].phrase}”)`];
    if (ch?.redirects) stages.push(`${ch.redirects} redirect(s)`);
    stages.push(strong[0]);
    if (sensitive.length) stages.push(`asks for ${list(sensitive)}`);
    check('chain', 'Scam chain', 'found', sensitive.length ? `Every stage of a classic scam is present: ${stages.join(' → ')}` : `The message's scam wording leads to a suspicious site: ${stages.join(' → ')}`, sensitive.length ? 30 : 20);
    // inside a scam chain, the redirects are part of the evidence, not a side note
    for (const c of checks) if (c.id === 'path' && c.status === 'note') c.status = 'found';
  }

  // A good reputation never cancels scam evidence on the page itself: reputable sites get
  // hacked and used to host phishing kits, so vouches stop counting once the page shows it.
  const pageEvidence = checks.some((c) => c.status === 'found' && ['chain', 'clone', 'lookalike', 'scripts'].includes(c.id));
  for (const c of checks) {
    if (pageEvidence && c.status === 'good' && c.pts < 0) {
      risk -= c.pts;
      c.pts = 0;
      c.detail += ' Not counted: this page itself shows scam evidence, and trusted sites can be hacked.';
    }
  }

  risk = Math.max(0, Math.min(100, risk));
  const level = risk >= 60 ? 'danger' : risk >= 30 ? 'caution' : (s?.pos || 0) >= 0.5 && !pageEvidence ? 'trusted' : 'unknown';
  const verdict = { url: sender.url, domain, risk, level, checks, chain: ch?.hops.length > 1 ? ch.hops : [], at: Date.now() };
  const seenKey = `${tabId ?? 'link'}|${sender.url}`;
  if (!countedPages.has(seenKey)) {
    countedPages.add(seenKey);
    if (countedPages.size > 500) countedPages.delete(countedPages.values().next().value);
    bumpStat(sender.linkCheck ? 'links' : 'pages');
    if (level === 'danger') bumpStat('blocked');
    else if (level === 'caution') bumpStat('warned');
  }
  if (tabId != null) {
    await chrome.storage.session.set({ ['verdict_' + tabId]: verdict });
    const [text, color] = { danger: ['!', '#B42318'], caution: ['?', '#B54708'], trusted: ['✓', '#067647'], unknown: ['', '#475467'] }[level];
    chrome.action.setBadgeText({ tabId, text });
    chrome.action.setBadgeBackgroundColor({ tabId, color });
  }
  return verdict;
}

async function chainMessage({ tabId, text }) {
  const st = await tabState(tabId);
  st.message = String(text || '').slice(0, 2000); // stays in this browser; never sent anywhere
  persist(tabId);
  const f = lastFacts.get(tabId);
  if (!f) return null;
  const v = await wotAnalyze(f.page, f.sender);
  chrome.tabs.sendMessage(tabId, { type: 'emcon:verdict', verdict: v }).catch(() => {});
  return v;
}

// "Check a link or message": judge where a link really lands without opening it.
const linkChecks = new Map(); // id -> verdict, for receipts
async function linkCheck({ text }) {
  const raw = String(text || '').trim().slice(0, 2000);
  const start = urlsIn(raw)[0];
  if (!start) throw new Error('No link found. Paste a link, or a whole message that contains one.');
  let exp;
  try { exp = await api('/api/link/expand?url=' + encodeURIComponent(start)); } catch (e) { exp = { hops: [{ url: start }], final: start, complete: false, error: e.message }; }
  // hop i was reached the way hop i-1 left
  const hops = exp.hops.map((h, i) => ({ url: h.url, via: i === 0 ? 'link' : exp.hops[i - 1].leaves || 'redirect' }));
  if (hops[hops.length - 1]?.url !== exp.final) hops.push({ url: exp.final, via: exp.hops[exp.hops.length - 1]?.leaves || 'redirect' });
  const message = /\s/.test(raw) ? raw : ''; // a bare link has no spaces; anything more is a message
  const v = await wotAnalyze(
    { title: '', text: '', html: '', hasPassword: false, formHosts: [], fields: [] },
    { url: exp.final, linkCheck: { hops, message, complete: exp.complete, error: exp.error } },
  );
  const checkId = toHex(randomBytes(6));
  linkChecks.set(checkId, { ...v, checkedLink: start });
  if (linkChecks.size > 50) linkChecks.delete(linkChecks.keys().next().value);
  return { ...v, checkId, checkedLink: start };
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

// ---------- checkout script-change alarm (Magecart-style skimmers) ----------
// Trust on first use: the first time you see a payment page, EMCON records its scripts and a
// fingerprint of each one's content. Later, a script from a NEW outside domain raises the alarm
// before you type card details. Content changes and new first-party files are shown as notes:
// sites redeploy and ad scripts update constantly, and crying wolf would teach people to ignore it.
const checkoutKey = (u) => { const x = new URL(u); return x.origin + x.pathname.split('/').map((p) => (/^\d+$|^[0-9a-f-]{16,}$/i.test(p) ? ':id' : p)).join('/'); };
// app.3f2a9c1e.js and app.71b0c2d4.js are the same script after a deploy
const scriptId = (s) => { try { const u = new URL(s); if (!/^https?:$/.test(u.protocol)) return u.protocol + 'inline'; return u.origin + u.pathname.replace(/[.-][0-9a-f]{6,}(?=[.-])/gi, '.*').replace(/\d{6,}/g, '*'); } catch { return null; } };
const scriptHashes = new Map();
function scriptHash(src) {
  if (!scriptHashes.has(src)) {
    scriptHashes.set(src, (/^https?:/.test(src) ? fetch(src, { credentials: 'omit' }).then((r) => (r.ok ? r.arrayBuffer() : null)) : Promise.resolve(new TextEncoder().encode(src)))
      .then(async (b) => (b ? toHex(await sha256(new Uint8Array(b))).slice(0, 16) : null)).catch(() => null));
    if (scriptHashes.size > 400) scriptHashes.delete(scriptHashes.keys().next().value);
  }
  return scriptHashes.get(src);
}
async function checkoutScripts(pageUrl, srcs) {
  const key = checkoutKey(pageUrl);
  const site = normDomain(new URL(pageUrl).hostname);
  const items = [];
  for (const src of [...new Set(srcs)].slice(0, 60)) {
    const id = scriptId(src);
    if (!id || items.some((i) => i.id === id)) continue;
    let host = 'an inline data: or blob: script';
    try { if (/^https?:/.test(src)) host = normDomain(new URL(src).hostname); } catch { /* keep */ }
    items.push({ id, src: src.slice(0, 300), host, third: host !== site && !(host.includes('.') && sameSite(host, site)), hash: await scriptHash(src) });
  }
  const all = (await local.get('checkouts')) || {};
  const base = all[key];
  if (!base) {
    all[key] = { first: Date.now(), visits: 1, scripts: Object.fromEntries(items.map((i) => [i.id, { host: i.host, third: i.third, hash: i.hash }])) };
    const keys = Object.keys(all);
    for (const k of keys.slice(0, Math.max(0, keys.length - 300))) delete all[k];
    await local.set('checkouts', all);
    return { status: 'first', count: items.length };
  }
  base.visits = (base.visits || 1) + 1;
  base.last = Date.now();
  const knownHosts = new Set(Object.values(base.scripts).map((s) => s.host));
  const added = items.filter((i) => !base.scripts[i.id]);
  const changed = items.filter((i) => base.scripts[i.id]?.hash && i.hash && base.scripts[i.id].hash !== i.hash);
  const newHosts = [...new Set(added.filter((i) => i.third && !knownHosts.has(i.host)).map((i) => i.host))];
  base.pending = [...added, ...changed];
  await local.set('checkouts', all);
  return { status: newHosts.length ? 'alarm' : added.length || changed.length ? 'changed' : 'same', newHosts, added, changed, count: items.length, since: base.first, visits: base.visits };
}
async function checkoutAccept({ url }) {
  const all = (await local.get('checkouts')) || {};
  const base = all[checkoutKey(url)];
  if (base?.pending) {
    for (const i of base.pending) base.scripts[i.id] = { host: i.host, third: i.third, hash: i.hash };
    base.accepted = Date.now();
    delete base.pending;
    await local.set('checkouts', all);
  }
  return true;
}

// ---------- crowdsourced ratings ----------
// Signed by your EMCON key. You count as a verified person after spending one humanity token
// (needs Ghost set up); otherwise your rating is shown, but not counted in the verified score.
async function ratingsFor(domain) {
  const prefix = toHex(await sha256(domain)).slice(0, 5);
  const { ratings } = await api('/api/ratings?prefix=' + prefix);
  return ratings.filter((r) => r.domain === domain);
}
function summarise(list, trust, me) {
  const verified = list.filter((r) => r.human);
  const avg = (xs) => (xs.length ? +(xs.reduce((a, r) => a + r.stars, 0) / xs.length).toFixed(1) : null);
  const tags = {};
  for (const r of verified) for (const t of r.tags) tags[t] = (tags[t] || 0) + 1;
  const network = list.filter((r) => trust.has(r.did) && r.did !== me).map((r) => ({ ...r, who: trust.labels.get(r.did) || 'someone your network trusts' }));
  return {
    verified: { count: verified.length, avg: avg(verified), tags: Object.entries(tags).sort((a, b) => b[1] - a[1]) },
    unverified: list.length - verified.length,
    network, mine: list.find((r) => r.did === me) || null,
  };
}
async function rateGet({ domain }) {
  const d = normDomain(domain);
  const [list, trust, me] = await Promise.all([ratingsFor(d), trustMapCached(), wotIdentity()]);
  return { domain: d, ...summarise(list, trust, me.did), tags: await api('/api/ratings/tags'), raterVerified: !!(await local.get('raterVerified')) };
}
async function rateSubmit({ domain, stars, tags }) {
  const me = await wotIdentity();
  let verified = !!(await local.get('raterVerified'));
  if (!verified) {
    // Spend one humanity token to prove "a real person holds this key". Without Ghost, skip.
    const g = await local.get('ghost');
    const bundle = g?.bundles?.find((b) => g.tokens?.[b]?.length);
    if (bundle) {
      const token = g.tokens[bundle].shift();
      await local.set('ghost', g);
      const sig = toB64u(await ed25519Sign(me.privateKey, `EMCON-RATER-v1|${me.did}|${token.t}`));
      await api('/api/ratings/verify', { method: 'POST', body: { did: me.did, token: { t: token.t, s: token.s, keyId: token.keyId }, sig } });
      await local.set('raterVerified', true);
      verified = true;
    }
  }
  const d = normDomain(domain), n = Math.round(Number(stars)), t = (tags || []).slice(0, 4), iat = Date.now();
  const sig = toB64u(await ed25519Sign(me.privateKey, `EMCON-RATE-v1|${me.did}|${d}|${n}|${t.join(',')}|${iat}`));
  await api('/api/ratings', { method: 'POST', body: { did: me.did, domain: d, stars: n, tags: t, iat, sig } });
  return { ...(await rateGet({ domain: d })), justVerified: verified };
}

// ---------- trust over QR codes (person to person, no server) ----------
async function qrStore() { return (await local.get('qrAtts')) || []; }
async function qrAttestationsFor(domain) {
  const now = Date.now();
  return (await qrStore()).filter((a) => a.domain === domain && a.expires > now)
    .map((a) => ({ issuer: a.issuer, verdict: a.claim === 'safe' ? 'trusted' : 'scam', transacted: a.claim === 'safe', note: 'shared in person by QR code', issued: new Date(a.issued).toISOString() }));
}
async function qrContact({ nickname }) {
  const me = await wotIdentity();
  return { text: encodeQr(await makeContact(me, nickname)), did: me.did };
}
async function qrAttest({ domain, claim }) {
  const me = await wotIdentity();
  const p = await makeAttestation(me, domain, claim);
  // keep my own statement too, so it counts on this browser and replaces any older one
  await qrSave(await verifyQr(p));
  return { text: encodeQr(p), domain: p.d, expires: p.exp * 1000 };
}
async function qrSave(v) {
  const list = (await qrStore()).filter((a) => !(a.issuer === v.issuer && a.domain === v.domain && a.issued <= v.issued));
  if (list.some((a) => a.issuer === v.issuer && a.domain === v.domain)) return false; // a newer one already exists
  list.push({ issuer: v.issuer, domain: v.domain, claim: v.claim, issued: v.issued, expires: v.expires, nonce: v.nonce, raw: v.raw, received: Date.now() });
  await local.set('qrAtts', list.slice(-500));
  return true;
}
/** A scanned or pasted QR: contacts are returned for the user to confirm; attestations are checked and stored. */
async function qrImport({ text }) {
  const v = await verifyQr(decodeQr(text));
  const me = await wotIdentity();
  const roots = (await wotState()).roots;
  const label = (did) => (did === me.did ? 'You' : roots.find((r) => r.did === did)?.label || null);
  if (v.kind === 'contact') return { ...v, raw: undefined, isMe: v.did === me.did, known: label(v.did) };
  const who = label(v.issuer);
  // Sybil rule: only people you added yourself (in person) count. Strangers can't vote.
  if (!who) throw new Error('This vouch is signed by someone who is not in your contacts. Scan their contact QR first, in person.');
  const fresh = await qrSave(v);
  trustMapCached.reset();
  return { ...v, raw: undefined, from: who, stored: fresh };
}
async function qrList() {
  const roots = (await wotState()).roots;
  const me = (await wotIdentity()).did;
  const now = Date.now();
  return (await qrStore()).filter((a) => a.expires > now).sort((a, b) => b.issued - a.issued)
    .map(({ raw, ...a }) => ({ ...a, from: a.issuer === me ? 'You' : roots.find((r) => r.did === a.issuer)?.label || 'Removed contact' }));
}

async function wotTrust({ did, weight, label, publish }) {
  pubFromDidKey(did); // throws if malformed
  const me = await wotIdentity();
  if (did === me.did) throw new Error("that's you");
  const w = await wotState();
  w.roots = w.roots.filter((r) => r.did !== did);
  w.roots.push({ did, weight: Math.min(1, Math.max(0.05, Number(weight) || 0.5)), label: String(label || 'Friend').slice(0, 40), kind: 'person' });
  await local.set('wot', w);
  trustMapCached.reset();
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
  if (w.roots.find((r) => r.did === did)?.kind === 'group') w.dismissed.push(did);
  w.roots = w.roots.filter((r) => r.did !== did);
  await local.set('wot', w);
  trustMapCached.reset();
  return w.roots;
}

// =====================================================================
// Privacy promise monitor (observations come from watch.js + the page script)
// =====================================================================
async function privacyFeatures(m, sender) {
  const tabId = sender.tab?.id;
  if (tabId == null) return false;
  const st = await tabState(tabId);
  if (!st.privacy) return false;
  const counts = {};
  for (const [f, n] of Object.entries(m.counts || {})) if (/^[a-z-]{2,30}$/.test(f)) counts[f] = Math.min(1e6, Number(n) || 0);
  st.privacy.frames[`${sender.frameId}`] = { origin: sender.origin, counts };
  persist(tabId);
  return true;
}

async function privacyConsent({ tabId, state, how }, sender) {
  const id = tabId ?? sender.tab?.id;
  if (id == null || !['denied', 'granted'].includes(state)) throw new Error('bad consent event');
  const st = await tabState(id);
  // an automatic click detection never overrides an explicit "I said no"
  if (st.privacy?.consent?.state === 'denied' && state === 'granted' && sender.tab) return false;
  markConsent(st, state, String(how || (state === 'denied' ? 'marked in EMCON' : 'accepted')).slice(0, 80));
  persist(id);
  return privacyReport(st);
}

// =====================================================================
// Evidence receipts
// =====================================================================
async function receiptCreate({ tabId, image, checkId }) {
  const { did, privateKey } = await wotIdentity();
  const { server } = await settings();
  let subject;
  if (checkId) {
    const v = linkChecks.get(checkId);
    if (!v) throw new Error('That link check has expired. Check the link again.');
    subject = {
      id: v.checkedLink, kind: 'link', lands: v.url, domain: v.domain, checkedAt: new Date(v.at).toISOString(),
      verdict: { level: v.level, risk: v.risk },
      checks: v.checks.map(({ label, status, detail, pts }) => ({ label, status, detail, points: pts })),
      path: v.chain.map(({ label, via }) => ({ host: label, via })),
    };
  } else if (image) {
    const r = await provCheck(image);
    subject = { id: image, kind: 'image', checkedAt: new Date(r.checkedAt || Date.now()).toISOString(), verdict: { status: r.status, summary: IMAGE_VERDICT[r.status] || r.status }, checks: imageChecks(r) };
  } else {
    const v = (await chrome.storage.session.get('verdict_' + tabId))['verdict_' + tabId];
    if (!v) throw new Error('No analysis for this tab yet. Reload the page and try again.');
    const st = await tabState(tabId);
    const pr = privacyReport(st);
    subject = {
      id: v.url, kind: 'website', domain: v.domain, checkedAt: new Date(v.at).toISOString(),
      verdict: { level: v.level, risk: v.risk },
      checks: v.checks.map(({ label, status, detail, pts }) => ({ label, status, detail, points: pts })),
      path: v.chain.map(({ label, via }) => ({ host: label, via })),
      privacy: pr && { thirdPartyDomains: pr.thirdPartyCount, trackingDomains: pr.trackerCount, consent: pr.consent?.state || 'not given', promises: pr.promises.map(({ text, status, evidence }) => ({ promise: text, status, evidence })) },
    };
  }
  const doc = {
    '@context': VC_CONTEXT,
    type: ['VerifiableCredential', 'EmconEvidenceReceipt'],
    issuer: did,
    validFrom: new Date().toISOString(),
    credentialSubject: { ...subject, engine: { name: 'EMCON', version: VERSION, server } },
  };
  // Independent timestamp: the server signs only the digest + its clock, never the contents.
  try { doc.evidenceTimestamp = await api('/api/timestamp', { method: 'POST', body: { digest: await receiptDigest(doc) } }); } catch { /* receipt stays self-timestamped */ }
  return signCredential(doc, privateKey, did);
}

// =====================================================================
// Messaging
// =====================================================================
const HANDLERS = {
  // callable from web pages' content scripts
  'ghost:request': ghostRequest,
  'prov:check': async (m, sender) => {
    if (!(await settings()).provenance) return [];
    const results = await Promise.all((m.urls || []).slice(0, 40).map(provCheck));
    const tabId = sender.tab?.id;
    if (tabId != null) {
      const t = (tabImages.get(tabId)?.url === sender.tab.url && tabImages.get(tabId)) || { url: sender.tab.url, counts: {} };
      for (const r of results) if (LABELLED.has(r?.status)) { t.counts[r.status] = (t.counts[r.status] || 0) + 1; bumpStat('photos'); }
      tabImages.set(tabId, t);
    }
    return results;
  },
  'wot:analyze': (m, sender) => wotAnalyze(m.page, sender),
  'privacy:features': privacyFeatures,
  'privacy:consent': (m, sender) => privacyConsent({ state: m.state, how: m.how }, sender),
  'receipt:open': async ({ image }) => { await chrome.tabs.create({ url: chrome.runtime.getURL('pages/receipt.html?img=' + encodeURIComponent(image)) }); return true; },
  // extension pages only
  'ghost:status': ghostStatus,
  'ghost:enroll': ghostEnroll,
  'ghost:refill': refill,
  'ghost:reset-site': ghostResetSite,
  'ghost:approval-info': ({ id }) => { const a = approvals.get(id); if (!a) throw new Error('request expired'); const { resolve, ...info } = a; return info; },
  'ghost:approve': ghostApprove,
  'wot:tab': async ({ tabId }) => (await chrome.storage.session.get('verdict_' + tabId))['verdict_' + tabId] || null,
  'prov:tab': async ({ tabId }) => { const tab = await chrome.tabs.get(tabId).catch(() => null); const t = tabImages.get(tabId); return t && tab?.url === t.url ? t.counts : {}; },
  'stats:week': weekStats,
  'checkout:accept': checkoutAccept,
  'brake:info': brakeInfo,
  'brake:request': brakeRequest,
  'brake:status': brakeStatus,
  'rate:get': rateGet,
  'rate:submit': rateSubmit,
  'qr:contact': qrContact,
  'qr:attest': qrAttest,
  'qr:import': qrImport,
  'qr:list': qrList,
  'qr:remove': async ({ issuer, domain }) => { await local.set('qrAtts', (await qrStore()).filter((a) => !(a.issuer === issuer && a.domain === domain))); trustMapCached.reset(); return qrList(); },
  'account:status': accountStatus,
  'account:pair': accountPair,
  'account:unpair': async () => { await chrome.storage.local.remove('device'); return { connected: false }; },
  'wot:me': async () => ({ did: (await wotIdentity()).did, roots: (await wotState()).roots }),
  'wot:attest': wotAttest,
  'wot:trust': wotTrust,
  'wot:untrust': wotUntrust,
  'chain:message': chainMessage,
  'link:check': linkCheck,
  'privacy:tab': async ({ tabId }) => privacyReport(await tabState(tabId)),
  'privacy:mark': (m, sender) => privacyConsent({ tabId: m.tabId, state: m.state || 'denied', how: 'marked “I said no” in EMCON' }, sender),
  'receipt:create': receiptCreate,
  'settings:get': settings,
  'settings:set': async ({ patch }) => {
    const before = await settings();
    const s = { ...before, ...patch };
    await local.set('settings', s);
    if (s.server !== before.server) for (const c of caches) c.reset();
    await syncGuard();
    return s;
  },
};
const CONTENT_ALLOWED = new Set(['ghost:request', 'prov:check', 'wot:analyze', 'privacy:features', 'privacy:consent', 'receipt:open', 'checkout:accept', 'brake:info', 'brake:request', 'brake:status']);

// First install: show the welcome page once (unpacked reloads don't repeat it).
chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  if (reason !== 'install' || (await local.get('welcomed'))) return;
  await local.set('welcomed', true);
  chrome.tabs.create({ url: chrome.runtime.getURL('pages/welcome.html') });
});

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
