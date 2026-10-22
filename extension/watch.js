// Per-tab observations behind two shields:
//  * Scam Chain Detector: the path that led to a page (link clicks, server redirects,
//    page redirects, tabs opened from other tabs), plus what each step said and asked for.
//  * Privacy Promise Monitor: every third-party request the page makes, every
//    fingerprinting / sensitive feature it touches, and whether that continues after you say no.
//
// Everything is observed locally in the browser; none of it is sent anywhere.

import { trackerFor } from './lib/trackers.js';
import { SHORTENERS, lureFindings, urlsIn } from './lib/signals.js';
import { registrable, sameSite, normDomain } from './lib/domains.js';

const CHAIN_GAP = 10 * 60e3; // a step more than 10 min after the previous one starts a new chain
const MAX_HOPS = 12;
const FRESH = new Set(['typed', 'auto_bookmark', 'generated', 'keyword', 'keyword_generated', 'start_page']);

// ---------- tab state (memory, mirrored to session storage so a sleeping worker loses nothing) ----------
const mem = new Map();
const loading = new Map();
const blank = () => ({ chain: [], navStart: 0, expect: null, privacy: null, message: '' });

export function tabState(tabId) {
  if (mem.has(tabId)) return Promise.resolve(mem.get(tabId));
  if (!loading.has(tabId)) {
    loading.set(tabId, chrome.storage.session.get('tab_' + tabId).then((r) => {
      const s = mem.get(tabId) || r['tab_' + tabId] || blank();
      mem.set(tabId, s);
      loading.delete(tabId);
      return s;
    }));
  }
  return loading.get(tabId);
}

const timers = new Map();
export function persist(tabId) {
  clearTimeout(timers.get(tabId));
  timers.set(tabId, setTimeout(() => {
    const s = mem.get(tabId);
    if (s) chrome.storage.session.set({ ['tab_' + tabId]: s }).catch(() => {});
  }, 400));
}

const stripHash = (u) => u.split('#')[0];
function pushHop(s, url, via, t) {
  if (!/^https?:/.test(url)) return;
  const last = s.chain[s.chain.length - 1];
  if (last && t - last.t > CHAIN_GAP) s.chain = [];
  if (last && stripHash(last.url) === stripHash(url)) return;
  s.chain.push({ url, host: normDomain(new URL(url).hostname), via, t, lure: [], data: [] });
  if (s.chain.length > MAX_HOPS) s.chain.splice(0, s.chain.length - MAX_HOPS);
}

/** Attach what the content script saw on a page to its step in the chain. */
export function recordPageFacts(s, url, lure, data) {
  const hop = [...s.chain].reverse().find((h) => stripHash(h.url) === stripHash(url)) || s.chain[s.chain.length - 1];
  if (hop) { hop.lure = lure; hop.data = data; }
}

// ---------- privacy record ----------
const newPrivacy = (url) => ({ url, host: normDomain(new URL(url).hostname), started: Date.now(), hosts: {}, frames: {}, consent: null, promise: null });

export function featureTotals(p) {
  const t = {};
  for (const fr of Object.values(p.frames)) for (const [f, n] of Object.entries(fr.counts)) t[f] = (t[f] || 0) + n;
  return t;
}

export function markConsent(s, state, how) {
  if (!s.privacy) return;
  s.privacy.consent = { state, how, at: Date.now(), baseline: featureTotals(s.privacy) };
}

// ---------- listeners ----------
export function initWatch() {
  chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
    if (d.frameId !== 0) return;
    (await tabState(d.tabId)).navStart = d.timeStamp;
  });

  chrome.webRequest.onBeforeRedirect.addListener(async (d) => {
    if (d.tabId < 0) return;
    const s = await tabState(d.tabId);
    pushHop(s, d.url, s.expect === d.url ? 'redirect' : 'link', d.timeStamp);
    s.expect = d.redirectUrl;
    persist(d.tabId);
  }, { urls: ['<all_urls>'], types: ['main_frame'] });

  chrome.webNavigation.onCommitted.addListener(async (d) => {
    if (d.frameId !== 0 || !/^https?:/.test(d.url)) return;
    const s = await tabState(d.tabId);
    const q = d.transitionQualifiers || [];
    const fresh = (FRESH.has(d.transitionType) || q.includes('from_address_bar')) && !q.includes('server_redirect') && !q.includes('client_redirect');
    // a typed or bookmarked visit starts a new chain, but keeps redirects of *this* navigation (a typed bit.ly link)
    if (fresh || FRESH.has(d.transitionType)) s.chain = s.chain.filter((h) => h.t >= s.navStart);
    const via = s.expect === d.url || q.includes('server_redirect') ? 'redirect'
      : q.includes('client_redirect') ? 'page redirect'
        : fresh ? 'typed'
          : d.transitionType === 'form_submit' ? 'form' : d.transitionType === 'reload' ? 'reload' : 'link';
    pushHop(s, d.url, via, d.timeStamp);
    s.expect = null;
    persist(d.tabId);
  });

  // links that open a new tab keep the chain of the tab they came from
  chrome.webNavigation.onCreatedNavigationTarget.addListener(async (d) => {
    const src = await tabState(d.sourceTabId);
    const s = await tabState(d.tabId);
    s.chain = src.chain.map((h) => ({ ...h }));
    s.message = src.message;
    s.navStart = d.timeStamp;
    persist(d.tabId);
  });

  chrome.webRequest.onBeforeRequest.addListener((d) => {
    if (d.tabId < 0) return;
    observeRequest(d);
  }, { urls: ['<all_urls>'] });

  chrome.tabs.onRemoved.addListener((tabId) => {
    mem.delete(tabId);
    chrome.storage.session.remove('tab_' + tabId).catch(() => {});
  });
}

async function observeRequest(d) {
  const s = await tabState(d.tabId);
  if (d.type === 'main_frame') {
    if (/^https?:/.test(d.url)) { s.privacy = newPrivacy(d.url); persist(d.tabId); }
    return;
  }
  const p = s.privacy;
  if (!p) return;
  let host;
  try { host = normDomain(new URL(d.url).hostname); } catch { return; }
  if (!host || sameSite(host, p.host)) return; // first-party traffic is not what the promise is about
  const e = (p.hosts[host] ||= { n: 0, afterDenial: 0, tracker: trackerFor(host), first: d.timeStamp, types: [] });
  e.n++;
  if (p.consent?.state === 'denied' && d.timeStamp >= p.consent.at) e.afterDenial++;
  if (!e.types.includes(d.type)) e.types.push(d.type);
  persist(d.tabId);
}

// ---------- reports ----------
export function chainReport(s, currentUrl, currentLure = []) {
  const hops = s.chain.length ? s.chain : [];
  const n = hops.length;
  const lure = [];
  hops.forEach((h, i) => {
    const isCurrent = stripHash(h.url) === stripHash(currentUrl || '');
    for (const l of isCurrent ? currentLure : h.lure || []) lure.push({ ...l, where: isCurrent ? 'this page' : `step ${i + 1} of ${n} (${h.host})` });
  });
  if (!hops.some((h) => stripHash(h.url) === stripHash(currentUrl || ''))) for (const l of currentLure) lure.push({ ...l, where: 'this page' });
  const msgLure = lureFindings(s.message).map((l) => ({ ...l, where: 'the message you pasted' }));
  const msgUrls = urlsIn(s.message);
  const linked = msgUrls.some((u) => { const h = normDomain(new URL(u).hostname); return hops.some((x) => x.host === h); });
  const label = (u) => { const x = new URL(u); return (normDomain(x.hostname) + (x.pathname === '/' ? '' : x.pathname)).slice(0, 48); };
  return {
    hops: hops.map(({ url, host, via }) => ({ url, host, via, label: label(url) })),
    redirects: hops.filter((h) => /redirect/.test(h.via)).length,
    sites: [...new Set(hops.map((h) => registrable(h.host)))],
    shorteners: [...new Set(hops.map((h) => h.host).filter((h) => SHORTENERS.has(h)))],
    lure: [...msgLure, ...lure],
    message: s.message ? { lure: msgLure.length, urls: msgUrls, linked } : null,
  };
}

const FINGERPRINTING = { 'canvas-readback': 'read back canvas pixels', 'gpu-query': 'asked for your exact graphics card', 'audio-fingerprint': 'probed your audio hardware', 'font-probing': 'probed which fonts you have' };
const SENSITIVE = { location: 'asked for your location', 'camera-mic': 'asked for camera or microphone', 'device-list': 'listed your cameras and microphones', 'clipboard-read': 'tried to read your clipboard', notifications: 'asked to send notifications', battery: 'read your battery status', beacon: 'sent background tracking beacons' };

const listHosts = (list) => list.slice(0, 4).map((t) => (t.tracker ? `${t.host} (${t.tracker})` : t.host)).join(', ') + (list.length > 4 ? ` and ${list.length - 4} more` : '');

export function privacyReport(s) {
  const p = s?.privacy;
  if (!p) return null;
  const third = Object.entries(p.hosts).map(([host, e]) => ({ host, ...e })).sort((a, b) => b.n - a.n);
  const trackers = third.filter((t) => t.tracker);
  const totals = featureTotals(p);
  const base = p.consent?.baseline || {};
  const features = Object.entries(totals).filter(([, n]) => n > 0).map(([f, n]) => ({
    f, n, label: FINGERPRINTING[f] || SENSITIVE[f] || f, fingerprinting: !!FINGERPRINTING[f], afterDenial: Math.max(0, n - (base[f] || 0)),
  }));
  const fp = features.filter((x) => x.fingerprinting);
  const declared = p.promise?.tokens || [];
  const denied = p.consent?.state === 'denied';
  const promises = [];

  if (declared.includes('no-third-party-tracking')) {
    promises.push({
      text: 'No third-party tracking', source: 'declared by the site',
      status: trackers.length ? 'broken' : 'kept',
      evidence: trackers.length
        ? `The page promises no third-party tracking, but your browser observed requests to ${trackers.length} tracking domain(s): ${listHosts(trackers)}`
        : `No known tracking domains contacted (${third.length} other third-party domain(s) seen)`,
    });
  }
  if (declared.includes('no-third-parties')) {
    promises.push({ text: 'No third parties at all', source: 'declared by the site', status: third.length ? 'broken' : 'kept', evidence: third.length ? `Requests went to ${third.length} third-party domain(s): ${listHosts(third)}` : 'Only first-party requests observed' });
  }
  if (declared.includes('no-fingerprinting')) {
    promises.push({ text: 'No fingerprinting', source: 'declared by the site', status: fp.length ? 'broken' : 'kept', evidence: fp.length ? `Scripts ${fp.map((x) => `${x.label} (${x.n}×)`).join(', ')}` : 'No fingerprinting APIs used' });
  }
  const afterT = trackers.filter((t) => t.afterDenial > 0);
  const afterFp = fp.filter((x) => x.afterDenial > 0);
  promises.push({
    text: 'Stops tracking after you say no',
    source: declared.includes('respects-consent') ? 'declared by the site, and the legal baseline (GDPR, India DPDP Act)' : 'legal baseline (GDPR, India DPDP Act)',
    status: !denied ? 'untested' : afterT.length || afterFp.length ? 'broken' : 'kept',
    evidence: !denied
      ? "Not tested yet. Say no on the site's cookie banner, or press “I said no” in EMCON, then keep using the page."
      : afterT.length || afterFp.length
        ? `After you said no (${p.consent.how}), the page still contacted ${afterT.length} tracking domain(s)${afterT.length ? ': ' + listHosts(afterT) : ''}${afterFp.length ? `, and scripts ${afterFp.map((x) => x.label).join(', ')}` : ''}`
        : `Since you said no (${p.consent.how}), no tracking domains or fingerprinting were observed`,
  });

  return {
    host: p.host, since: p.started,
    thirdParties: third.slice(0, 40).map(({ host, n, tracker, afterDenial }) => ({ host, n, tracker, afterDenial })),
    thirdPartyCount: third.length, trackerCount: trackers.length,
    features, consent: p.consent && { state: p.consent.state, how: p.consent.how, at: p.consent.at },
    declared, promiseSource: p.promise?.source || null, promises,
  };
}
