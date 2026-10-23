// Every shield on the real internet, with nothing of ours: the live OpenPhish feed, real short
// links, the C2PA standards body's sample photos, a real public image CDN, real news sites, a
// real card form and live phishing pages. Needs an internet connection; results depend on what
// is live today. Phishing pages open in a throwaway headless profile with downloads blocked,
// and nothing is ever typed into them.
//
//   npm run test:real            (HEADED=1 to watch)
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { launchBrowser, waitFor, sleep } from '../tools/browser.mjs';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'emcon-real-'));
process.env.EMCON_DATA = path.join(TMP, 'data');
delete process.env.EMCON_DEMO_SITE;
delete process.env.EMCON_FEED_URL; // the real OpenPhish feed
delete process.env.DATABASE_URL;
const { createApp } = await import('../server/app.js');
const { feedHosts } = await import('../server/wot.js');
const { db } = await import('../server/store.js');
const { dhashOf } = await import('../server/imagehash.js');
const { validateC2pa, trustFromPem } = await import('../extension/lib/c2pa.js');
const server = await createApp();
await new Promise((r) => server.listen(0, r));
const L = `http://localhost:${server.address().port}`;

let jar = '';
async function api(p, { method = 'GET', body, headers = {} } = {}) {
  const r = await fetch(L + p, { method, headers: { 'content-type': 'application/json', origin: L, ...(jar ? { cookie: jar } : {}), ...headers }, body: body && JSON.stringify(body) });
  const c = r.headers.get('set-cookie');
  if (c) jar = c.split(';')[0];
  return { status: r.status, ...(await r.json().catch(() => ({}))) };
}

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log('  ✔', name); } catch (e) { failed++; console.log('  ✖', name, '\n     ', e.message); }
}
const note = (s) => console.log('      ' + s);

const RAW = 'https://raw.githubusercontent.com/c2pa-org/public-testfiles/main/legacy/1.4/image/jpeg/';
const TRUEPIC = RAW + 'truepic-20230212-camera.jpg';
const STRIPPED = `https://images.weserv.nl/?url=${encodeURIComponent(TRUEPIC.replace('https://', ''))}&w=1200&output=jpg`;
const bytesOf = async (u) => new Uint8Array(await (await fetch(u)).arrayBuffer());

console.log('\nServer, on the real internet');
const feed = await waitFor(async () => { const f = await api('/api/wot/feed?limit=12'); return f.updated && f.count > 0 && f; }, { timeout: 60000, what: 'OpenPhish feed' }).catch(() => null);
await test('the live OpenPhish phishing feed is loaded as signed scam reports', () => {
  assert.ok(feed?.count > 20, 'feed loaded');
  note(`${feed.count} live phishing hosts, e.g. ${feed.sample.slice(0, 3).join(', ')}`);
});
await test('a real short link (aka.ms) is followed to where it really lands', async () => {
  const r = await api('/api/link/expand?url=' + encodeURIComponent('https://aka.ms/terminal'));
  assert.ok(r.hops.length >= 2);
  assert.doesNotMatch(new URL(r.final).hostname, /aka\.ms/);
  note(r.hops.map((h) => new URL(h.url).hostname).join(' → '));
});
await test('link-check API: a message with a live phishing link -> scam; a real short link -> no warnings', async () => {
  assert.equal((await api('/api/auth/signup', { method: 'POST', body: { email: `real-test-${Date.now()}@example.com`, password: 'correct horse battery staple 9' } })).status, 200);
  const { key } = await api('/api/me/keys', { method: 'POST', body: { name: 'real-internet test' } });
  const check = (text) => api('/api/v1/check', { method: 'POST', body: { text }, headers: { authorization: 'Bearer ' + key, cookie: '' } });
  const scam = await check(`SBI: Dear customer, your YONO account will be blocked today. Complete your KYC update immediately: https://${feed.sample[0]}/`);
  assert.equal(scam.result.verdict, 'scam');
  note(`${feed.sample[0]}: ${scam.result.reasons.map((x) => x.text).join(' | ').slice(0, 200)}`);
  const ok = await check('https://aka.ms/terminal');
  assert.equal(ok.result.verdict, 'no_warnings');
});

const t = await api('/api/prov/c2pa-trust');
const trust = trustFromPem(t.anchors, t.allowed);
await test('Content Credentials: the C2PA sample files get the official verifier\'s verdicts', async () => {
  const v = async (f) => validateC2pa(await bytesOf(RAW + f), trust);
  const tp = await v('truepic-20230212-camera.jpg');
  assert.deepEqual([tp.signature, tp.assertions, tp.binding, tp.trust], ['valid', 'valid', 'valid', 'anchored']);
  assert.equal(tp.signerOrg, 'Truepic');
  assert.equal((await v('adobe-20220124-CA.jpg')).trust, 'unknown');
  assert.equal((await v('adobe-20220124-XCA.jpg')).binding, 'mismatch');
  assert.equal((await v('adobe-20220124-E-sig-CA.jpg')).signature, 'invalid');
  assert.equal((await v('adobe-20220124-E-uri-CA.jpg')).assertions, 'mismatch');
});
await test('remembering the Truepic photo lets a copy stripped by a public CDN be recognised', async () => {
  const r = await api('/api/prov/c2pa', { method: 'POST', body: { url: TRUEPIC } });
  assert.equal(r.entry.issuerName, 'Truepic');
  const m = await api('/api/prov/lookup?dhash=' + dhashOf(await bytesOf(STRIPPED)));
  assert.equal(m.match?.issuerName, 'Truepic');
  note(`stripped copy matches at distance ${m.distance}/64`);
});

console.log('\nThe extension, on real websites');
const browser = await launchBrowser({ profile: path.join(TMP, 'profile'), headless: !process.env.HEADED, fresh: true });
await browser.send('Browser.setDownloadBehavior', { behavior: 'deny' });
const extPage = await browser.open(`chrome-extension://${browser.extensionId}/pages/popup.html`);
await waitFor(() => extPage.eval('!!chrome.runtime?.id'), { what: 'extension page' });
const ext = async (msg) => { const r = await extPage.eval(`new Promise((r) => chrome.runtime.sendMessage(${JSON.stringify(msg)}, r))`); if (r?.error) throw new Error(r.error); return r?.result; };
await ext({ type: 'settings:set', patch: { server: L } });
const tabIdOf = (targetUrl) => extPage.eval(`chrome.tabs.query({}).then((t) => t.find((x) => (x.url || x.pendingUrl || '').startsWith(${JSON.stringify(targetUrl.slice(0, 50))}))?.id)`);
async function ui(page) {
  const { root } = await page.send('DOM.getDocument', { depth: -1, pierce: true });
  const out = { badges: [], wall: null, bar: null, brake: false };
  const text = (n) => (n.nodeType === 3 ? n.nodeValue : '') + [...(n.children || []), ...(n.shadowRoots || [])].map(text).join('');
  // only EMCON's own UI, inside its shadow root: pages have .bar and .badge classes of their own
  const walk = (n, ours) => {
    const a = n.attributes || [];
    const cls = ours && a.includes('class') ? a[a.indexOf('class') + 1].split(/\s+/) : [];
    if (cls.includes('badge')) out.badges.push(text(n));
    if (cls.includes('wall')) out.wall = text(n);
    if (cls.includes('bar')) out.bar = text(n);
    if (cls.includes('brake')) out.brake = true;
    (n.children || []).forEach((c) => walk(c, ours));
    (n.shadowRoots || []).forEach((c) => walk(c, true));
  };
  walk(root, false);
  return out;
}
const close = (p) => browser.send('Target.closeTarget', { targetId: p.targetId }).catch(() => {});
const badgeOn = async (url) => {
  const p = await browser.open(url);
  try { return (await waitFor(async () => (await ui(p)).badges[0], { timeout: 45000, what: 'photo label' })); } finally { await close(p); }
};

await test('photo labels on the real files: Verified, unknown signer, Altered, Forged, Recovered', async () => {
  const got = {
    truepic: await badgeOn(TRUEPIC), ca: await badgeOn(RAW + 'adobe-20220124-CA.jpg'), xca: await badgeOn(RAW + 'adobe-20220124-XCA.jpg'),
    esig: await badgeOn(RAW + 'adobe-20220124-E-sig-CA.jpg'), stripped: await badgeOn(STRIPPED),
  };
  note(Object.values(got).join(' | '));
  assert.equal(got.truepic, 'Verified · Truepic');
  assert.equal(got.ca, 'Content Credentials · unknown signer');
  assert.equal(got.xca, 'Altered after signing');
  assert.equal(got.esig, 'Forged provenance');
  assert.equal(got.stripped, 'Recovered · Truepic');
});

await test('Global Privacy Control reaches real servers (httpbin.org echoes Sec-Gpc: 1)', async () => {
  const p = await browser.open('https://httpbin.org/headers');
  const body = await waitFor(() => p.eval('document.body?.innerText'), { what: 'httpbin' });
  await close(p);
  assert.match(body, /"Sec-Gpc": "1"/i);
});

await test('anti-fingerprinting: the canvas signature browserleaks.com computes changes on every load', async () => {
  const sigs = [];
  for (let i = 0; i < 2; i++) {
    const p = await browser.open('https://browserleaks.com/canvas');
    sigs.push(await waitFor(async () => /Signature\s+([0-9A-F]{32})/.exec(await p.eval("location.hostname === 'browserleaks.com' ? document.body.innerText : ''"))?.[1], { timeout: 30000, what: 'browserleaks signature' }));
    await close(p);
  }
  note(sigs.join(' then '));
  assert.notEqual(sigs[0], sigs[1]);
});

await test('privacy monitor on timesofindia.indiatimes.com names trackers that ignore the GPC signal', async () => {
  const url = 'https://timesofindia.indiatimes.com/';
  const p = await browser.open(url);
  await sleep(20000);
  const r = await ext({ type: 'privacy:tab', tabId: await tabIdOf(url) });
  await close(p);
  const gpc = r.promises.find((x) => /signal/.test(x.text));
  assert.ok(r.trackerCount > 0);
  assert.equal(gpc.status, 'broken');
  note(`${r.trackerCount} tracking domains, e.g. ${r.thirdParties.filter((x) => x.tracker).slice(0, 4).map((x) => x.host).join(', ')}`);
});

await test('scam chain: a real short link (aka.ms) shows up as a step of how you got to the page', async () => {
  const p = await browser.open('https://aka.ms/terminal');
  await sleep(9000);
  const landed = await p.eval('location.href');
  const v = await ext({ type: 'wot:tab', tabId: await tabIdOf(landed) });
  await close(p);
  assert.ok(v.chain.some((h) => /aka\.ms/.test(JSON.stringify(h))), 'aka.ms in the chain');
  assert.notEqual(v.level, 'danger');
  note(`landed on ${new URL(landed).hostname}, chain of ${v.chain.length}`);
});

const scriptsCheck = async (tabId) => (await ext({ type: 'wot:tab', tabId }))?.checks?.find((c) => c.id === 'scripts');
await test('checkout alarm on a real card form (W3Schools): quiet on the first visit and on a normal return visit', async () => {
  const url = 'https://www.w3schools.com/howto/howto_css_checkout_form.asp';
  const p = await browser.open(url);
  const tabId = await waitFor(() => tabIdOf(url), { what: 'tab' });
  const first = await waitFor(() => scriptsCheck(tabId), { timeout: 30000, what: 'payment page scripts' });
  assert.equal(first.status, 'note');
  await sleep(20000); // late ad scripts join the baseline of the first visit
  assert.equal((await scriptsCheck(tabId)).status, 'note', 'scripts loading late on the first visit are learned, not alarmed');
  assert.equal((await ui(p)).bar, null);
  await close(p);
  const again = await browser.open(url);
  const t2 = await waitFor(() => tabIdOf(url), { what: 'tab' });
  await sleep(20000);
  const c = await scriptsCheck(t2);
  note(`return visit: ${c.status}: ${c.detail.slice(0, 120)}`);
  assert.notEqual(c.status, 'found');
  // a skimmer is injected into the page, as Magecart does on real shops
  await again.eval("document.head.append(Object.assign(document.createElement('script'), { src: 'https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js' }))");
  const bar = await waitFor(async () => { await again.eval("document.querySelector('#ccnum')?.focus()"); return (await ui(again)).bar; }, { timeout: 20000, what: 'alarm bar' });
  await close(again);
  assert.match(bar, /cdn\.jsdelivr\.net/);
  note(bar.replace(/\s+/g, ' ').slice(0, 160));
});

await test('a real Stripe checkout (EFF donations) counts as a payment page through its card iframe', async () => {
  const url = 'https://supporters.eff.org/donate/join-eff-4';
  const p = await browser.open(url);
  const tabId = await waitFor(() => tabIdOf(url), { what: 'tab' });
  const c = await waitFor(() => scriptsCheck(tabId), { timeout: 40000, what: 'payment page scripts' });
  await close(p);
  assert.equal(c.status, 'note');
  note(c.detail.slice(0, 110));
});

await test('crowdsourced rating for amazon.in is signed, stored and read back', async () => {
  const before = await ext({ type: 'rate:get', domain: 'amazon.in' });
  const r = await ext({ type: 'rate:submit', domain: 'amazon.in', stars: 4, tags: before.tags.slice(0, 1) });
  assert.equal(r.mine.stars, 4);
});

await test('live phishing pages from the feed are blocked before anything can be typed', async () => {
  const text = await (await fetch('https://openphish.com/feed.txt')).text();
  // only pages the server's copy of the feed lists (the feed changes by the minute)
  const known = new Set(db.wot.attestations.filter((a) => /OpenPhish/.test(a.vc.credentialSubject.note)).map((a) => a.domain));
  const hosts = new Set(feedHosts(text).filter((h) => known.has(h)));
  const urls = [];
  for (const line of text.split('\n')) {
    try { const u = new URL(line.trim()); if (hosts.has(u.hostname.replace(/^www\./, '')) && !urls.some((x) => new URL(x).hostname === u.hostname)) urls.push(u.href); } catch { /* skip */ }
  }
  let blocked = 0, tried = 0, brakes = 0;
  // stop once 3 are blocked and one of them asked for payment details (or after 16 tries)
  for (const u of urls.slice(0, 16)) {
    if (blocked >= 3 && brakes >= 1) break;
    tried++;
    const p = await browser.open(u);
    const seen = await waitFor(async () => (await ui(p)).wall && (await ui(p)), { timeout: 25000, what: 'block page' }).catch(() => null);
    const host = new URL(u).hostname.replace(/\./g, '[.]');
    if (seen) { blocked++; if (seen.brake) brakes++; note(`blocked ${host}${seen.brake ? ' (asks for payment details: payment brake on)' : ''}`); }
    else {
      const v = await ext({ type: 'wot:tab', tabId: await tabIdOf(u) }).catch(() => null);
      note(`not blocked: ${host} (${await p.eval('document.title').catch(() => 'no page')}; ${v ? `${v.level}, risk ${v.risk}` : 'not analysed'})`);
    }
    await close(p);
  }
  assert.ok(blocked >= 1, `${blocked} of ${tried} blocked`);
  note(`${blocked} of ${tried} live phishing pages blocked; ${brakes} had the payment brake`);
});

await browser.close();
server.close();
console.log(`\n${passed} passed${failed ? `, ${failed} failed` : ''}`);
process.exit(failed ? 1 : 0);
