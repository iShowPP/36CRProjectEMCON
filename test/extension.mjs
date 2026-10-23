// Browser end-to-end test: loads the real extension into Chrome (headless by default,
// HEADED=1 to watch), points it at a throwaway server, and drives all four shields
// through the actual UI: content script, service worker, consent window, badges, block page.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { launchBrowser, waitFor, sleep } from '../tools/browser.mjs';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'emcon-browser-test-'));
process.env.EMCON_DATA = path.join(TMP, 'data');
process.env.EMCON_DEMO_SITE = '1'; // the made-up test site in test/site (never served in production)
// Stand-in for the live OpenPhish feed; *.test hostnames are mapped to this machine below.
process.env.EMCON_FEED_URL = 'data:text/plain,' + encodeURIComponent('https://live-scam-shop.test/login\n');
const { createApp } = await import('../server/app.js');
const server = await createApp();
await new Promise((r) => server.listen(0, r));
const PORT = server.address().port;
const L = `http://localhost:${PORT}`;   // "official" origin
const IP = `http://127.0.0.1:${PORT}`;  // plays a different company / the phishing host

const browser = await launchBrowser({
  profile: path.join(TMP, 'profile'), headless: !process.env.HEADED, fresh: true,
  extraArgs: ['--host-resolver-rules=MAP *.test 127.0.0.1'], // real-looking hostnames, served by the local test server
});
console.log(`\n  browser: ${browser.exe}\n  extension id: ${browser.extensionId}\n  server: ${L}`);

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log('  ✔', name); }
  catch (e) { failed++; console.log('  ✖', name, '\n     ', e.message); }
}

// An extension page gives us a context that can message the service worker.
const extPage = await browser.open(`chrome-extension://${browser.extensionId}/pages/popup.html`);
const ext = (msg) => extPage.eval(`new Promise((r) => chrome.runtime.sendMessage(${JSON.stringify(msg)}, r))`);
await waitFor(() => extPage.eval('!!chrome.runtime?.id'), { what: 'extension page' });
await ext({ type: 'settings:set', patch: { server: L } });

console.log('\nInstall experience');
await test('welcome page opens on install and connects to the server', async () => {
  const t = await waitFor(async () => (await browser.targets()).find((x) => x.url.endsWith('/pages/welcome.html')), { what: 'welcome tab' });
  const w = await browser.attach(t.targetId);
  await waitFor(() => w.eval("!!document.querySelector('#check') && document.querySelector('#status').textContent !== 'Checking…'"), { what: 'welcome page' });
  await w.eval(`document.querySelector('#server').value = ${JSON.stringify(L)}; document.querySelector('#check').click()`);
  const status = await waitFor(() => w.eval("document.querySelector('#status').textContent.includes('Connected') && document.querySelector('#status').textContent"), { what: 'server check' });
  assert.match(status, /EMCON SecOps Collective/);
  assert.equal(await w.eval("document.querySelector('#t-wot').textContent"), 'active now');
});

const ready = (page) => waitFor(() => page.eval("document.documentElement.getAttribute('data-emcon') === '1'"), { what: 'content script' });

// The extension renders into a *closed* shadow root; CDP's pierce mode can still read it.
async function extensionUi(page) {
  const { root } = await page.send('DOM.getDocument', { depth: -1, pierce: true });
  const out = { badges: [], wall: null, bar: null };
  const text = (n) => (n.nodeType === 3 ? n.nodeValue : '') + [...(n.children || []), ...(n.shadowRoots || [])].map(text).join('');
  const walk = (n) => {
    const a = n.attributes || [];
    const cls = a[a.indexOf('class') + 1] || '';
    if (a.includes('class')) {
      if (/\bbadge\b/.test(cls)) out.badges.push(text(n));
      if (/\bwall\b/.test(cls)) out.wall = text(n);
      if (/\bbar\b/.test(cls)) out.bar = text(n);
    }
    [...(n.children || []), ...(n.shadowRoots || [])].forEach(walk);
  };
  walk(root);
  return out;
}

async function approveNext({ pin, decline = false } = {}) {
  const t = await waitFor(async () => (await browser.targets()).find((x) => x.url.includes('/pages/approve.html')), { what: 'consent window' });
  const ap = await browser.attach(t.targetId);
  await waitFor(() => ap.eval("document.querySelector('#origin').textContent"), { what: 'consent details' });
  const shown = await ap.eval("document.querySelector('#origin').textContent + ' | ' + document.querySelector('#shares').innerText");
  await ap.eval(decline ? "document.querySelector('#no').click()" : `document.querySelector('#pin').value = ${JSON.stringify(pin)}; document.querySelector('#ok').click()`);
  return shown;
}

async function ghostSignIn(page, { over18 = true, pin = '2468', decline = false } = {}) {
  await page.eval(`document.querySelector('#over18').checked = ${over18}; document.querySelector('#result').classList.add('hidden'); document.querySelector('#go').click()`);
  const shown = await approveNext({ pin, decline });
  const outcome = await waitFor(() => page.eval(`(() => {
    const r = document.querySelector('#result:not(.hidden) h2'); if (r) return { ok: true, text: r.textContent };
    const s = document.querySelector('#status').textContent; if (s.startsWith('Error:')) return { ok: false, text: s };
  })()`), { what: 'sign-in result' });
  return { ...outcome, shown };
}

console.log('\nShield 1 · Ghost Engine');
let handleA;
await test('enrolment mints blind tokens through the issuer', async () => {
  const r = await ext({ type: 'ghost:enroll', dob: '1995-04-02', pin: '2468' });
  assert.ok(!r.error, r.error);
  assert.deepEqual(r.result.tokens, { human: 5, 'human+18': 5 });
});
const rpA = await browser.open(L + '/rp.html');
await ready(rpA);
await test('first sign-in: consent window → new 18+ account, no personal data', async () => {
  const r = await ghostSignIn(rpA);
  assert.ok(r.ok, r.text);
  assert.match(r.text, /Account created/);
  assert.match(r.shown, /over 18/);
  handleA = r.text.split(', ').pop();
  const known = await rpA.eval("document.querySelector('#result pre').textContent");
  assert.match(known, /"email": null/);
});
await test('second sign-in on the same site recognises you (no token spent)', async () => {
  const before = (await ext({ type: 'ghost:status' })).result.tokens['human+18'];
  const r = await ghostSignIn(rpA);
  assert.match(r.text, /Welcome back/);
  assert.equal((await ext({ type: 'ghost:status' })).result.tokens['human+18'], before);
});
await test('wrong PIN in the consent window is refused', async () => {
  await rpA.eval("document.querySelector('#go').click()");
  const t = await waitFor(async () => (await browser.targets()).find((x) => x.url.includes('/pages/approve.html')), { what: 'consent window' });
  const ap = await browser.attach(t.targetId);
  await waitFor(() => ap.eval("document.querySelector('#origin').textContent"));
  await ap.eval("document.querySelector('#pin').value = '0000'; document.querySelector('#ok').click()");
  await waitFor(() => ap.eval("document.querySelector('#msg').textContent.includes('wrong PIN')"), { what: 'wrong-PIN message' });
  await ap.eval("document.querySelector('#no').click()");
  await waitFor(() => rpA.eval("document.querySelector('#status').textContent.includes('declined')"), { what: 'declined status' });
});
await test('a different site gets a different, unlinkable pseudonym', async () => {
  const rpB = await browser.open(IP + '/rp.html');
  await ready(rpB);
  const r = await ghostSignIn(rpB);
  assert.match(r.text, /Account created/);
  const handleB = r.text.split(', ').pop();
  assert.notEqual(handleB, handleA);
});

console.log('\nShield 1b · Anti-fingerprinting + Global Privacy Control');
// A bare page whose first script reads the canvas while the HTML is still parsing, as real
// fingerprinting scripts do (browserleaks.com, FingerprintJS). It also records its request headers.
const DRAW = `function (d) { const c = d.createElement('canvas'); c.width = 220; c.height = 50; const g = c.getContext('2d');
  g.font = '18px Arial'; g.fillStyle = '#f60'; g.fillRect(0, 0, 130, 40); g.fillStyle = '#069'; g.fillText('EMCON fingerprint', 4, 30); return c.toDataURL(); }`;
let probeHeaders = {};
const probe = http.createServer((req, res) => {
  probeHeaders = req.headers;
  res.setHeader('content-type', 'text/html');
  res.end(`<!doctype html><title>probe</title><script>window.__early = (${DRAW})(document);</script><p>probe</p>`);
});
await new Promise((r) => probe.listen(0, '127.0.0.1', r));
const PROBE = `http://127.0.0.1:${probe.address().port}/`;
const early = async () => { const p = await browser.open(PROBE); return { p, v: await waitFor(() => p.eval('window.__early'), { what: 'probe page' }) }; };
let first;
await test('page scripts see a noised canvas from their very first line, and a fresh iframe is no way around it', async () => {
  const { p, v } = await early();
  first = v;
  assert.equal(await p.eval(`(${DRAW})(document)`), v, 'reading twice on one page must match');
  const inFrame = await p.eval(`(() => { const f = document.createElement('iframe'); document.body.append(f); return (${DRAW})(f.contentWindow.document); })()`);
  await ext({ type: 'settings:set', patch: { farbleExceptions: ['127.0.0.1'] } });
  const real = (await early()).v;
  await ext({ type: 'settings:set', patch: { farbleExceptions: [] } });
  assert.notEqual(v, real, 'the page must not see the real canvas');
  assert.notEqual(inFrame, real, 'a fresh iframe must not expose the real canvas');
});
await test('every visit looks like a different device, and the wrappers look native', async () => {
  const { p, v } = await early();
  assert.notEqual(v, first, 'a new visit must get new noise');
  assert.equal(await p.eval('HTMLCanvasElement.prototype.toDataURL.toString()'), 'function toDataURL() { [native code] }');
  assert.equal(await p.eval('Function.prototype.toString.toString()'), 'function toString() { [native code] }');
  assert.equal(await p.eval('"prototype" in HTMLCanvasElement.prototype.toDataURL'), false);
});
await test('Global Privacy Control reaches the site: Sec-GPC header and navigator.globalPrivacyControl', async () => {
  const { p } = await early();
  assert.equal(probeHeaders['sec-gpc'], '1');
  assert.equal(await p.eval('navigator.globalPrivacyControl'), true);
});

console.log('\nShield 2 · Provenance badges');
await test('studio builds the five-post demo feed', async () => {
  const s = await browser.open(L + '/sign.html');
  await waitFor(() => s.eval("document.querySelector('#signer').options.length > 0"), { what: 'signer list' });
  await s.eval("document.querySelector('#sample').click()");
  await waitFor(() => s.eval("!document.querySelector('#demo').disabled"), { what: 'sample image' });
  await s.eval("document.querySelector('#demo').click()");
  await waitFor(() => s.eval("document.querySelector('#out').textContent.includes('Feed built')"), { timeout: 30000, what: 'feed build' });
});
await test('feed shows verified / altered / recovered / unknown-signer badges and none on the unsigned photo', async () => {
  const f = await browser.open(L + '/feed.html');
  const ui = await waitFor(async () => { const u = await extensionUi(f); return u.badges.length >= 4 && u; }, { timeout: 25000, what: 'four badges' });
  await sleep(1500);
  const { badges } = await extensionUi(f);
  console.log('      badges:', badges.join(' | '));
  assert.equal(badges.length, 4, 'exactly four images carry a badge');
  assert.ok(badges.some((b) => b.startsWith('Verified · Kestrel Daily News')));
  assert.ok(badges.some((b) => b.startsWith('Altered after signing')));
  assert.ok(badges.some((b) => b.startsWith('Recovered · Kestrel Daily News')));
  assert.ok(badges.some((b) => b.startsWith('Signed · unknown signer')));
  void ui;
});

console.log('\nShield 3 · Honey-Vault (UI)');
await test('payment to a scam-flagged payee is held for guardians', async () => {
  const v = await browser.open(L + '/vault.html');
  await waitFor(() => v.eval("document.querySelector('#guardianLinks').textContent.length > 0"), { what: 'vault page script' });
  await v.eval("document.querySelector('#pin').value = '1234'; document.querySelector('#doLogin').click()");
  await waitFor(() => v.eval("document.querySelector('#payee').options.length > 0"), { what: 'vault login' });
  await v.eval("document.querySelector('#payee').value = 'p3'; document.querySelector('#amount').value = '2500'; document.querySelector('#tpin').value = '1234'; document.querySelector('#send').click()");
  const msg = await waitFor(() => v.eval("document.querySelector('#sendMsg').textContent"), { what: 'transfer result' });
  assert.match(msg, /guardian approvals/);
});

console.log('\nShield 4 · Web of Trust & clone detection');
await test('phishing clone on 127.0.0.1 is blocked with explainable reasons', async () => {
  const p = await browser.open(IP + '/phish-login.html');
  const ui = await waitFor(async () => (await extensionUi(p)).wall && (await extensionUi(p)), { timeout: 20000, what: 'block page' });
  console.log('      ' + ui.wall.replace(/\s+/g, ' ').slice(0, 260) + '…');
  assert.match(ui.wall, /blocked this page/);
  assert.match(ui.wall, /layout matches Kestrel Bank/);
  assert.match(ui.wall, /raw IP address/);
  assert.match(ui.wall, /scam by 1 source/);
});
await test('the real bank login on its official domain gets no warning', async () => {
  const p = await browser.open(L + '/bank-login.html');
  await ready(p);
  await sleep(3500);
  const ui = await extensionUi(p);
  assert.equal(ui.wall, null);
  assert.equal(ui.bar, null);
});
await test('a site listed in the live phishing feed is blocked', async () => {
  const p = await browser.open(`http://live-scam-shop.test:${PORT}/feed.html`);
  const ui = await waitFor(async () => (await extensionUi(p)).wall && (await extensionUi(p)), { timeout: 20000, what: 'block page' });
  assert.match(ui.wall, /scam by 1 source/);
});
await test('a look-alike address (paypa1) gets a warning', async () => {
  const p = await browser.open(`http://paypa1-secure.test:${PORT}/rp.html`);
  const ui = await waitFor(async () => (await extensionUi(p)).bar && (await extensionUi(p)), { timeout: 20000, what: 'warning bar' });
  console.log('      ' + ui.bar.replace(/\s+/g, ' ').slice(0, 160));
  assert.match(ui.bar, /look-alike characters \("paypa1"\)/);
  assert.match(ui.bar, /not an official PayPal domain/);
});
await test('you can publish your own signed attestation and DID', async () => {
  const me = await ext({ type: 'wot:me' });
  assert.match(me.result.did, /^did:key:z6Mk/);
  assert.equal(me.result.roots[0].label, 'EMCON SecOps Collective (demo)');
  const r = await ext({ type: 'wot:attest', domain: 'shop.test', verdict: 'trusted', transacted: true });
  assert.equal(r.result, true, r.error);
});

const tabIdFor = async (prefix) => {
  const tabs = await extPage.eval('new Promise((r) => chrome.tabs.query({}, (t) => r(t.map((x) => ({ id: x.id, url: x.url })))))');
  return tabs.find((t) => t.url?.startsWith(prefix))?.id;
};

console.log('\nScam chain detector');
await test('prize SMS → 2 redirects → fake claim page is blocked, with the whole chain explained', async () => {
  const p = await browser.open(L + '/sms.html');
  await ready(p);
  await sleep(1500); // let EMCON record the message page as step 1
  await p.eval("document.querySelector('#sms-link').click()");
  const ui = await waitFor(async () => { const u = await extensionUi(p); return u.wall && u; }, { timeout: 25000, what: 'block page on the claim page' });
  console.log('      ' + ui.wall.replace(/\s+/g, ' ').slice(0, 420) + '…');
  assert.match(ui.wall, /Scam chain/);
  assert.match(ui.wall, /2 automatic redirect/);
  assert.match(ui.wall, /card number/);
  assert.match(ui.wall, /QuickKart/);
  assert.match(ui.wall, /localhost\/s\/qk50/);
});
await test('a pasted message joins the chain (and stays local)', async () => {
  const tabId = await tabIdFor(L + '/claim.html');
  const r = await ext({ type: 'chain:message', tabId, text: 'Your parcel is held at customs. Pay the customs fee here: http://localhost/s/qk50' });
  assert.ok(!r.error, r.error);
  const msg = r.result.checks.find((c) => c.id === 'message');
  assert.equal(msg.status, 'found');
  assert.match(msg.detail, /leads into this chain/);
});

console.log('\nPrivacy promise monitor');
await test('newspaper breaks its declared promise, before and after "Reject all"', async () => {
  const p = await browser.open(L + '/news.html');
  await ready(p);
  await sleep(1000);
  await p.eval("document.querySelector('#reject').click()");
  await sleep(2500);
  const r = (await ext({ type: 'privacy:tab', tabId: await tabIdFor(L + '/news.html') })).result;
  const by = Object.fromEntries(r.promises.map((x) => [x.text, x]));
  console.log('      ' + by['Stops tracking after you say no'].evidence);
  assert.equal(by['No third-party tracking'].status, 'broken');
  assert.equal(by['Stops tracking after you say no'].status, 'broken');
  assert.match(by['Stops tracking after you say no'].evidence, /Reject all/);
  assert.ok(r.thirdParties.some((t) => t.host === 'collect.adnetwork-demo.example' && t.afterDenial >= 1), 'tracker contacted after denial');
  assert.ok(r.features.some((f) => f.f === 'canvas-readback' && f.afterDenial > 0), 'canvas fingerprinting after denial');
  assert.equal(by['Honours your “do not sell or share” signal'].status, 'broken', 'trackers loaded despite GPC');
});
await test('a page that stops after you say no keeps the baseline promise', async () => {
  const p = await browser.open(L + '/vault.html');
  await ready(p);
  const tabId = await tabIdFor(L + '/vault.html');
  await ext({ type: 'privacy:mark', tabId, state: 'denied' });
  await sleep(1500);
  const r = (await ext({ type: 'privacy:tab', tabId })).result;
  assert.equal(r.promises.find((x) => x.text === 'Stops tracking after you say no').status, 'kept');
  assert.equal(r.trackerCount, 0);
  assert.equal(r.promises.find((x) => x.text === 'Honours your “do not sell or share” signal').status, 'kept');
});

console.log('\nEvidence receipts');
const { verifyReceipt } = await import('../extension/lib/receipt.js');
const tsDid = (await (await fetch(L + '/api/timestamp/key')).json()).did;
await test('website receipt is signed, server-timestamped and verifiable by anyone; tampering is caught', async () => {
  const r = await ext({ type: 'receipt:create', tabId: await tabIdFor(IP + '/phish-login.html') });
  assert.ok(!r.error, r.error);
  const vc = r.result;
  const v = await verifyReceipt(vc, { timestampDid: tsDid });
  assert.equal(v.signature, true);
  assert.equal(v.timestamp.status, 'valid');
  const statuses = new Set(vc.credentialSubject.checks.map((c) => c.status));
  assert.ok(statuses.has('found') && statuses.has('na'), 'found + not-applicable rows recorded');
  assert.ok(vc.credentialSubject.checks.some((c) => /raw IP address/.test(c.detail)));
  const bad = structuredClone(vc);
  bad.credentialSubject.verdict.risk = 0;
  assert.equal((await verifyReceipt(bad, { timestampDid: tsDid })).signature, false);
});
await test('“Check a link”: a pasted SMS is followed through its redirects without opening it, and gets a receipt', async () => {
  const sms = `Congratulations! You have won a QuickKart prize. Claim within 24 hours: ${L}/s/qk50`;
  const r = await ext({ type: 'link:check', text: sms });
  assert.ok(!r.error, r.error);
  const v = r.result;
  const by = Object.fromEntries(v.checks.map((c) => [c.id, c]));
  console.log(`      ${v.level} · risk ${v.risk} · ${v.checks.filter((c) => c.status === 'found').map((c) => c.label).join(' · ')}`);
  assert.equal(new URL(v.url).pathname, '/claim.html', 'judged by where the link lands');
  assert.equal(by.message?.status, 'found', 'prize wording in the pasted message');
  assert.ok(v.chain.length >= 3 && v.chain.filter((h) => /redirect/.test(h.via)).length >= 2, 'both redirects shown');
  assert.notEqual(v.level, 'ok');
  const rc = await ext({ type: 'receipt:create', checkId: v.checkId });
  assert.ok(!rc.error, rc.error);
  assert.equal(rc.result.credentialSubject.kind, 'link');
  assert.equal((await verifyReceipt(rc.result, { timestampDid: tsDid })).signature, true);
});
await test('image receipt explains why a doctored photo is "altered"', async () => {
  const feed = await (await fetch(L + '/api/prov/feed')).json();
  const r = await ext({ type: 'receipt:create', image: L + feed.find((f) => f.kind === 'tampered').url });
  assert.ok(!r.error, r.error);
  const rows = r.result.credentialSubject.checks;
  assert.equal(rows.find((x) => x.label === 'Signature').status, 'good');
  assert.equal(rows.find((x) => x.label === 'Pixels unchanged since signing').status, 'found');
  assert.equal((await verifyReceipt(r.result, { timestampDid: tsDid })).timestamp.status, 'valid');
});
await test('receipt page renders the evidence inside the extension', async () => {
  const tabId = await tabIdFor(IP + '/phish-login.html');
  const pg = await browser.open(`chrome-extension://${browser.extensionId}/pages/receipt.html?tab=${tabId}`);
  const text = await waitFor(() => pg.eval("document.querySelector('#dl') && document.body.innerText"), { timeout: 20000, what: 'receipt page' });
  assert.match(text, /Very likely a scam/);
  assert.match(text, /signature valid/);
  assert.match(text, /countersigned by the EMCON server/);
});

console.log('\nTrust by QR code + community ratings');
const qrlib = await import('../extension/lib/qrtrust.js');
const ut = await import('../extension/lib/util.js');
const ashaKey = await ut.ed25519FromSeed(ut.randomBytes(32));
const asha = { privateKey: ashaKey.privateKey, did: ut.didKeyFromPub(ashaKey.pub) };
const QR_SITE = `http://qrshop.test:${PORT}`;
await test('a vouch from a stranger is refused; after scanning their contact code it counts in the site check', async () => {
  const vouch = qrlib.encodeQr(await qrlib.makeAttestation(asha, 'qrshop.test', 'safe'));
  const refused = await ext({ type: 'qr:import', text: vouch });
  assert.match(refused.error, /not in your contacts/);
  const contact = (await ext({ type: 'qr:import', text: qrlib.encodeQr(await qrlib.makeContact(asha, 'Asha')) })).result;
  assert.equal(contact.kind, 'contact');
  assert.equal(contact.nickname, 'Asha');
  await ext({ type: 'wot:trust', did: contact.did, label: 'Asha', weight: 1, publish: false });
  const ok = (await ext({ type: 'qr:import', text: vouch })).result;
  assert.equal(ok.from, 'Asha');
  assert.equal(ok.stored, true);
  const p = await browser.open(QR_SITE + '/terms');
  await ready(p);
  const id = await tabIdFor(QR_SITE);
  const v = await waitFor(async () => (await ext({ type: 'wot:tab', tabId: id })).result, { what: 'verdict' });
  const rep = v.checks.find((c) => c.id === 'reports');
  assert.equal(rep.status, 'good');
  assert.match(rep.detail, /Asha/);
});
await test('a QR code with one character changed is rejected', async () => {
  const text = qrlib.encodeQr(await qrlib.makeAttestation(asha, 'qrshop.test', 'scam'));
  const i = text.length - 12;
  const r = await ext({ type: 'qr:import', text: text.slice(0, i) + (text[i] === 'A' ? 'B' : 'A') + text.slice(i + 1) });
  assert.ok(r.error, 'tampered code must fail');
});
await test('the QR page draws a scannable contact code', async () => {
  const pg = await browser.open(`chrome-extension://${browser.extensionId}/pages/qr.html`);
  await waitFor(() => pg.eval('typeof window.qrcode === "function" && typeof window.jsQR === "function"'), { what: 'QR libraries' });
  await pg.eval("document.querySelector('#nick').value = 'Priya'; document.querySelector('#mkContact').click()");
  const text = await waitFor(() => pg.eval("document.querySelector('#contactOut .payload')?.textContent"), { what: 'contact code' });
  // read it back with the scanner from the rendered SVG
  const decoded = await pg.eval(`new Promise((res) => { const img = new Image(); img.onload = () => { const c = document.createElement('canvas'); c.width = c.height = 400; const g = c.getContext('2d'); g.fillStyle = '#fff'; g.fillRect(0, 0, 400, 400); g.drawImage(img, 0, 0, 400, 400); res(window.jsQR(g.getImageData(0, 0, 400, 400).data, 400, 400)?.data); }; img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(document.querySelector('.qrbox svg').outerHTML); })`);
  assert.equal(decoded, text, 'the drawn QR scans back to the same text');
});
await test('rating a site signs it, verifies you as a person with one Ghost token, and shows in the check', async () => {
  const r = (await ext({ type: 'rate:submit', domain: 'qrshop.test', stars: 5, tags: ['good support'] })).result;
  assert.equal(r.raterVerified, true);
  assert.equal(r.verified.count, 1);
  assert.equal(r.verified.avg, 5);
  assert.equal(r.mine.stars, 5);
});

console.log('\nCheckout script-change alarm');
const verdictOn = async (prefix) => { const id = await tabIdFor(prefix); return waitFor(async () => (await ext({ type: 'wot:tab', tabId: id })).result, { what: 'verdict' }); };
await test('first visit to a payment page records its scripts (no warning)', async () => {
  const p = await browser.open(L + '/checkout.html');
  await ready(p);
  const v = await verdictOn(L + '/checkout.html');
  const row = v.checks.find((c) => c.id === 'scripts');
  assert.equal(row.status, 'note');
  assert.match(row.detail, /First visit to this payment page/);
  assert.equal((await extensionUi(p)).bar, null);
});
await test('a script injected from a new outside domain raises the alarm before card entry, even on a trusted site', async () => {
  const p = await browser.open(L + '/checkout.html?compromised=1');
  await ready(p);
  const ui = await waitFor(async () => { const u = await extensionUi(p); return u.bar && /payment page/.test(u.bar) && u; }, { timeout: 20000, what: 'script alarm' });
  console.log('      ' + ui.bar.replace(/\s+/g, ' ').slice(0, 220));
  assert.match(ui.bar, /A script from 127\.0\.0\.1 appeared on this payment page/);
  assert.match(ui.bar, /Magecart/);
  assert.match(ui.bar, /Trust this change/);
  const v = (await ext({ type: 'wot:tab', tabId: await tabIdFor(L + '/checkout.html?compromised=1') })).result;
  const rep = v.checks.find((c) => c.id === 'reports');
  assert.ok(!rep || rep.status !== 'good' || /Not counted/.test(rep.detail), 'a good reputation does not cancel the alarm');
});
await test('"Trust this change" accepts it; the same scripts later give no warning', async () => {
  await ext({ type: 'checkout:accept', url: L + '/checkout.html?compromised=1' });
  const p = await browser.open(L + '/checkout.html?compromised=1&visit=3');
  await ready(p);
  await sleep(4000);
  assert.equal((await extensionUi(p)).bar, null);
  const v = (await ext({ type: 'wot:tab', tabId: await tabIdFor(L + '/checkout.html?compromised=1&visit=3') })).result;
  assert.notEqual(v.checks.find((c) => c.id === 'scripts').status, 'found');
});

await browser.close();
server.close();
probe.close();
console.log(`\n${passed} passed, ${failed} failed\n`);
fs.rmSync(TMP, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });
process.exit(failed ? 1 : 0);
