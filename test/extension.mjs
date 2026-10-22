// Browser end-to-end test: loads the real extension into Chrome (headless by default,
// HEADED=1 to watch), points it at a throwaway server, and drives all four shields
// through the actual UI: content script, service worker, consent window, badges, block page.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { launchBrowser, waitFor, sleep } from '../tools/browser.mjs';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'emcon-browser-test-'));
process.env.EMCON_DATA = path.join(TMP, 'data');
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
    const s = document.querySelector('#status').textContent; if (s.startsWith('⚠️')) return { ok: false, text: s };
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

console.log('\nShield 1b · Anti-fingerprinting');
const draw = `(() => { const c = document.createElement('canvas'); c.width = 220; c.height = 50; const g = c.getContext('2d');
  g.font = '18px Arial'; g.fillStyle = '#f60'; g.fillRect(0, 0, 130, 40); g.fillStyle = '#069'; g.fillText('EMCON fingerprint', 4, 30); return c.toDataURL(); })()`;
await test('canvas fingerprint is stable on one site but differs between sites', async () => {
  const a = await browser.open(L + '/feed.html');
  const b = await browser.open(IP + '/feed.html');
  await ready(a); await ready(b);
  const a1 = await a.eval(draw), a2 = await a.eval(draw), b1 = await b.eval(draw);
  assert.equal(a1, a2, 'same site must read the same value twice');
  assert.notEqual(a1, b1, 'two sites must see different fingerprints');
  assert.equal(await a.eval('HTMLCanvasElement.prototype.toDataURL.toString()'), 'function toDataURL() { [native code] }');
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
  assert.ok(badges.some((b) => b.startsWith('✔ Verified')));
  assert.ok(badges.some((b) => b.startsWith('✖ Altered')));
  assert.ok(badges.some((b) => b.startsWith('↺ Provenance recovered')));
  assert.ok(badges.some((b) => b.startsWith('? Signed')));
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

await browser.close();
server.close();
console.log(`\n${passed} passed, ${failed} failed\n`);
fs.rmSync(TMP, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });
process.exit(failed ? 1 : 0);
