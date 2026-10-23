// Product screenshots, taken on the real internet (nothing of ours): a live phishing page from
// the OpenPhish feed, the popup's verdict on it, a real news site's trackers, a scam message
// with a live phishing link, a real C2PA photo and a real card form with an injected script.
// Phishing pages open in a throwaway headless profile with downloads blocked; nothing is typed.
//
//   node tools/real-screens.mjs        -> web/img/*.png (landing page) and docs/screens/*.png
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { launchBrowser, waitFor, sleep, ROOT } from './browser.mjs';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'emcon-screens-'));
process.env.EMCON_DATA = path.join(TMP, 'data');
delete process.env.EMCON_DEMO_SITE;
delete process.env.EMCON_FEED_URL;
const { createApp } = await import('../server/app.js');
const { feedHosts } = await import('../server/wot.js');
const { db } = await import('../server/store.js');
const server = await createApp();
await new Promise((r) => server.listen(0, r));
const L = `http://localhost:${server.address().port}`;
await waitFor(() => db.wot?.feed?.updated, { timeout: 60000, what: 'OpenPhish feed' });

const IMG = path.join(ROOT, 'web', 'img'), SCREENS = path.join(ROOT, 'docs', 'screens');
const browser = await launchBrowser({ profile: path.join(TMP, 'profile'), headless: !process.env.HEADED, fresh: true });
await browser.send('Browser.setDownloadBehavior', { behavior: 'deny' });
const extPage = await browser.open(`chrome-extension://${browser.extensionId}/pages/popup.html`);
await waitFor(() => extPage.eval('!!chrome.runtime?.id'), { what: 'extension page' });
const ext = async (msg) => { const r = await extPage.eval(`new Promise((r) => chrome.runtime.sendMessage(${JSON.stringify(msg)}, r))`); if (r?.error) throw new Error(r.error); return r?.result; };
await ext({ type: 'settings:set', patch: { server: L } });
const tabIdOf = (u) => extPage.eval(`chrome.tabs.query({}).then((t) => t.find((x) => (x.url || x.pendingUrl || '').startsWith(${JSON.stringify(u.slice(0, 50))}))?.id)`);
const close = (p) => browser.send('Target.closeTarget', { targetId: p.targetId }).catch(() => {});

async function shot(page, file, { width, height, dirs = [IMG] }) {
  await page.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
  await sleep(1200);
  const { data } = await page.send('Page.captureScreenshot', { format: 'png' });
  for (const d of dirs) fs.writeFileSync(path.join(d, file), Buffer.from(data, 'base64'));
  console.log('  saved', file);
}
async function popupFor(tabId, file, { view, script, height = 600 } = {}) {
  const p = await browser.open(`chrome-extension://${browser.extensionId}/pages/popup.html?tab=${tabId}`);
  await p.send('Emulation.setDeviceMetricsOverride', { width: 400, height, deviceScaleFactor: 1, mobile: false });
  await sleep(3500);
  if (view) await p.eval(`document.querySelector('nav.tabs [data-tab="${view}"]').click()`);
  if (script) await p.eval(script);
  await sleep(2500);
  await shot(p, file, { width: 400, height });
  return p;
}
async function emconUi(page) {
  const { root } = await page.send('DOM.getDocument', { depth: -1, pierce: true });
  let wall = false, bar = false, badge = false;
  const walk = (n, ours) => {
    const a = n.attributes || [];
    const cls = ours && a.includes('class') ? a[a.indexOf('class') + 1].split(/\s+/) : [];
    wall ||= cls.includes('wall'); bar ||= cls.includes('bar'); badge ||= cls.includes('badge');
    (n.children || []).forEach((c) => walk(c, ours));
    (n.shadowRoots || []).forEach((c) => walk(c, true));
  };
  walk(root, false);
  return { wall, bar, badge };
}

// 1. a live phishing page, blocked
console.log('Live phishing page');
const text = await (await fetch('https://openphish.com/feed.txt')).text();
const known = new Set(db.wot.attestations.filter((a) => /OpenPhish/.test(a.vc.credentialSubject.note)).map((a) => a.domain));
const hosts = new Set(feedHosts(text).filter((h) => known.has(h)));
let phish = null;
for (const line of text.split('\n')) {
  let u;
  try { u = new URL(line.trim()); } catch { continue; }
  if (!hosts.has(u.hostname.replace(/^www\./, ''))) continue;
  hosts.delete(u.hostname.replace(/^www\./, ''));
  const p = await browser.open(u.href);
  await p.send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
  if (await waitFor(async () => (await emconUi(p)).wall, { timeout: 25000, what: 'block page' }).catch(() => false)) { phish = { page: p, url: u.href }; break; }
  await close(p);
}
if (phish) {
  console.log('  blocked', new URL(phish.url).hostname);
  await shot(phish.page, 'block-page.png', { width: 1280, height: 800, dirs: [IMG, SCREENS] });
  const tabId = await tabIdOf(phish.url);
  await close(await popupFor(tabId, 'popup-verdict.png'));
  // the same link, arriving in a scam SMS: Check message follows it on the server
  const sms = `SBI: Dear customer, your YONO account will be blocked today. Complete your KYC update immediately: ${phish.url}`;
  await close(await popupFor(tabId, 'popup-check.png', { view: 'check', height: 640, script: `document.querySelector('#chk').value = ${JSON.stringify(sms)}; document.querySelector('#chkGo').click()` }));
  await close(phish.page);
} else console.log('  no live phishing page loaded right now; kept the old screenshots');

// 2. a real news site's trackers, despite Global Privacy Control
console.log('Privacy on timesofindia.indiatimes.com');
{
  const url = 'https://timesofindia.indiatimes.com/';
  const p = await browser.open(url);
  await sleep(20000);
  await close(await popupFor(await tabIdOf(url), 'popup-privacy.png', { view: 'privacy' }));
  await close(p);
}

// 3. a real C2PA photo
console.log('Content Credentials photo');
{
  const url = 'https://github.com/c2pa-org/public-testfiles/blob/main/legacy/1.4/image/jpeg/truepic-20230212-camera.jpg';
  const p = await browser.open(url);
  await p.send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
  await waitFor(async () => (await emconUi(p)).badge, { timeout: 60000, what: 'photo label' });
  await shot(p, 'photo-verified.png', { width: 1280, height: 800, dirs: [IMG, SCREENS] });
  await close(p);
}

// 4. the checkout alarm on a real card form: first visit, return visit, injected script
console.log('Checkout alarm on W3Schools');
{
  const url = 'https://www.w3schools.com/howto/howto_css_checkout_form.asp';
  const first = await browser.open(url);
  await sleep(20000);
  await close(first);
  const p = await browser.open(url);
  await p.send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
  await sleep(15000);
  await p.eval("document.head.append(Object.assign(document.createElement('script'), { src: 'https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js' }))");
  await waitFor(async () => { await p.eval("document.querySelector('#ccnum')?.scrollIntoView({ block: 'center' }); document.querySelector('#ccnum')?.focus()"); return (await emconUi(p)).bar; }, { timeout: 20000, what: 'alarm bar' });
  await shot(p, 'checkout-alarm.png', { width: 1280, height: 800, dirs: [IMG, SCREENS] });
  await close(p);
}

await browser.close();
server.close();
process.exit(0);
