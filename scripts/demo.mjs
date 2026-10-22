// One command to run everything: `npm run demo`
//  1. starts the EMCON server on :8787 (or reuses one that is already running)
//  2. opens Chrome/Edge with the EMCON extension loaded, in its own profile
//     (data/browser-profile — your normal browser profile is never touched)
//  3. points the extension at the server and, unless --fresh, sets up Ghost
//     with a demo PIN so every demo flow works immediately
// Close the browser window (or press Ctrl+C) to stop.
import path from 'node:path';
import { launchBrowser, ROOT, waitFor } from '../tools/browser.mjs';

const PORT = Number(process.env.PORT) || 8787;
const BASE = `http://localhost:${PORT}`;
const FRESH = process.argv.includes('--fresh');
const DEMO_PIN = '2468';

async function emconServerUp() {
  try { const r = await fetch(`${BASE}/api/wot/groups`); return r.ok && Array.isArray(await r.json()); } catch { return false; }
}

let server = null;
if (await emconServerUp()) {
  console.log(`  ✔ Reusing the EMCON server already running on ${BASE}`);
} else {
  const { createApp } = await import('../server/app.js');
  server = await createApp();
  await new Promise((resolve, reject) => {
    server.once('error', (e) => reject(e.code === 'EADDRINUSE' ? new Error(`Port ${PORT} is used by another program. Free it or run with PORT=<other>.`) : e));
    server.listen(PORT, resolve);
  });
  console.log(`  ✔ EMCON server started on ${BASE}`);
}

const browser = await launchBrowser({ profile: path.join(ROOT, 'data', 'browser-profile'), fresh: FRESH, startUrl: BASE + '/', headless: !!process.env.EMCON_HEADLESS });
console.log(`  ✔ ${path.basename(browser.exe)} launched with the EMCON extension (id ${browser.extensionId})`);

// Talk to the extension's service worker through a hidden extension page.
const { targetId } = await browser.send('Target.createTarget', { url: `chrome-extension://${browser.extensionId}/pages/popup.html`, background: true });
const ext = await browser.attach(targetId);
await waitFor(() => ext.eval('!!chrome.runtime?.id'), { what: 'extension context' });
const call = async (msg) => {
  const r = await ext.eval(`new Promise((r) => chrome.runtime.sendMessage(${JSON.stringify(msg)}, r))`);
  if (r?.error) throw new Error(r.error);
  return r?.result;
};
await call({ type: 'settings:set', patch: { server: BASE } });

let ghost = await call({ type: 'ghost:status' });
if (!ghost.enrolled && !FRESH) {
  ghost = await call({ type: 'ghost:enroll', dob: '1995-04-02', pin: DEMO_PIN });
  console.log(`  ✔ Ghost set up with demo PIN ${DEMO_PIN} (run with --fresh to do the setup yourself)`);
} else if (ghost.enrolled) {
  console.log('  ✔ Ghost already set up in this profile');
}
await browser.send('Target.closeTarget', { targetId });

console.log(`
  EMCON is running. Try, in the browser window that just opened:
    Hub ................. ${BASE}/
    Ghost sign-in ....... ${BASE}/rp.html${ghost.enrolled && !FRESH ? `   (consent PIN: ${DEMO_PIN})` : '   (set up Ghost from the 🛡️ toolbar icon first)'}
    Provenance studio ... ${BASE}/sign.html  → "Build the full demo feed" → ${BASE}/feed.html
    Bank vault .......... ${BASE}/vault.html  (PIN 1234, duress PIN 9999)
    Phishing clone ...... http://127.0.0.1:${PORT}/phish-login.html

  Close the browser window or press Ctrl+C to stop.
`);

async function shutdown() {
  await browser.close();
  server?.close();
  process.exit(0);
}
process.on('SIGINT', shutdown);
browser.exited.then(() => { console.log('  Browser closed, stopping EMCON.'); server?.close(); process.exit(0); });
