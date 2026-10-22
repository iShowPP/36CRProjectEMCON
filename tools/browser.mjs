// Launch Chrome / Edge / Brave with the EMCON extension loaded, driven over the
// DevTools protocol pipe. Branded Chrome ignores --load-extension since v137, so we
// use CDP `Extensions.loadUnpacked` (needs --remote-debugging-pipe +
// --enable-unsafe-extension-debugging), the same mechanism Puppeteer uses.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const EXTENSION_DIR = path.join(ROOT, 'extension');
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const CANDIDATES = {
  win32: [
    '%ProgramFiles%\\Google\\Chrome\\Application\\chrome.exe',
    '%ProgramFiles(x86)%\\Google\\Chrome\\Application\\chrome.exe',
    '%LOCALAPPDATA%\\Google\\Chrome\\Application\\chrome.exe',
    '%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe',
    '%ProgramFiles%\\Microsoft\\Edge\\Application\\msedge.exe',
    '%ProgramFiles%\\BraveSoftware\\Brave-Browser\\Application\\brave.exe',
  ],
  darwin: [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
  ],
  linux: ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/microsoft-edge'],
};

export function findBrowser() {
  if (process.env.EMCON_BROWSER) return process.env.EMCON_BROWSER;
  const list = (CANDIDATES[process.platform] || CANDIDATES.linux).map((p) => p.replace(/%([^%]+)%/g, (_, v) => process.env[v] || ''));
  const hit = list.find((p) => p && fs.existsSync(p));
  if (!hit) throw new Error('No Chrome/Edge/Brave found. Set EMCON_BROWSER to the browser executable.');
  return hit;
}

export async function launchBrowser({ profile, headless = false, exe = findBrowser(), startUrl = 'about:blank', fresh = false } = {}) {
  if (fresh) fs.rmSync(profile, { recursive: true, force: true });
  fs.mkdirSync(profile, { recursive: true });
  const args = [
    `--user-data-dir=${profile}`, '--remote-debugging-pipe', '--enable-unsafe-extension-debugging',
    '--no-first-run', '--no-default-browser-check', ...(headless ? ['--headless=new'] : []), startUrl,
  ];
  const proc = spawn(exe, args, { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
  const toBrowser = proc.stdio[3], fromBrowser = proc.stdio[4];
  const pending = new Map();
  let id = 0, buf = '';
  fromBrowser.on('data', (chunk) => {
    buf += chunk.toString('utf8');
    let i;
    while ((i = buf.indexOf('\0')) >= 0) {
      const msg = JSON.parse(buf.slice(0, i));
      buf = buf.slice(i + 1);
      const p = msg.id && pending.get(msg.id);
      if (p) { pending.delete(msg.id); msg.error ? p.rej(new Error(msg.error.message)) : p.res(msg.result); }
    }
  });
  const exited = new Promise((r) => proc.on('exit', r));
  const send = (method, params = {}, sessionId) => new Promise((res, rej) => {
    if (proc.exitCode !== null) return rej(new Error('browser exited'));
    const n = ++id;
    pending.set(n, { res, rej });
    toBrowser.write(JSON.stringify({ id: n, method, params, sessionId }) + '\0');
  });

  await send('Browser.getVersion');
  const { id: extensionId } = await send('Extensions.loadUnpacked', { path: EXTENSION_DIR });

  async function attach(targetId) {
    const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
    const s = (m, p) => send(m, p, sessionId);
    await s('Runtime.enable').catch(() => {});
    return {
      targetId,
      send: s,
      async eval(expression) {
        const r = await s('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, userGesture: true });
        if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
        return r.result.value;
      },
    };
  }

  return {
    proc, exe, extensionId, send, attach, exited,
    async open(url) { const { targetId } = await send('Target.createTarget', { url }); return attach(targetId); },
    async targets() { return (await send('Target.getTargets')).targetInfos; },
    async close() { await send('Browser.close').catch(() => {}); await Promise.race([exited, sleep(3000)]); if (proc.exitCode === null) proc.kill(); },
  };
}

export async function waitFor(fn, { timeout = 15000, every = 250, what = 'condition' } = {}) {
  const t0 = Date.now();
  let last;
  while (Date.now() - t0 < timeout) {
    try { last = await fn(); if (last) return last; } catch (e) { last = e; }
    await sleep(every);
  }
  throw new Error(`timed out waiting for ${what}${last instanceof Error ? ` (${last.message})` : ''}`);
}
