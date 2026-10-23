// Production mode: the server exactly as deployed, without EMCON_DEMO_SITE. The made-up test
// site (test/site), its demo APIs and its made-up brands and signers must not exist at all.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

process.env.EMCON_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'emcon-prod-test-'));
delete process.env.EMCON_DEMO_SITE;
delete process.env.DATABASE_URL;
process.env.EMCON_FEED_URL = 'data:text/plain,' + encodeURIComponent('https://live-scam-shop.test/login\n');
const { createApp } = await import('../server/app.js');
const server = await createApp();
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const BASE = `http://127.0.0.1:${server.address().port}`;
const get = (p, opts) => fetch(BASE + p, opts);

let passed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log('  ✔', name); }
  catch (e) { console.log('  ✖', name); console.error(e); process.exitCode = 1; }
}

console.log('\nProduction mode (no demo site)');
await test('every page of the made-up test site is a 404', async () => {
  for (const f of fs.readdirSync(new URL('./site/', import.meta.url)).filter((x) => /\.(html|js)$/.test(x))) {
    assert.equal((await get('/' + f)).status, 404, f);
  }
  assert.equal((await get('/demo-cdn/analytics.js')).status, 404);
});
await test('the demo bank, demo sign-in site, photo studio and short-link service are gone', async () => {
  assert.equal((await get('/api/vault/state')).status, 404);
  assert.equal((await get('/api/rp/challenge')).status, 404);
  assert.equal((await get('/api/prov/signers')).status, 404);
  assert.equal((await get('/api/prov/sign', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status, 404);
  assert.equal((await get('/api/prov/feed')).status, 404);
  assert.equal((await get('/s/abc', { redirect: 'manual' })).status, 404);
});
await test('the product pages are served', async () => {
  for (const p of ['/', '/login', '/signup', '/app', '/real.html', '/verify.html']) assert.equal((await get(p)).status, 200, p);
});
await test('no made-up brands, newsroom keys or seeded reports', async () => {
  assert.deepEqual(await (await get('/api/prov/trust-list')).json(), []);
  assert.deepEqual(await (await get('/api/prov/registry')).json(), []);
  const brands = (await (await get('/api/wot/brands')).json()).map((b) => b.name).join(' ');
  assert.doesNotMatch(brands, /Kestrel|QuickKart/);
  const groups = JSON.stringify(await (await get('/api/wot/groups')).json());
  assert.doesNotMatch(groups, /demo|SecOps Collective/i);
});
await test('the real-site guide links to no page of ours and no made-up photos', async () => {
  const html = await (await get('/real.html')).text();
  assert.doesNotMatch(html, /36CRProjectEMCON\/main\/docs\/media|verified-photo|doctored-photo|bank-login|phish-login|demo\.html|Kestrel/);
  assert.match(html, /c2pa-org\/public-testfiles/);
});
await test('the Content Credentials trust lists are served for the extension', async () => {
  const t = await (await get('/api/prov/c2pa-trust')).json();
  assert.match(t.anchors, /BEGIN CERTIFICATE/);
  assert.match(t.source, /contentauthenticity\.org/);
});
await test('without DATABASE_URL the server says its storage is not persistent', async () => {
  const c = await (await get('/api/config')).json();
  assert.equal(c.persistent, false);
});

server.close();
console.log(`\n${passed} passed${process.exitCode ? ', some FAILED' : ''}`);
process.exit(process.exitCode || 0);
