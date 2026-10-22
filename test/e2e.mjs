// End-to-end tests: boots the real server on a random port with a throwaway data dir
// and drives every shield through its HTTP API using the extension's own crypto libs.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';

process.env.EMCON_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'emcon-test-'));
const { createApp } = await import('../server/app.js');
const { toHex, fromHex, toB64, toB64u, randomBytes, ed25519FromSeed, ed25519Sign, didKeyFromPub, concat, hamming } = await import('../extension/lib/util.js');
const brsa = await import('../extension/lib/blindrsa.js');
const prov = await import('../extension/lib/provenance.js');
const { signCredential, verifyCredential, VC_CONTEXT } = await import('../extension/lib/vc.js');
const { computeTrust, scoreDomain } = await import('../extension/lib/trustgraph.js');
const { domTokens, simhash64 } = await import('../extension/lib/simhash.js');

const server = await createApp();
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const BASE = `http://127.0.0.1:${server.address().port}`;
const ORIGIN = BASE; // RP derives origin from the Host header

async function api(p, { method = 'GET', body, headers = {} } = {}) {
  const r = await fetch(BASE + p, { method, headers: { 'content-type': 'application/json', ...headers }, body: body && JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  return { status: r.status, ...j };
}

let passed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log('  ✔', name); }
  catch (e) { console.log('  ✖', name); console.error(e); process.exitCode = 1; }
}

console.log('\nShield 1 · Ghost Engine');
const keys = await api('/api/issuer/keys');
const pub18 = { n: BigInt('0x' + keys['human+18'].n), e: BigInt('0x' + keys['human+18'].e) };
const { enrollmentId, bundles } = await api('/api/issuer/enroll', { method: 'POST', body: { dob: '1990-01-01' } });

async function mintTokens(n) {
  const pending = [];
  for (let i = 0; i < n; i++) { const t = randomBytes(32); pending.push({ t, ...(await brsa.blind(t, pub18)) }); }
  const res = await api('/api/issuer/issue', { method: 'POST', body: { enrollmentId, bundle: 'human+18', keyId: keys['human+18'].keyId, blinded: pending.map((p) => p.blinded.toString(16)) } });
  if (res.status !== 200) return res;
  return pending.map((p, i) => Object.defineProperty(
    { t: toHex(p.t), s: brsa.unblind(BigInt('0x' + res.signatures[i]), p.r, pub18.n).toString(16), keyId: keys['human+18'].keyId },
    'raw', { value: p, enumerable: false }, // keep BigInts out of JSON
  ));
}

const site = await ed25519FromSeed(randomBytes(32));
async function present(token, origin = ORIGIN) {
  const { challenge } = await api('/api/rp/challenge');
  const sig = await ed25519Sign(site.privateKey, `EMCON-GHOST-v1|${origin}|${challenge}|${token ? token.t : ''}`);
  return { challenge, presentation: { pseudonym: toB64u(site.pub), token: token && { t: token.t, s: token.s, keyId: token.keyId }, sig: toB64u(sig) } };
}

let tokens;
await test('adult enrolment is eligible for human and human+18', () => assert.deepEqual(bundles, ['human', 'human+18']));
await test('blind tokens unblind into valid issuer signatures', async () => {
  tokens = await mintTokens(4);
  for (const tk of tokens) assert.ok(await brsa.verify(fromHex(tk.t), BigInt('0x' + tk.s), pub18));
});
await test('issuer never saw the token: blinded value != FDH(token)', async () => {
  const { raw } = tokens[0];
  assert.notEqual(raw.blinded, await brsa.fdh(raw.t, pub18.n));
});
await test('new account without a token is refused (428)', async () => {
  const r = await api('/api/rp/auth', { method: 'POST', body: await present(null) });
  assert.equal(r.status, 428);
});
await test('sign-up with token creates an 18+ account, knows nothing else', async () => {
  const r = await api('/api/rp/auth', { method: 'POST', body: await present(tokens[0]) });
  assert.equal(r.status, 200, r.error);
  assert.equal(r.newAccount, true);
  assert.deepEqual(r.account.claims, ['human', 'over18']);
  assert.equal(r.whatThisSiteKnows.email, null);
});
await test('returning login needs no token', async () => {
  const r = await api('/api/rp/auth', { method: 'POST', body: await present(null) });
  assert.equal(r.status, 200, r.error);
  assert.equal(r.newAccount, false);
});
await test('spent token cannot mint a second account (Sybil)', async () => {
  const other = await ed25519FromSeed(randomBytes(32));
  const { challenge } = await api('/api/rp/challenge');
  const sig = await ed25519Sign(other.privateKey, `EMCON-GHOST-v1|${ORIGIN}|${challenge}|${tokens[0].t}`);
  const r = await api('/api/rp/auth', { method: 'POST', body: { challenge, presentation: { pseudonym: toB64u(other.pub), token: tokens[0], sig: toB64u(sig) } } });
  assert.equal(r.status, 409);
});
await test('presentation signed for a different origin is rejected (phishing relay)', async () => {
  const r = await api('/api/rp/auth', { method: 'POST', body: await present(tokens[1], 'https://evil.example') });
  assert.equal(r.status, 401);
});
await test('challenge replay is rejected', async () => {
  const body = await present(null);
  assert.equal((await api('/api/rp/auth', { method: 'POST', body })).status, 200);
  assert.equal((await api('/api/rp/auth', { method: 'POST', body })).status, 400);
});
await test('forged token signature is rejected', async () => {
  const fake = { ...tokens[2], s: (BigInt('0x' + tokens[2].s) + 1n).toString(16) };
  const other = await ed25519FromSeed(randomBytes(32));
  const { challenge } = await api('/api/rp/challenge');
  const sig = await ed25519Sign(other.privateKey, `EMCON-GHOST-v1|${ORIGIN}|${challenge}|${fake.t}`);
  const r = await api('/api/rp/auth', { method: 'POST', body: { challenge, presentation: { pseudonym: toB64u(other.pub), token: fake, sig: toB64u(sig) } } });
  assert.equal(r.status, 401);
});
await test('monthly issuance quota stops token farming', async () => {
  for (let i = 0; i < 3; i++) await mintTokens(5); // 4 + 15 = 19
  const r = await mintTokens(5);
  assert.equal(r.status, 429);
});
await test('minor cannot get an over-18 token', async () => {
  const kid = await api('/api/issuer/enroll', { method: 'POST', body: { dob: new Date(Date.now() - 15 * 365 * 864e5).toISOString().slice(0, 10) } });
  assert.deepEqual(kid.bundles, ['human']);
  const { blinded } = await brsa.blind(randomBytes(32), pub18);
  const r = await api('/api/issuer/issue', { method: 'POST', body: { enrollmentId: kid.enrollmentId, bundle: 'human+18', keyId: keys['human+18'].keyId, blinded: [blinded.toString(16)] } });
  assert.equal(r.status, 403);
});

console.log('\nShield 2 · Media provenance');
function makePng(w, h, fn) {
  const raw = Buffer.alloc((w * 3 + 1) * h);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) raw.set(fn(x, y), y * (w * 3 + 1) + 1 + x * 3);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 2;
  return concat(new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]), prov.pngChunk('IHDR', ihdr), prov.pngChunk('IDAT', zlib.deflateSync(raw)), prov.pngChunk('IEND', new Uint8Array(0)));
}
const img = makePng(64, 48, (x, y) => [x * 4, y * 5, 128]);
const trust = await (await fetch(BASE + '/api/prov/trust-list')).json();
const fetchBytes = async (u) => new Uint8Array(await (await fetch(BASE + u)).arrayBuffer());
let signedBytes;

await test('trusted newsroom signature verifies', async () => {
  const r = await api('/api/prov/sign', { method: 'POST', body: { image: toB64(img), signer: 'newsroom', title: 'test', dhash: '0f0f0f0f0f0f0f0f' } });
  assert.equal(r.status, 200, r.error);
  signedBytes = await fetchBytes(r.url);
  const v = await prov.verifyImageBytes(signedBytes, trust);
  assert.equal(v.status, 'verified');
  assert.equal(v.issuerName, 'Kestrel Daily News');
});
await test('pixel edit with the original manifest copied over -> altered', async () => {
  const edited = makePng(64, 48, (x, y) => (x < 10 ? [255, 0, 0] : [x * 4, y * 5, 128]));
  const v = await prov.verifyImageBytes(prov.embedManifest(edited, prov.extractManifest(signedBytes).manifest), trust);
  assert.equal(v.status, 'altered');
});
await test('editing the manifest text -> forged', async () => {
  const m = { ...prov.extractManifest(signedBytes).manifest, title: 'something else' };
  assert.equal((await prov.verifyImageBytes(prov.embedManifest(signedBytes, m), trust)).status, 'forged');
});
await test('impersonating a trusted keyId with your own key -> forged', async () => {
  const mallory = await ed25519FromSeed(randomBytes(32));
  const { sig, ...fields } = prov.extractManifest(signedBytes).manifest;
  const evil = await prov.signManifest({ ...fields, issuer: { ...fields.issuer, pub: toB64u(mallory.pub) } }, mallory.privateKey);
  assert.equal((await prov.verifyImageBytes(prov.embedManifest(signedBytes, evil), trust)).status, 'forged');
});
await test('self-signed key not on trust list -> untrusted', async () => {
  const r = await api('/api/prov/sign', { method: 'POST', body: { image: toB64(img), signer: 'unknown', title: 'me' } });
  assert.equal((await prov.verifyImageBytes(await fetchBytes(r.url), trust)).status, 'untrusted');
});
await test('stripped copy has no manifest -> none (never "fake")', async () => {
  assert.equal((await prov.verifyImageBytes(prov.stripManifest(signedBytes), trust)).status, 'none');
});
await test('soft-binding registry recovers provenance within 10 bits', async () => {
  const near = await api('/api/prov/lookup?dhash=0f0f0f0f0f0f0f0e');
  assert.equal(near.match?.issuerName, 'Kestrel Daily News');
  const far = await api('/api/prov/lookup?dhash=f0f0f0f0f0f0f0f0');
  assert.equal(far.match, null);
});
await test('JPEG: manifest round-trips and metadata segments do not change the hash', async () => {
  const seg = (m, payload) => concat(new Uint8Array([0xff, m, (payload.length + 2) >> 8, (payload.length + 2) & 255]), payload);
  const jpeg = concat(new Uint8Array([0xff, 0xd8]), seg(0xe0, new TextEncoder().encode('JFIF\0\x01\x01')), seg(0xdb, randomBytes(65)), seg(0xc0, randomBytes(15)), seg(0xc4, randomBytes(30)), seg(0xda, randomBytes(10)), randomBytes(500), new Uint8Array([0xff, 0xd9]));
  const before = await prov.contentHash(jpeg);
  const withM = prov.embedManifest(jpeg, { hello: 'world' });
  assert.equal(await prov.contentHash(withM), before);
  assert.deepEqual(prov.extractManifest(withM).manifest, { hello: 'world' });
  assert.equal(withM[2], 0xff); assert.equal(withM[3], 0xe0); // JFIF stays first
});

console.log('\nShield 3 · Honey-Vault');
const vlogin = async (pin) => (await api('/api/vault/login', { method: 'POST', body: { pin } })).token;
const H = (t) => ({ 'x-vault-session': t });
let real = await vlogin('1234');
const transfer = (t, payeeId, amount, pin = '1234') => api('/api/vault/transfer', { method: 'POST', headers: H(t), body: { payeeId, amount, pin } });
const guardians = (await api('/api/vault/demo/info')).guardians.map((g) => new URL(g.url).searchParams.get('g'));
const allNo = { contacted: 'no', secret: 'no', returns: 'no', watched: 'no' };

await test('small payment to a long-standing payee is instant', async () => {
  const r = await transfer(real, 'p1', 120);
  assert.equal(r.tx.status, 'completed');
});
await test('stolen session without PIN step-up cannot move money', async () => {
  const r = await api('/api/vault/transfer', { method: 'POST', headers: H(real), body: { payeeId: 'p1', amount: 50, pin: '0000' } });
  assert.equal(r.status, 401);
});
await test('larger payment cools off and needs the check-in before release', async () => {
  const r = await transfer(real, 'p1', 800);
  assert.equal(r.tx.status, 'cooling');
  await api('/api/vault/demo/fast-forward', { method: 'POST', body: { minutes: 120 } });
  let st = await api('/api/vault/state', { headers: H(real) });
  assert.equal(st.txs.find((t) => t.id === r.tx.id).status, 'cooling', 'must not release without check-in');
  st = await api(`/api/vault/tx/${r.tx.id}/quiz`, { method: 'POST', headers: H(real), body: { answers: allNo } });
  assert.equal(st.txs.find((t) => t.id === r.tx.id).status, 'completed');
});
await test('scam-flagged payee goes to guardians; one veto refunds', async () => {
  const before = (await api('/api/vault/state', { headers: H(real) })).balance;
  const r = await transfer(real, 'p3', 3000);
  assert.equal(r.tx.status, 'awaiting_guardians');
  assert.ok(r.tx.risk.reasons.some((x) => x.includes('cryptoyield-pro.xyz')));
  await api(`/api/vault/guardian/${guardians[0]}/decide`, { method: 'POST', body: { txId: r.tx.id, decision: 'veto' } });
  const st = await api('/api/vault/state', { headers: H(real) });
  assert.equal(st.txs.find((t) => t.id === r.tx.id).status, 'vetoed');
  assert.equal(st.balance, before);
});
await test('yes on the scam-script check-in escalates to guardians, m-of-n releases', async () => {
  const r = await transfer(real, 'p2', 700);
  assert.equal(r.tx.status, 'cooling');
  await api(`/api/vault/tx/${r.tx.id}/quiz`, { method: 'POST', headers: H(real), body: { answers: { ...allNo, secret: 'yes' } } });
  await api('/api/vault/demo/fast-forward', { method: 'POST', body: { minutes: 200 } });
  let st = await api('/api/vault/state', { headers: H(real) });
  assert.equal(st.txs.find((t) => t.id === r.tx.id).status, 'awaiting_guardians');
  await api(`/api/vault/guardian/${guardians[0]}/decide`, { method: 'POST', body: { txId: r.tx.id, decision: 'approve' } });
  await api(`/api/vault/guardian/${guardians[1]}/decide`, { method: 'POST', body: { txId: r.tx.id, decision: 'approve' } });
  st = await api('/api/vault/state', { headers: H(real) });
  assert.equal(st.txs.find((t) => t.id === r.tx.id).status, 'completed');
});
await test('loosening a protection is time-locked, tightening is instant', async () => {
  const r = await api('/api/vault/settings', { method: 'POST', headers: H(real), body: { pin: '1234', changes: { instantLimit: 100000, coolingMinutes: 30 } } });
  assert.deepEqual(r.applied, ['coolingMinutes']);
  assert.equal(r.delayed[0].key, 'instantLimit');
  assert.equal(r.state.settings.instantLimit, 500);
});
await test('duress PIN: decoy shows success, money diverted, guardians alerted', async () => {
  const d = await vlogin('9999');
  const r = await transfer(d, 'p3', 5000, '9999');
  assert.equal(r.tx.status, 'completed', 'attacker must see success');
  assert.equal(r.state.freezeVault, undefined, 'decoy hides the freeze vault');
  const st = await api('/api/vault/state', { headers: H(real) });
  assert.equal(st.freezeVault, 5000);
  assert.equal(st.txs.find((t) => t.id === r.tx.id).status, 'diverted');
  const g = await api(`/api/vault/guardian/${guardians[2]}`);
  assert.equal(g.duressActive, true);
});
await test('guardians close the duress episode and money returns', async () => {
  const before = (await api('/api/vault/state', { headers: H(real) })).balance;
  await api(`/api/vault/guardian/${guardians[0]}/clear-duress`, { method: 'POST' });
  await api(`/api/vault/guardian/${guardians[1]}/clear-duress`, { method: 'POST' });
  const st = await api('/api/vault/state', { headers: H(real) });
  assert.equal(st.balance, before + 5000);
  assert.equal(st.freezeVault, 0);
});
await test('owner panic freeze cannot be undone by the owner', async () => {
  await api('/api/vault/freeze', { method: 'POST', headers: H(real) });
  const r = await transfer(real, 'p1', 10);
  assert.equal(r.status, 423);
  await api(`/api/vault/guardian/${guardians[0]}/freeze`, { method: 'POST', body: { frozen: false } });
  assert.equal((await transfer(real, 'p1', 10)).tx.status, 'completed');
});

console.log('\nShield 4 · Web of Trust');
const alice = await ed25519FromSeed(randomBytes(32));
const aliceDid = didKeyFromPub(alice.pub);
const att = (domain, verdict) => signCredential({ '@context': VC_CONTEXT, type: ['VerifiableCredential', 'EmconDomainAttestation'], issuer: aliceDid, validFrom: new Date().toISOString(), credentialSubject: { id: 'dns:' + domain, domain, verdict, transacted: true, note: '' } }, alice.privateKey, aliceDid);

await test('signed attestation verifies; tampered one does not', async () => {
  const vc = await att('shop.example', 'trusted');
  assert.ok(await verifyCredential(vc));
  assert.equal(await verifyCredential({ ...vc, credentialSubject: { ...vc.credentialSubject, verdict: 'scam' } }), false);
});
await test('relay rejects forged attestations', async () => {
  const vc = await att('shop.example', 'trusted');
  const r = await api('/api/wot/attest', { method: 'POST', body: { ...vc, credentialSubject: { ...vc.credentialSubject, domain: 'other.example', id: 'dns:other.example' } } });
  assert.equal(r.status, 400);
});
await test('k-anonymous prefix lookup returns the attestation', async () => {
  await api('/api/wot/attest', { method: 'POST', body: await att('shop.example', 'trusted') });
  const { createHash } = await import('node:crypto');
  const prefix = createHash('sha256').update('shop.example').digest('hex').slice(0, 5);
  const r = await api('/api/wot/domain?prefix=' + prefix);
  assert.ok(r.attestations.some((a) => a.issuer === aliceDid));
  assert.equal((await api('/api/wot/domain?prefix=ab')).status, 400, 'short prefixes refused');
});
await test('Sybil swarm outside your web is ignored; one compromised friend is capped', () => {
  const roots = [{ did: 'me', weight: 1 }, { did: 'friend', weight: 0.8 }];
  const vouches = Array.from({ length: 500 }, (_, i) => ({ issuer: 'friend', subject: 'sybil' + i, weight: 1 }));
  const trustMap = computeTrust(roots, vouches);
  const reports = [
    ...Array.from({ length: 1000 }, (_, i) => ({ issuer: 'stranger' + i, verdict: 'trusted', transacted: true, issued: '2026-01-01' })),
    ...Array.from({ length: 500 }, (_, i) => ({ issuer: 'sybil' + i, verdict: 'trusted', transacted: true, issued: '2026-01-01' })),
  ];
  const s = scoreDomain(reports, trustMap);
  assert.equal(s.ignored, 1000);
  assert.ok(s.pos <= 1.0001, `branch capped at 1, got ${s.pos}`);
});
await test('phishing clone is structurally close to the real login page; unrelated pages are not', () => {
  const read = (f) => fs.readFileSync(new URL(`../web/${f}`, import.meta.url), 'utf8');
  const h = (f) => simhash64(domTokens(read(f)));
  const clone = hamming(h('bank-login.html'), h('phish-login.html'));
  const other = Math.min(hamming(h('bank-login.html'), h('rp.html')), hamming(h('bank-login.html'), h('vault.html')));
  console.log(`      (clone distance ${clone}/64, unrelated ${other}/64)`);
  assert.ok(clone <= 12, `clone distance ${clone}`);
  assert.ok(other > 12, `unrelated distance ${other}`);
});

server.close();
console.log(`\n${passed} passed${process.exitCode ? ', some FAILED' : ''}\n`);
fs.rmSync(process.env.EMCON_DATA, { recursive: true, force: true });
process.exit(process.exitCode || 0);
