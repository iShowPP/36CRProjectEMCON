// Provenance service: publisher signing, trust list, and a soft-binding registry
// (perceptual hash -> original signed asset) to recover provenance after platforms
// strip metadata.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { db, save, HttpError, MEDIA_DIR, ROOT } from './store.js';
import { DEMO, HOSTED } from './config.js';
import { ed25519Jwk } from './keys.js';
import { contentHash, detectFormat, embedManifest, signManifest } from '../extension/lib/provenance.js';
import { fromB64, fromB64u, toHex, sha256, ed25519FromSeed, hamming } from '../extension/lib/util.js';
import { validateC2pa, trustFromPem } from '../extension/lib/c2pa.js';
import { dhashOf } from './imagehash.js';
import { assertPublic } from './link.js';

const SIGNERS = {
  newsroom: { name: 'Kestrel Daily News', role: 'Accredited newsroom', trusted: true },
  camera: { name: 'Lumen Camera Co. (device key)', role: 'Capture device', trusted: true },
  unknown: { name: 'Anonymous blog', role: 'Self-signed', trusted: false },
};
const RECOVERY_MAX_DISTANCE = 10;
const keys = {};

// ---------- real publishers (accounts that proved they own a website) ----------
// Each publisher account signs with its own key, derived from the server secret. Its photos
// count as "Verified" once the account has proved control of its domain (dashboard).
export async function publisherKey(uid) {
  const jwk = ed25519Jwk('prov/publisher/' + uid);
  const { privateKey, pub } = await ed25519FromSeed(fromB64u(jwk.d));
  return { privateKey, pub: jwk.x, keyId: toHex(await sha256(pub)).slice(0, 16) };
}
const verifiedPublishers = () => Object.values(db.accounts?.users || {}).filter((u) => u.publisher?.verified);

/** Sign a photo for a publisher account; returns the signed bytes and the manifest. */
export async function signForPublisher(user, b64, title, dhash) {
  const bytes = decodeImage(b64);
  const key = await publisherKey(user.id);
  const name = user.publisher?.verified ? user.publisher.domain : user.name;
  const fields = {
    v: 1, type: 'emcon.provenance', title: String(title || 'Untitled').slice(0, 120), claimGenerator: 'EMCON Signer/1.0',
    created: new Date().toISOString(), issuer: { name, keyId: key.keyId, pub: key.pub },
    actions: [{ action: 'c2pa.created', when: new Date().toISOString() }],
    contentHash: { alg: 'sha256', value: await contentHash(bytes) },
    softBinding: /^[0-9a-f]{16}$/.test(dhash || '') ? { alg: 'dhash64', value: dhash } : undefined,
  };
  const signed = embedManifest(bytes, await signManifest(fields, key.privateKey));
  // only verified publishers enter the recovery registry (it feeds "Recovered" labels)
  if (user.publisher?.verified && fields.softBinding) {
    db.prov.registry.push({ dhash, title: fields.title, issuerName: name, keyId: key.keyId, created: fields.created, url: null, uid: user.id });
    db.prov.registry = db.prov.registry.slice(-5000);
    save();
  }
  return { bytes: signed, manifest: fields };
}

// ---------- Content Credentials (C2PA) ----------
// The trust lists the official verifier at contentcredentials.org/verify uses: trust anchors and
// known signer certificates. A copy ships in server/seed and is refreshed once a day when hosted.
const TRUST_SRC = 'https://verify.contentauthenticity.org/trust/';
const c2paTrust = {
  anchors: fs.readFileSync(path.join(ROOT, 'server', 'seed', 'c2pa-anchors.pem'), 'utf8'),
  allowed: fs.readFileSync(path.join(ROOT, 'server', 'seed', 'c2pa-allowed.sha256.txt'), 'utf8'),
  fetchedAt: null,
};
let parsedTrust = trustFromPem(c2paTrust.anchors, c2paTrust.allowed);
async function refreshC2paTrust() {
  try {
    const get = async (file) => {
      const r = await fetch(TRUST_SRC + file, { signal: AbortSignal.timeout(15000) });
      if (!r.ok) throw new Error(`${file}: HTTP ${r.status}`);
      return r.text();
    };
    const [anchors, allowed] = await Promise.all([get('anchors.pem'), get('allowed.sha256.txt')]);
    if (!anchors.includes('BEGIN CERTIFICATE')) throw new Error('anchors.pem has no certificates');
    Object.assign(c2paTrust, { anchors, allowed, fetchedAt: new Date().toISOString() });
    parsedTrust = trustFromPem(anchors, allowed);
  } catch (e) { console.warn('[prov] Content Credentials trust list refresh failed, keeping the bundled copy:', e.message); }
}

const c2paHits = new Map();
function c2paLimit(ip) {
  const now = Date.now();
  const recent = (c2paHits.get(ip) || []).filter((t) => now - t < 3600e3);
  if (recent.length >= 30) throw new HttpError(429, 'Too many photos at once. Try again in an hour.');
  recent.push(now);
  c2paHits.set(ip, recent);
  if (c2paHits.size > 5000) c2paHits.delete(c2paHits.keys().next().value);
}

// Downloads a public image (redirects checked hop by hop), at most 20 MB.
async function downloadImage(raw) {
  let u;
  try { u = new URL(String(raw || '')); } catch { throw new HttpError(400, 'not a valid image address'); }
  for (let hop = 0; hop < 4; hop++) {
    if (!/^https?:$/.test(u.protocol)) throw new HttpError(400, 'only http and https images');
    await assertPublic(u.hostname);
    const res = await fetch(u, { redirect: 'manual', signal: AbortSignal.timeout(20000), headers: { 'user-agent': 'Mozilla/5.0 (EMCON photo check)', accept: 'image/*' } }).catch(() => null);
    if (!res) throw new HttpError(502, 'the image could not be downloaded');
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) { res.body?.cancel().catch(() => {}); u = new URL(loc, u); continue; }
    if (!res.ok) throw new HttpError(502, `the image host answered HTTP ${res.status}`);
    if (Number(res.headers.get('content-length')) > 20e6) throw new HttpError(413, 'image too large');
    const chunks = [];
    let size = 0;
    for await (const c of res.body) {
      size += c.length;
      if (size > 20e6) throw new HttpError(413, 'image too large');
      chunks.push(c);
    }
    const bytes = new Uint8Array(Buffer.concat(chunks));
    if (!detectFormat(bytes)) throw new HttpError(415, 'PNG or JPEG only');
    return { bytes, url: u.href };
  }
  throw new HttpError(400, 'too many redirects');
}

const plainTitle = (t) => (t && !/^[0-9a-f-]{20,}\.\w+$/i.test(t) ? String(t).slice(0, 120) : null);

function c2paRoutes(route) {
  if (HOSTED) {
    refreshC2paTrust();
    setInterval(refreshC2paTrust, 24 * 3600e3).unref();
  }
  route('GET', '/api/prov/c2pa-trust', () => ({ anchors: c2paTrust.anchors, allowed: c2paTrust.allowed, source: TRUST_SRC, fetchedAt: c2paTrust.fetchedAt }));

  // Remember a photo whose Content Credentials are valid and from a trusted signer, so a copy
  // whose credentials a site stripped can still be recognised. The server downloads and checks
  // the file itself: nothing a client says about the photo is taken on trust.
  route('POST', '/api/prov/c2pa', async ({ body, ip }) => {
    c2paLimit(ip);
    const { bytes, url } = await downloadImage(body.url);
    const v = await validateC2pa(bytes, parsedTrust);
    if (!v) throw new HttpError(422, 'This image has no Content Credentials.');
    if (v.signature !== 'valid' || v.assertions !== 'valid') throw new HttpError(422, 'Its Content Credentials do not verify.');
    if (v.binding !== 'valid') throw new HttpError(422, 'The image does not match what was signed.');
    if (v.trust === 'unknown') throw new HttpError(422, 'It is signed, but not by a signer on the Content Credentials trust list.');
    const entry = {
      dhash: dhashOf(bytes), title: plainTitle(v.title) || 'Signed photo', issuerName: v.signerOrg || v.signer, signer: v.signer,
      created: v.signedAt ? new Date(v.signedAt).toISOString() : null, url, source: 'c2pa',
    };
    const known = db.prov.registry.find((r) => r.url === url);
    if (!known) {
      db.prov.registry.push(entry);
      db.prov.registry = db.prov.registry.slice(-5000);
      save();
    }
    return { registered: !known, entry: known || entry };
  });
}

export default async function prov(route) {
  db.prov ||= { signers: {}, registry: [], feed: [] };
  c2paRoutes(route);
  if (!DEMO) {
    // made-up newsroom keys and their photos are test fixtures, never part of the product
    db.prov.registry = db.prov.registry.filter((r) => r.uid || r.source === 'c2pa');
    route('GET', '/api/prov/trust-list', async () => Promise.all(verifiedPublishers().map(async (u) => {
      const k = await publisherKey(u.id);
      return { keyId: k.keyId, name: u.publisher.domain, role: 'Publisher (verified domain)', pub: k.pub };
    })));
    route('GET', '/api/prov/registry', () => db.prov.registry.map(({ uid, ...r }) => r));
    route('GET', '/api/prov/lookup', ({ query }) => lookup(query.dhash));
    return;
  }
  for (const [id, meta] of Object.entries(SIGNERS)) {
    if (!db.prov.signers[id]) {
      db.prov.signers[id] = ed25519Jwk('prov/' + id);
      save();
    }
    const jwk = db.prov.signers[id];
    const { privateKey, pub } = await ed25519FromSeed(fromB64u(jwk.d));
    keys[id] = { ...meta, id, privateKey, pub: jwk.x, keyId: toHex(await sha256(pub)).slice(0, 16) };
  }

  // In production this list is itself signed and distributed like a CA bundle.
  route('GET', '/api/prov/trust-list', () =>
    Object.values(keys).filter((k) => k.trusted).map((k) => ({ keyId: k.keyId, name: k.name, role: k.role, pub: k.pub })));

  route('GET', '/api/prov/signers', () => Object.values(keys).map((k) => ({ id: k.id, name: k.name, role: k.role, trusted: k.trusted })));

  route('POST', '/api/prov/sign', async ({ body }) => {
    const key = keys[body.signer];
    if (!key) throw new HttpError(400, 'unknown signer');
    const bytes = decodeImage(body.image);
    const fields = {
      v: 1,
      type: 'emcon.provenance',
      title: String(body.title || 'Untitled').slice(0, 120),
      claimGenerator: 'EMCON Signer/1.0',
      created: new Date().toISOString(),
      issuer: { name: key.name, keyId: key.keyId, pub: key.pub },
      actions: [{ action: body.action === 'edited' ? 'c2pa.edited' : 'c2pa.created', when: new Date().toISOString() }],
      contentHash: { alg: 'sha256', value: await contentHash(bytes) },
      softBinding: /^[0-9a-f]{16}$/.test(body.dhash || '') ? { alg: 'dhash64', value: body.dhash } : undefined,
    };
    const signed = embedManifest(bytes, await signManifest(fields, key.privateKey));
    const file = writeMedia(signed);
    if (key.trusted && fields.softBinding) {
      db.prov.registry.push({ dhash: body.dhash, title: fields.title, issuerName: key.name, keyId: key.keyId, created: fields.created, url: file });
    }
    if (body.addToFeed) db.prov.feed.unshift({ url: file, caption: body.caption || fields.title, author: body.author || key.name, kind: 'signed', at: Date.now() });
    save();
    return { url: file, manifest: fields };
  });

  // Unsigned uploads, e.g. the "stripped" / "tampered" / "unsigned" variants for the demo feed.
  route('POST', '/api/prov/upload', ({ body }) => {
    const file = writeMedia(decodeImage(body.image));
    db.prov.feed.unshift({ url: file, caption: String(body.caption || '').slice(0, 200), author: String(body.author || 'someone').slice(0, 60), kind: body.kind || 'upload', at: Date.now() });
    save();
    return { url: file };
  });

  route('GET', '/api/prov/feed', () => db.prov.feed);
  route('DELETE', '/api/prov/feed', () => { db.prov.feed = []; save(); });

  route('GET', '/api/prov/lookup', ({ query }) => lookup(query.dhash));

  // The whole (small) registry, so the extension can match fingerprints locally and
  // never has to tell the server which images you are looking at.
  route('GET', '/api/prov/registry', ({ origin }) => db.prov.registry.map((r) => ({ ...r, url: r.url ? new URL(r.url, origin).href : null })));
}

function lookup(dhash) {
  if (!/^[0-9a-f]{16}$/.test(dhash || '')) throw new HttpError(400, 'dhash must be 16 hex chars');
  let best = null;
  for (const r of db.prov.registry) {
    const d = hamming(r.dhash, dhash);
    if (d <= RECOVERY_MAX_DISTANCE && (!best || d < best.distance)) best = { match: r, distance: d };
  }
  return best || { match: null };
}

function decodeImage(b64) {
  if (typeof b64 !== 'string' || !b64) throw new HttpError(400, 'image (base64) required');
  const bytes = fromB64(b64.replace(/^data:[^,]+,/, ''));
  if (bytes.length > 15e6) throw new HttpError(413, 'image too large');
  if (!detectFormat(bytes)) throw new HttpError(415, 'PNG or JPEG only');
  return bytes;
}

function writeMedia(bytes) {
  const name = crypto.randomBytes(8).toString('hex') + (detectFormat(bytes) === 'png' ? '.png' : '.jpg');
  fs.writeFileSync(path.join(MEDIA_DIR, name), bytes);
  return '/media/' + name;
}
