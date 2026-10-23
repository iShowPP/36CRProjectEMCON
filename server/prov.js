// Provenance service: publisher signing, trust list, and a soft-binding registry
// (perceptual hash -> original signed asset) to recover provenance after platforms
// strip metadata.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { db, save, HttpError, MEDIA_DIR, ROOT } from './store.js';
import { DEMO } from './config.js';
import { ed25519Jwk } from './keys.js';
import { contentHash, detectFormat, embedManifest, signManifest } from '../extension/lib/provenance.js';
import { fromB64, fromB64u, toHex, sha256, ed25519FromSeed, hamming } from '../extension/lib/util.js';

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

export default async function prov(route) {
  db.prov ||= { signers: {}, registry: [], feed: [] };
  if (!DEMO) {
    // made-up newsroom keys and their photos are test fixtures, never part of the product
    db.prov.registry = db.prov.registry.filter((r) => r.uid);
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

  // Signed photos published on other hosts (docs/media on GitHub): their fingerprints are
  // seeded on every start, so a host that wipes its disk still recognises stripped copies.
  const seedFile = path.join(ROOT, 'server', 'seed', 'registry.json');
  if (fs.existsSync(seedFile)) {
    for (const s of JSON.parse(fs.readFileSync(seedFile, 'utf8'))) {
      if (!db.prov.registry.some((r) => r.dhash === s.dhash && r.url === s.url)) db.prov.registry.push(s);
    }
    save();
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
