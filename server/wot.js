// Web-of-Trust attestation relay.
//
// The server is a dumb, untrusted mailbox: it stores signed W3C credentials and
// hands them back. Clients re-verify every signature and compute trust locally,
// so a compromised relay can withhold data but cannot forge reputation.
//
// Privacy: lookups use a short SHA-256 prefix of the domain (k-anonymity, like
// Safe Browsing), so the relay never learns which exact site you are visiting.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { db, save, HttpError, ROOT } from './store.js';
import { verifyCredential, signCredential, VC_CONTEXT } from '../extension/lib/vc.js';
import { toHex, sha256, fromB64u, ed25519FromSeed, didKeyFromPub, pubFromDidKey } from '../extension/lib/util.js';
import { domTokens, simhash64 } from '../extension/lib/simhash.js';

const MIN_PREFIX = 4;
let group; // the demo "security group" identity
let brands = [];

export const normalizeDomain = (d) => String(d || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/:].*$/, '').replace(/^www\./, '');
const domainHash = async (d) => toHex(await sha256(normalizeDomain(d)));

export default async function wot(route) {
  db.wot ||= { attestations: [], vouches: [] };
  if (!db.wot.groupKey) {
    db.wot.groupKey = crypto.generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
    save();
  }
  const { privateKey, pub } = await ed25519FromSeed(fromB64u(db.wot.groupKey.d));
  group = { did: didKeyFromPub(pub), privateKey, name: 'EMCON SecOps Collective (demo)', description: 'Volunteer analysts who triage reported scams and phishing kits.' };

  if (!db.wot.seeded) {
    const seed = [
      { domain: '127.0.0.1', verdict: 'scam', transacted: false, note: 'Clone of the Kestrel Bank login page harvesting passwords' },
      { domain: 'cryptoyield-pro.xyz', verdict: 'scam', transacted: false, note: 'Pig-butchering "investment platform"; victims cannot withdraw' },
      { domain: 'localhost', verdict: 'trusted', transacted: true, note: 'Official Kestrel Bank (demo)' },
    ];
    for (const s of seed) await store(await attestationFor(s, group.privateKey, group.did));
    db.wot.seeded = true;
    save();
  }

  // Brand fingerprints for clone detection, computed from the official login page.
  const official = fs.readFileSync(path.join(ROOT, 'web', 'bank-login.html'), 'utf8');
  brands = [{ name: 'Kestrel Bank', domains: ['localhost', 'kestrel-bank.example'], keywords: ['kestrel bank', 'kestrel'], simhash: simhash64(domTokens(official)) }];

  route('GET', '/api/wot/groups', () => [{ did: group.did, name: group.name, description: group.description, defaultWeight: 0.8 }]);
  route('GET', '/api/wot/brands', () => brands);

  route('POST', '/api/wot/attest', async ({ body }) => {
    const a = await store(body);
    return { ok: true, domain: a.domain };
  });

  route('POST', '/api/wot/vouch', async ({ body }) => {
    if (!body?.type?.includes('EmconPersonVouch') || !(await verifyCredential(body))) throw new HttpError(400, 'invalid vouch credential');
    const subject = body.credentialSubject?.id;
    try { pubFromDidKey(subject); } catch { throw new HttpError(400, 'subject must be a did:key'); }
    if (subject === body.issuer) throw new HttpError(400, 'cannot vouch for yourself');
    db.wot.vouches = db.wot.vouches.filter((v) => !(v.issuer === body.issuer && v.subject === subject));
    db.wot.vouches.push({ issuer: body.issuer, subject, weight: Number(body.credentialSubject.weight) || 0, vc: body });
    save();
    return { ok: true };
  });

  route('GET', '/api/wot/domain', ({ query }) => {
    const prefix = String(query.prefix || '').toLowerCase();
    if (!/^[0-9a-f]+$/.test(prefix) || prefix.length < MIN_PREFIX) throw new HttpError(400, `prefix must be >= ${MIN_PREFIX} hex chars`);
    return { attestations: db.wot.attestations.filter((a) => a.hash.startsWith(prefix)).map((a) => a.vc) };
  });

  // Vouches reachable from the caller's roots (2 hops); client verifies + scores locally.
  route('GET', '/api/wot/vouches', ({ query }) => {
    let frontier = new Set(String(query.issuers || '').split(',').filter(Boolean).slice(0, 50));
    const seen = new Set(frontier);
    const out = [];
    for (let hop = 0; hop < 2 && frontier.size; hop++) {
      const next = new Set();
      for (const v of db.wot.vouches) {
        if (!frontier.has(v.issuer)) continue;
        out.push(v.vc);
        if (!seen.has(v.subject)) { seen.add(v.subject); next.add(v.subject); }
      }
      frontier = next;
    }
    return { vouches: out };
  });
}

async function attestationFor({ domain, verdict, transacted, note }, privateKey, did) {
  return signCredential({
    '@context': VC_CONTEXT,
    type: ['VerifiableCredential', 'EmconDomainAttestation'],
    issuer: did,
    validFrom: new Date().toISOString(),
    credentialSubject: { id: 'dns:' + domain, domain, verdict, transacted, note },
  }, privateKey, did);
}

async function store(vc) {
  if (!vc?.type?.includes('EmconDomainAttestation') || !(await verifyCredential(vc))) throw new HttpError(400, 'invalid attestation credential');
  const s = vc.credentialSubject || {};
  const domain = normalizeDomain(s.domain);
  if (!domain || normalizeDomain(s.id?.replace(/^dns:/, '')) !== domain) throw new HttpError(400, 'subject domain mismatch');
  if (!['trusted', 'scam'].includes(s.verdict)) throw new HttpError(400, 'verdict must be trusted|scam');
  const a = { issuer: vc.issuer, domain, hash: await domainHash(domain), verdict: s.verdict, issued: vc.validFrom, vc };
  // one live attestation per (issuer, domain): re-attesting replaces, so spamming doesn't add weight
  db.wot.attestations = db.wot.attestations.filter((x) => !(x.issuer === a.issuer && x.domain === domain));
  db.wot.attestations.push(a);
  save();
  return a;
}

// Used by the vault's risk engine: does the security group flag this payee's website?
export function groupVerdict(domain) {
  const d = normalizeDomain(domain);
  const a = db.wot?.attestations.find((x) => x.issuer === group?.did && x.domain === d);
  return a ? { verdict: a.verdict, note: a.vc.credentialSubject.note, source: group.name } : null;
}
