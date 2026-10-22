// Web-of-Trust attestation relay.
//
// The server is a dumb, untrusted mailbox: it stores signed W3C credentials and
// hands them back. Clients re-verify every signature and compute trust locally,
// so a compromised relay can withhold data but cannot forge reputation.
//
// Privacy: lookups use a short SHA-256 prefix of the domain (k-anonymity, like
// Safe Browsing), so the relay never learns which exact site you are visiting.
//
// Two built-in sources users follow by default:
//  * EMCON SecOps (demo)      hand-curated reports, including the demo scam sites
//  * OpenPhish live feed      real phishing sites, imported every 6 hours and signed
//                             by the feed's own key, so it is just another attester

import fs from 'node:fs';
import path from 'node:path';
import { db, save, HttpError, ROOT } from './store.js';
import { ed25519Jwk } from './keys.js';
import { OFFICIAL_HOST, ALT_HOST } from './config.js';
import { REAL_BRANDS, SHARED_HOSTS } from './brands.js';
import { verifyCredential, signCredential, VC_CONTEXT } from '../extension/lib/vc.js';
import { toHex, sha256, fromB64u, ed25519FromSeed, didKeyFromPub, pubFromDidKey } from '../extension/lib/util.js';
import { domTokens, simhash64 } from '../extension/lib/simhash.js';

const MIN_PREFIX = 4;
const FEED_URL = process.env.EMCON_FEED_URL || 'https://openphish.com/feed.txt';
const FEED_ON = process.env.EMCON_FEED !== 'off';
const FEED_EVERY = 6 * 3600e3;
let group, feed; // signing identities of the two built-in sources
let brands = [];

export const normalizeDomain = (d) => String(d || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/:].*$/, '').replace(/^www\./, '');
const domainHash = async (d) => toHex(await sha256(normalizeDomain(d)));
const isOfficialBrandHost = (host) => REAL_BRANDS.some((b) => b.domains.some((d) => host === d || host.endsWith('.' + d)));

async function identity(keyName, label, name, description) {
  db.wot[keyName] ||= ed25519Jwk(label);
  const { privateKey, pub } = await ed25519FromSeed(fromB64u(db.wot[keyName].d));
  return { did: didKeyFromPub(pub), privateKey, name, description };
}

export default async function wot(route) {
  db.wot ||= { attestations: [], vouches: [] };
  group = await identity('groupKey', 'wot/secops', 'EMCON SecOps Collective (demo)', 'Volunteer analysts who triage reported scams and phishing kits.');
  feed = await identity('feedKey', 'wot/openphish', 'OpenPhish live feed (via EMCON)', 'Phishing sites currently listed in the OpenPhish community feed (openphish.com), refreshed every 6 hours.');
  save();

  // Demo reports: added if missing, so a hosted deployment gets reports for its own hostnames.
  const seed = [
    ALT_HOST && { domain: ALT_HOST, verdict: 'scam', transacted: false, note: 'Clone of the Kestrel Bank login page harvesting passwords' },
    { domain: 'cryptoyield-pro.xyz', verdict: 'scam', transacted: false, note: 'Pig-butchering "investment platform"; victims cannot withdraw' },
    { domain: OFFICIAL_HOST, verdict: 'trusted', transacted: true, note: 'Official Kestrel Bank (demo)' },
  ].filter(Boolean);
  for (const s of seed) {
    if (!db.wot.attestations.some((a) => a.issuer === group.did && a.domain === s.domain)) await store(await attestationFor(s, group));
  }

  // Brands: the demo bank (with a structural fingerprint of its real login page) + real brands.
  const official = fs.readFileSync(path.join(ROOT, 'web', 'bank-login.html'), 'utf8');
  brands = [
    { name: 'Kestrel Bank', domains: [OFFICIAL_HOST, 'kestrel-bank.example'], keywords: ['kestrel bank', 'kestrel'], tokens: [], simhash: simhash64(domTokens(official)) },
    // fictional shop impersonated by the scam-chain demo (never a real brand on a public page)
    { name: 'QuickKart', domains: ['quickkart.example'], keywords: ['quickkart'], tokens: ['quickkart'], simhash: null },
    ...REAL_BRANDS.map((b) => ({ ...b, keywords: b.tokens, simhash: null })),
  ];

  if (FEED_ON) {
    refreshFeed();
    setInterval(refreshFeed, FEED_EVERY).unref();
  }

  route('GET', '/api/wot/groups', () => [
    { did: group.did, name: group.name, description: group.description, defaultWeight: 0.8 },
    { did: feed.did, name: feed.name, description: feed.description, defaultWeight: 0.9 },
  ]);
  route('GET', '/api/wot/brands', () => brands);

  route('GET', '/api/wot/feed', ({ query }) => {
    const hosts = db.wot.attestations.filter((a) => a.issuer === feed.did).map((a) => a.domain);
    const n = Math.min(20, Math.max(0, Number(query.limit) || 0));
    const sample = [...hosts].sort(() => Math.random() - 0.5).slice(0, n);
    return { enabled: FEED_ON, ...(db.wot.feed || {}), count: hosts.length, sample };
  });

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

// Feed URLs -> attacker-controlled hostnames. Shared hosts (where only the path is the
// attacker's) and real brands' own domains are skipped so we never flag e.g. docs.google.com.
export function feedHosts(text) {
  const hosts = new Set();
  for (const line of text.split(/\r?\n/)) {
    let host;
    try { host = normalizeDomain(new URL(line.trim()).hostname); } catch { continue; }
    if (!host || SHARED_HOSTS.has(host) || isOfficialBrandHost(host)) continue;
    hosts.add(host);
  }
  return [...hosts];
}

async function refreshFeed() {
  try {
    const r = await fetch(FEED_URL, { redirect: 'follow' });
    if (!r.ok) throw new Error(`feed returned HTTP ${r.status}`);
    const hosts = feedHosts(await r.text()).slice(0, 5000);
    const current = new Set(hosts);
    // sites that left the feed lose the feed's report
    db.wot.attestations = db.wot.attestations.filter((a) => a.issuer !== feed.did || current.has(a.domain));
    const have = new Set(db.wot.attestations.filter((a) => a.issuer === feed.did).map((a) => a.domain));
    const day = new Date().toISOString().slice(0, 10);
    for (const host of hosts) {
      if (!have.has(host)) await store(await attestationFor({ domain: host, verdict: 'scam', transacted: false, note: `Listed in the OpenPhish community phishing feed (${day})` }, feed));
    }
    db.wot.feed = { updated: new Date().toISOString(), source: FEED_URL.startsWith('data:') ? 'inline test feed' : FEED_URL, error: null };
    console.log(`[wot] phishing feed: ${hosts.length} live phishing hosts`);
  } catch (e) {
    db.wot.feed = { ...(db.wot.feed || {}), error: String(e.message || e) };
    console.warn('[wot] phishing feed unavailable:', e.message);
  }
  save();
}

async function attestationFor({ domain, verdict, transacted, note }, signer) {
  return signCredential({
    '@context': VC_CONTEXT,
    type: ['VerifiableCredential', 'EmconDomainAttestation'],
    issuer: signer.did,
    validFrom: new Date().toISOString(),
    credentialSubject: { id: 'dns:' + domain, domain, verdict, transacted, note },
  }, signer.privateKey, signer.did);
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

// Used by the vault's risk engine: do the built-in sources flag this payee's website?
export function groupVerdict(domain) {
  const d = normalizeDomain(domain);
  for (const src of [group, feed]) {
    const a = db.wot?.attestations.find((x) => x.issuer === src?.did && x.domain === d);
    if (a) return { verdict: a.verdict, note: a.vc.credentialSubject.note, source: src.name };
  }
  return null;
}
