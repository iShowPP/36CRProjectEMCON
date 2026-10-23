// Content Credentials (C2PA) validation for JPEG and PNG files, with no dependencies.
//
// For the active manifest this checks what a C2PA validator checks:
//   1. the claim signature (COSE_Sign1: ES256/384/512, PS256/384/512 or Ed25519) with the
//      signer certificate carried in the file,
//   2. every assertion the claim lists against its hash, so an edited assertion fails,
//   3. the hard binding (c2pa.hash.data): a hash of the whole file minus the manifest, so any
//      edit to the pixels fails,
//   4. the certificate chain, up to a trust anchor or a known signer certificate (the lists the
//      official verifier at contentcredentials.org/verify uses).
// Not covered: ingredient manifests, OCSP revocation and BMFF/box hashes (reported as such).

import { td, concat } from './util.js';

const subtle = globalThis.crypto.subtle;
const u32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// ---------- CBOR (RFC 8949), decode only what manifests use ----------
function cbor(b, o = 0) {
  if (o >= b.length) throw new Error('truncated CBOR');
  const ib = b[o++], mt = ib >> 5, ai = ib & 31;
  let n = ai;
  if (ai === 24) n = b[o++];
  else if (ai === 25) { n = (b[o] << 8) | b[o + 1]; o += 2; }
  else if (ai === 26) { n = u32(b, o); o += 4; }
  else if (ai === 27) { n = u32(b, o) * 2 ** 32 + u32(b, o + 4); o += 8; }
  else if (ai === 31 && mt >= 2 && mt <= 5) return indefinite(b, o, mt);
  else if (ai > 27) throw new Error('unsupported CBOR');
  switch (mt) {
    case 0: return [n, o];
    case 1: return [-1 - n, o];
    case 2: case 3: {
      if (o + n > b.length) throw new Error('truncated CBOR');
      const v = b.subarray(o, o + n);
      return [mt === 2 ? v : td.decode(v), o + n];
    }
    case 4: {
      const a = [];
      for (let i = 0; i < n; i++) { let v; [v, o] = cbor(b, o); a.push(v); }
      return [a, o];
    }
    case 5: {
      const m = {};
      for (let i = 0; i < n; i++) { let k, v; [k, o] = cbor(b, o); [v, o] = cbor(b, o); m[k] = v; }
      return [m, o];
    }
    case 6: return cbor(b, o); // tags (COSE_Sign1 is tag 18) carry nothing we need
    default: {
      if (ai === 20) return [false, o];
      if (ai === 21) return [true, o];
      if (ai === 22 || ai === 23) return [null, o];
      const dv = new DataView(b.buffer, b.byteOffset + o - (ai === 25 ? 2 : ai === 26 ? 4 : 8));
      return [ai === 26 ? dv.getFloat32(0) : ai === 27 ? dv.getFloat64(0) : n, o];
    }
  }
}
// indefinite-length strings, arrays and maps run until a 0xff "break"
function indefinite(b, o, mt) {
  const items = [];
  while (b[o] !== 0xff) {
    if (o >= b.length) throw new Error('truncated CBOR');
    let v;
    [v, o] = cbor(b, o);
    items.push(v);
  }
  o++;
  if (mt === 2) return [concat(...items), o];
  if (mt === 3) return [items.join(''), o];
  if (mt === 4) return [items, o];
  const m = {};
  for (let i = 0; i + 1 < items.length; i += 2) m[items[i]] = items[i + 1];
  return [m, o];
}
const decode = (b) => cbor(b)[0];

function cborHead(mt, n) {
  if (n < 24) return [(mt << 5) | n];
  if (n < 256) return [(mt << 5) | 24, n];
  if (n < 65536) return [(mt << 5) | 25, n >> 8, n & 255];
  return [(mt << 5) | 26, n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
}
const bstr = (b) => concat(new Uint8Array(cborHead(2, b.length)), b);

// ---------- JUMBF (ISO 19566-5) ----------
function boxes(b) {
  const out = [];
  let o = 0;
  while (o + 8 <= b.length) {
    let len = u32(b, o), h = 8;
    const type = td.decode(b.subarray(o + 4, o + 8));
    if (len === 1) { len = u32(b, o + 8) * 2 ** 32 + u32(b, o + 12); h = 16; } else if (len === 0) len = b.length - o;
    if (len < h || o + len > b.length) break;
    out.push({ type, data: b.subarray(o + h, o + len) });
    o += len;
  }
  return out;
}
// A JUMBF superbox: its label from the description box, and its content boxes
function superbox(box) {
  const kids = boxes(box.data);
  const d = kids[0];
  if (!d || d.type !== 'jumd' || d.data.length < 17) return null;
  let label = '';
  if (d.data[16] & 2) {
    const z = d.data.indexOf(0, 17);
    label = td.decode(d.data.subarray(17, z < 0 ? d.data.length : z));
  }
  return { label, box, kids: kids.slice(1) };
}
const subs = (sb) => sb.kids.filter((k) => k.type === 'jumb').map(superbox).filter(Boolean);
const content = (sb, type) => sb.kids.find((k) => k.type === type)?.data;

// The manifest store, from JPEG APP11 segments (JPEG XT boxes, possibly split) or a PNG caBX chunk
function jumbfFrom(b) {
  if (b[0] === 0xff && b[1] === 0xd8) {
    const parts = new Map();
    let o = 2;
    while (o + 4 <= b.length && b[o] === 0xff) {
      const m = b[o + 1];
      if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { o += 2; continue; }
      if (m === 0xda || m === 0xd9) break;
      const len = (b[o + 2] << 8) | b[o + 3];
      const p = b.subarray(o + 4, o + 2 + len);
      // APP11: "JP", box instance (2), packet sequence (4), then the box (header repeated in each packet)
      if (m === 0xeb && p[0] === 0x4a && p[1] === 0x50 && p.length > 16) {
        const en = (p[2] << 8) | p[3], z = u32(p, 4);
        const list = parts.get(en) || [];
        list.push({ z, body: p.subarray(8) });
        parts.set(en, list);
      }
      o += 2 + len;
    }
    for (const list of parts.values()) {
      list.sort((x, y) => x.z - y.z);
      const lbox = u32(list[0].body, 0), h = lbox === 1 ? 16 : 8;
      const whole = concat(list[0].body, ...list.slice(1).map((x) => x.body.subarray(h)));
      if (td.decode(whole.subarray(4, 8)) !== 'jumb') continue;
      const store = superbox(boxes(whole)[0] || { data: new Uint8Array() });
      if (store?.label === 'c2pa') return store;
    }
    return null;
  }
  if (b[0] === 0x89 && b[1] === 0x50) {
    let o = 8;
    while (o + 12 <= b.length) {
      const len = u32(b, o), type = td.decode(b.subarray(o + 4, o + 8));
      if (type === 'caBX') {
        const top = boxes(b.subarray(o + 8, o + 8 + len))[0];
        const store = top?.type === 'jumb' && superbox(top);
        return store?.label === 'c2pa' ? store : null;
      }
      if (type === 'IEND') break;
      o += 12 + len;
    }
  }
  return null;
}

// ---------- DER / X.509 ----------
function der(b, o) {
  const tag = b[o];
  let len = b[o + 1], h = 2;
  if (len & 0x80) {
    const k = len & 0x7f;
    len = 0;
    for (let i = 0; i < k; i++) len = len * 256 + b[o + 2 + i];
    h = 2 + k;
  }
  if (o + h + len > b.length) throw new Error('truncated DER');
  return { tag, start: o, body: o + h, end: o + h + len };
}
function kids(b, n) {
  const out = [];
  for (let o = n.body; o < n.end;) { const c = der(b, o); out.push(c); o = c.end; }
  return out;
}
const raw = (b, n) => b.subarray(n.start, n.end);
const body = (b, n) => b.subarray(n.body, n.end);
function oid(bytes) {
  const out = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let v = 0;
  for (let i = 1; i < bytes.length; i++) {
    v = v * 128 + (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) { out.push(v); v = 0; }
  }
  return out.join('.');
}
function derTime(b, n) {
  const s = td.decode(body(b, n));
  const y = n.tag === 0x17 ? (Number(s.slice(0, 2)) >= 50 ? 1900 : 2000) + Number(s.slice(0, 2)) : Number(s.slice(0, 4));
  const r = s.slice(n.tag === 0x17 ? 2 : 4);
  return Date.UTC(y, Number(r.slice(0, 2)) - 1, Number(r.slice(2, 4)), Number(r.slice(4, 6)), Number(r.slice(6, 8)), Number(r.slice(8, 10)) || 0);
}
function nameAttr(b, name, want) {
  for (const set of kids(b, name)) {
    for (const atv of kids(b, set)) {
      const [k, v] = kids(b, atv);
      if (oid(body(b, k)) === want) return td.decode(body(b, v));
    }
  }
  return null;
}

export function parseCert(c) {
  const root = der(c, 0);
  const [tbsN, algN, sigN] = kids(c, root);
  const t = kids(c, tbsN);
  let i = t[0].tag === 0xa0 ? 1 : 0;
  const issuerN = t[i + 2], validity = kids(c, t[i + 3]), subjectN = t[i + 4], spkiN = t[i + 5];
  const alg = kids(c, algN);
  const cert = {
    der: c,
    tbs: raw(c, tbsN),
    sigAlg: oid(body(c, alg[0])),
    sigParams: alg[1] && alg[1].tag === 0x30 ? raw(c, alg[1]) : null,
    sig: c.subarray(sigN.body + 1, sigN.end), // BIT STRING: skip the unused-bits byte
    issuer: raw(c, issuerN),
    subject: raw(c, subjectN),
    spki: raw(c, spkiN),
    notBefore: derTime(c, validity[0]),
    notAfter: derTime(c, validity[1]),
    cn: nameAttr(c, subjectN, '2.5.4.3'),
    org: nameAttr(c, subjectN, '2.5.4.10'),
    issuerCn: nameAttr(c, issuerN, '2.5.4.3'),
    issuerOrg: nameAttr(c, issuerN, '2.5.4.10'),
    eku: null,
  };
  const ext = t.find((n) => n.tag === 0xa3);
  if (ext) {
    for (const e of kids(c, kids(c, ext)[0])) {
      const f = kids(c, e);
      if (oid(body(c, f[0])) !== '2.5.29.37') continue;
      const val = f[f.length - 1]; // OCTET STRING holding a SEQUENCE of OIDs
      cert.eku = kids(c, der(c, val.body)).map((n) => oid(body(c, n)));
    }
  }
  return cert;
}

const HASH_OF = { '1.2.840.10045.4.3.2': 'SHA-256', '1.2.840.10045.4.3.3': 'SHA-384', '1.2.840.10045.4.3.4': 'SHA-512', '1.2.840.113549.1.1.11': 'SHA-256', '1.2.840.113549.1.1.12': 'SHA-384', '1.2.840.113549.1.1.13': 'SHA-512' };
const CURVE = { '1.2.840.10045.3.1.7': ['P-256', 32], '1.3.132.0.34': ['P-384', 48], '1.3.132.0.35': ['P-521', 66] };
const HASH_OID = { '2.16.840.1.101.3.4.2.1': 'SHA-256', '2.16.840.1.101.3.4.2.2': 'SHA-384', '2.16.840.1.101.3.4.2.3': 'SHA-512' };

function spkiInfo(spki) {
  const [algN] = kids(spki, der(spki, 0));
  const a = kids(spki, algN);
  return { oid: oid(body(spki, a[0])), param: a[1]?.tag === 0x06 ? oid(body(spki, a[1])) : null, bitString: kids(spki, der(spki, 0))[1] };
}
// WebCrypto only imports RSA keys labelled rsaEncryption, so relabel RSASSA-PSS keys
function rsaSpki(spki) {
  const info = spkiInfo(spki);
  if (info.oid === '1.2.840.113549.1.1.1') return spki;
  const algId = new Uint8Array([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
  const inner = concat(algId, raw(spki, info.bitString));
  return concat(derHead(0x30, inner.length), inner);
}
function derHead(tag, len) {
  if (len < 128) return new Uint8Array([tag, len]);
  if (len < 256) return new Uint8Array([tag, 0x81, len]);
  return new Uint8Array([tag, 0x82, len >> 8, len & 255]);
}
// ECDSA signatures in certificates are DER SEQUENCE { r, s }; WebCrypto wants r || s
function ecRaw(sig, size) {
  const [r, s] = kids(sig, der(sig, 0)).map((n) => body(sig, n));
  const fit = (x) => { while (x.length > size && x[0] === 0) x = x.subarray(1); const out = new Uint8Array(size); out.set(x, size - x.length); return out; };
  return concat(fit(r), fit(s));
}
function pssParams(p) {
  let hash = 'SHA-1', salt = 20;
  if (!p) return { hash, salt };
  for (const n of kids(p, der(p, 0))) {
    if (n.tag === 0xa0) hash = HASH_OID[oid(body(p, kids(p, kids(p, n)[0])[0]))] || hash;
    if (n.tag === 0xa2) salt = Number([...body(p, kids(p, n)[0])].reduce((v, x) => v * 256 + x, 0));
  }
  return { hash, salt };
}

// Verifies `sig` over `data` with the key in `spki`, for a certificate signature algorithm OID
async function verifyWith(spki, sigAlg, sigParams, sig, data) {
  const info = spkiInfo(spki);
  try {
    if (sigAlg.startsWith('1.2.840.10045.4.3.')) {
      const [curve, size] = CURVE[info.param] || [];
      if (!curve) return false;
      const key = await subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: curve }, false, ['verify']);
      return await subtle.verify({ name: 'ECDSA', hash: HASH_OF[sigAlg] }, key, ecRaw(sig, size), data);
    }
    if (HASH_OF[sigAlg]) {
      const key = await subtle.importKey('spki', rsaSpki(spki), { name: 'RSASSA-PKCS1-v1_5', hash: HASH_OF[sigAlg] }, false, ['verify']);
      return await subtle.verify('RSASSA-PKCS1-v1_5', key, sig, data);
    }
    if (sigAlg === '1.2.840.113549.1.1.10') {
      const { hash, salt } = pssParams(sigParams);
      const key = await subtle.importKey('spki', rsaSpki(spki), { name: 'RSA-PSS', hash }, false, ['verify']);
      return await subtle.verify({ name: 'RSA-PSS', saltLength: salt }, key, sig, data);
    }
    if (sigAlg === '1.3.101.112') {
      const key = await subtle.importKey('spki', spki, { name: 'Ed25519' }, false, ['verify']);
      return await subtle.verify('Ed25519', key, sig, data);
    }
  } catch { /* unsupported or malformed key */ }
  return false;
}

// COSE algorithm ids used by C2PA claim signatures
const COSE = { '-7': ['ECDSA', 'SHA-256'], '-35': ['ECDSA', 'SHA-384'], '-36': ['ECDSA', 'SHA-512'], '-37': ['RSA-PSS', 'SHA-256', 32], '-38': ['RSA-PSS', 'SHA-384', 48], '-39': ['RSA-PSS', 'SHA-512', 64], '-8': ['Ed25519'] };
const COSE_NAME = { '-7': 'ES256', '-35': 'ES384', '-36': 'ES512', '-37': 'PS256', '-38': 'PS384', '-39': 'PS512', '-8': 'Ed25519' };
async function coseVerify(alg, spki, sig, data) {
  const [name, hash, salt] = COSE[alg] || [];
  try {
    if (name === 'ECDSA') {
      const [curve] = CURVE[spkiInfo(spki).param] || [];
      const key = await subtle.importKey('spki', spki, { name, namedCurve: curve }, false, ['verify']);
      return await subtle.verify({ name, hash }, key, sig, data);
    }
    if (name === 'RSA-PSS') {
      const key = await subtle.importKey('spki', rsaSpki(spki), { name, hash }, false, ['verify']);
      return await subtle.verify({ name, saltLength: salt }, key, sig, data);
    }
    if (name === 'Ed25519') {
      const key = await subtle.importKey('spki', spki, { name }, false, ['verify']);
      return await subtle.verify(name, key, sig, data);
    }
  } catch { /* unsupported or malformed key */ }
  return false;
}

// EKUs a claim signing certificate may carry (the official verifier's store.cfg)
const SIGNING_EKU = new Set(['1.3.6.1.5.5.7.3.4', '1.3.6.1.5.5.7.3.36', '1.3.6.1.5.5.7.3.8', '1.3.6.1.5.5.7.3.9', '1.3.6.1.4.1.311.76.59.1.9', '1.3.6.1.4.1.62558.2.1']);

// The first GeneralizedTime in an RFC 3161 token is the TSTInfo genTime (it precedes the certificates)
function tokenTime(tok) {
  for (let i = 0; i + 17 < tok.length; i++) {
    if (tok[i] !== 0x18 || tok[i + 1] < 15 || tok[i + 1] > 24) continue;
    const s = td.decode(tok.subarray(i + 2, i + 2 + tok[i + 1]));
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(s);
    if (m) return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  }
  return null;
}
function tsaName(tok) {
  // the TSA's certificate subject: find a commonName after the token's TSTInfo
  for (let i = 0; i + 7 < tok.length; i++) {
    if (tok[i] === 0x06 && tok[i + 1] === 0x03 && tok[i + 2] === 0x55 && tok[i + 3] === 0x04 && tok[i + 4] === 0x03 && [0x0c, 0x13, 0x14].includes(tok[i + 5])) {
      const s = td.decode(tok.subarray(i + 7, i + 7 + tok[i + 6]));
      if (/time ?stamp|tsa/i.test(s)) return s;
    }
  }
  return null;
}

const ALG = { sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512' };

/** Trust data: { anchors: [Uint8Array DER], allowed: Set of base64 SHA-256 of signer certificates } */
export function trustFromPem(anchorsPem = '', allowedHashes = '') {
  const anchors = [...anchorsPem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)].map((m) => Uint8Array.from(atob(m[1].replace(/\s+/g, '')), (c) => c.charCodeAt(0)));
  const allowed = new Set(allowedHashes.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')));
  return { anchors, allowed };
}

const b64 = (b) => { let s = ''; for (const x of b) s += String.fromCharCode(x); return btoa(s); };

/**
 * Validates the active C2PA manifest in an image. Returns null when the file has none.
 *   signature  'valid' | 'invalid'
 *   assertions 'valid' | 'mismatch'      every assertion matches the hash in the signed claim
 *   binding    'valid' | 'mismatch' | 'unsupported'   the file bytes match the signed hash
 *   trust      'anchored' | 'known' | 'unknown'       the signer certificate's standing
 */
export async function validateC2pa(b, trust = { anchors: [], allowed: new Set() }) {
  const store = jumbfFrom(b);
  if (!store) return null;
  const manifests = subs(store);
  const active = manifests[manifests.length - 1];
  if (!active) return { error: 'empty manifest store' };
  const out = { manifest: active.label, manifests: manifests.length, errors: [] };
  const parts = subs(active);
  const claimBox = parts.find((p) => p.label === 'c2pa.claim' || p.label === 'c2pa.claim.v2');
  const sigBox = parts.find((p) => p.label === 'c2pa.signature');
  const assertionStore = parts.find((p) => p.label === 'c2pa.assertions');
  const claimBytes = claimBox && content(claimBox, 'cbor');
  if (!claimBytes || !sigBox || !assertionStore) return { ...out, signature: 'invalid', errors: ['the manifest is missing its claim or signature'] };
  const claim = decode(claimBytes);
  const gen = claim.claim_generator || (Array.isArray(claim.claim_generator_info) ? claim.claim_generator_info[0]?.name : claim.claim_generator_info?.name);
  Object.assign(out, { generator: gen || null, title: claim['dc:title'] || null, format: claim['dc:format'] || null });

  // 1. signature over the claim
  const cose = decode(content(sigBox, 'cbor'));
  const [protBytes, unprot = {}, , signature] = cose;
  const prot = protBytes.length ? decode(protBytes) : {};
  const x5 = prot[33] ?? unprot[33] ?? prot.x5chain ?? unprot.x5chain;
  const chain = (Array.isArray(x5) ? x5 : x5 ? [x5] : []).map(parseCert);
  out.alg = COSE_NAME[prot[1]] || String(prot[1]);
  const tst = unprot.sigTst?.tstTokens?.[0]?.val;
  out.signedAt = tst ? tokenTime(tst) : null;
  out.timestampAuthority = tst ? tsaName(tst) : null;
  if (!chain.length) { out.signature = 'invalid'; out.errors.push('no signer certificate'); }
  else {
    const toBeSigned = concat(new Uint8Array([0x84, 0x6a]), new TextEncoder().encode('Signature1'), bstr(protBytes), new Uint8Array([0x40]), bstr(claimBytes));
    out.signature = (await coseVerify(prot[1], chain[0].spki, signature, toBeSigned)) ? 'valid' : 'invalid';
    const s = chain[0];
    Object.assign(out, { signer: s.cn, signerOrg: s.org, issuer: s.issuerCn, issuerOrg: s.issuerOrg, certSha256: b64(new Uint8Array(await subtle.digest('SHA-256', s.der))) });
  }

  // 2. assertions named in the claim
  const listed = [...(claim.assertions || []), ...(claim.created_assertions || []), ...(claim.gathered_assertions || [])];
  const byLabel = new Map(subs(assertionStore).map((a) => [a.label, a]));
  const claimAlg = ALG[claim.alg] || 'SHA-256';
  out.assertions = 'valid';
  const labels = [];
  for (const ref of listed) {
    const label = String(ref.url || '').split('/').pop();
    labels.push(label);
    const a = byLabel.get(label);
    const h = a && new Uint8Array(await subtle.digest(ALG[ref.alg] || claimAlg, a.box.data));
    if (!a || !eq(h, ref.hash)) { out.assertions = 'mismatch'; out.errors.push(`assertion ${label} does not match the signed claim`); }
  }
  out.assertionLabels = labels;
  const actions = byLabel.get('c2pa.actions') || byLabel.get('c2pa.actions.v2');
  if (actions) {
    try { out.actions = (decode(content(actions, 'cbor')).actions || []).map((x) => x.action).filter(Boolean); } catch { /* optional */ }
  }

  // 3. hard binding: the file minus the excluded ranges
  const dataHash = byLabel.get('c2pa.hash.data');
  if (!dataHash) out.binding = 'unsupported';
  else {
    const h = decode(content(dataHash, 'cbor'));
    const ex = (h.exclusions || []).map((e) => [e.start, e.start + e.length]).sort((x, y) => x[0] - y[0]);
    const pieces = [];
    let at = 0;
    for (const [s, e] of ex) { if (s > at) pieces.push(b.subarray(at, s)); at = Math.max(at, e); }
    pieces.push(b.subarray(at));
    const got = new Uint8Array(await subtle.digest(ALG[h.alg] || claimAlg, concat(...pieces)));
    out.binding = eq(got, h.hash) ? 'valid' : 'mismatch';
    if (out.binding === 'mismatch') out.errors.push('the image bytes changed after signing');
  }

  // 4. certificate chain and trust
  out.trust = 'unknown';
  if (chain.length && out.signature === 'valid') {
    const at = out.signedAt || Date.now();
    const s = chain[0];
    out.certValid = s.notBefore <= at && at <= s.notAfter;
    out.ekuOk = !s.eku || s.eku.some((x) => SIGNING_EKU.has(x));
    let linked = true;
    for (let k = 0; k + 1 < chain.length && linked; k++) {
      linked = eq(chain[k].issuer, chain[k + 1].subject) && (await verifyWith(chain[k + 1].spki, chain[k].sigAlg, chain[k].sigParams, chain[k].sig, chain[k].tbs));
    }
    let anchored = false;
    if (linked) {
      const top = chain[chain.length - 1];
      for (const a of trust.anchors || []) {
        if (eq(a, top.der) || chain.some((c) => eq(c.der, a))) { anchored = true; break; }
        const ac = parseCert(a);
        if (eq(ac.subject, top.issuer) && (await verifyWith(ac.spki, top.sigAlg, top.sigParams, top.sig, top.tbs))) { anchored = true; out.anchor = ac.cn || ac.org; break; }
      }
    }
    const known = trust.allowed?.has(out.certSha256);
    if (out.certValid && out.ekuOk) out.trust = anchored ? 'anchored' : known ? 'known' : 'unknown';
    if (!linked) out.errors.push('the certificate chain does not link up');
    if (!out.certValid) out.errors.push('the signer certificate was not valid at signing time');
  }
  return out;
}
