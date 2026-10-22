// Shared encoding + crypto helpers. Pure Web Crypto, so the same file runs in the
// extension (service worker, pages) and on the server (Node 24 globalThis.crypto).

export const te = new TextEncoder();
export const td = new TextDecoder();
const subtle = globalThis.crypto.subtle;
const asBytes = (d) => (typeof d === 'string' ? te.encode(d) : d);

export const randomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export function concat(...parts) {
  const arrs = parts.map((p) => (typeof p === 'string' ? te.encode(p) : p instanceof Uint8Array ? p : new Uint8Array(p)));
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export function fromHex(h) {
  if (h.length % 2) h = '0' + h;
  const out = new Uint8Array(h.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

export function toB64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
export function fromB64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
export const toB64u = (b) => toB64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const fromB64u = (s) => fromB64(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));

export const sha256 = async (data) => new Uint8Array(await subtle.digest('SHA-256', asBytes(data)));

export async function hmacSha256(key, data) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, asBytes(data)));
}

// JCS-style canonical JSON (RFC 8785 for the value types we use: no floats with exponents).
export function canonicalJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']';
  return '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort()
    .map((k) => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}';
}

export const bytesToBigInt = (b) => (b.length ? BigInt('0x' + toHex(b)) : 0n);
export function bigIntToBytes(x, len) {
  const raw = fromHex(x.toString(16));
  if (!len) return raw;
  const out = new Uint8Array(len);
  out.set(raw, len - raw.length);
  return out;
}

// --- base58btc + did:key (Ed25519, multicodec 0xed01) ---
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function base58Encode(bytes) {
  let x = bytesToBigInt(bytes);
  let s = '';
  while (x > 0n) { s = B58[Number(x % 58n)] + s; x /= 58n; }
  for (const b of bytes) { if (b !== 0) break; s = '1' + s; }
  return s;
}
export function base58Decode(s) {
  let x = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error('bad base58');
    x = x * 58n + BigInt(i);
  }
  let lead = 0;
  for (const c of s) { if (c !== '1') break; lead++; }
  return concat(new Uint8Array(lead), x > 0n ? bigIntToBytes(x) : new Uint8Array(0));
}
export const didKeyFromPub = (pub) => 'did:key:z' + base58Encode(concat(new Uint8Array([0xed, 0x01]), pub));
export function pubFromDidKey(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) throw new Error('not a did:key');
  const raw = base58Decode(did.slice(9));
  if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) throw new Error('not an Ed25519 did:key');
  return raw.slice(2);
}

// --- Ed25519 (deterministic keys from a 32-byte seed) ---
const ED_PKCS8_PREFIX = fromHex('302e020100300506032b657004220420');
export async function ed25519FromSeed(seed) {
  const privateKey = await subtle.importKey('pkcs8', concat(ED_PKCS8_PREFIX, seed), { name: 'Ed25519' }, true, ['sign']);
  const jwk = await subtle.exportKey('jwk', privateKey);
  return { privateKey, pub: fromB64u(jwk.x) };
}
export const ed25519Sign = async (privateKey, data) =>
  new Uint8Array(await subtle.sign({ name: 'Ed25519' }, privateKey, asBytes(data)));
export async function ed25519Verify(pub, sig, data) {
  try {
    const k = await subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
    return await subtle.verify({ name: 'Ed25519' }, k, sig, asBytes(data));
  } catch {
    return false;
  }
}

// Popcount of XOR between two equal-length hex strings (used by dHash + SimHash).
export function hamming(a, b) {
  let x = BigInt('0x' + a) ^ BigInt('0x' + b);
  let n = 0;
  while (x) { n += Number(x & 1n); x >>= 1n; }
  return n;
}
