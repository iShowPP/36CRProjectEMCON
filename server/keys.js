// Every server key is derived from ONE secret, so a host that wipes its disk on restart
// (Render/Fly free tiers) comes back with the same keys. Without this, a restart would
// rotate the issuer keys and every installed extension would (rightly) refuse them.
//
// Secret source: EMCON_SECRET (set it once on your host; Render generates it), else a
// random secret stored in <data>/secret.key on first run.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DATA_DIR } from './store.js';
import { modInv } from '../extension/lib/blindrsa.js';

let SECRET;
function secret() {
  if (SECRET) return SECRET;
  if (process.env.EMCON_SECRET) return (SECRET = crypto.createHash('sha256').update(process.env.EMCON_SECRET).digest());
  const file = path.join(DATA_DIR, 'secret.key');
  if (!fs.existsSync(file)) fs.writeFileSync(file, crypto.randomBytes(32).toString('hex'));
  return (SECRET = Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex'));
}

// HMAC-based deterministic byte stream for one label.
function stream(label) {
  let counter = 0;
  return (n) => {
    const out = [];
    let len = 0;
    while (len < n) {
      const block = crypto.createHmac('sha256', secret()).update(`emcon-key|${label}|${counter++}`).digest();
      out.push(block);
      len += block.length;
    }
    return Buffer.concat(out).subarray(0, n);
  };
}

const b64u = (x) => {
  let h = x.toString(16);
  if (h.length % 2) h = '0' + h;
  return Buffer.from(h, 'hex').toString('base64url');
};
const gcd = (a, b) => (b ? gcd(b, a % b) : a);

function prime(rand, bits, e) {
  // top two bits set so p*q is exactly 2*bits long; odd
  let c = BigInt('0x' + rand(bits / 8).toString('hex')) | (1n << BigInt(bits - 1)) | (1n << BigInt(bits - 2)) | 1n;
  while (!(crypto.checkPrimeSync(c) && gcd(c - 1n, e) === 1n)) c += 2n;
  return c;
}

/** Deterministic 2048-bit RSA key (JWK) for `label`. */
export function rsaJwk(label) {
  const rand = stream('rsa|' + label);
  const e = 65537n;
  const p = prime(rand, 1024, e);
  let q;
  do q = prime(rand, 1024, e); while (q === p);
  const n = p * q;
  const d = modInv(e, (p - 1n) * (q - 1n));
  return { kty: 'RSA', n: b64u(n), e: b64u(e), d: b64u(d), p: b64u(p), q: b64u(q), dp: b64u(d % (p - 1n)), dq: b64u(d % (q - 1n)), qi: b64u(modInv(q, p)) };
}

/** Deterministic Ed25519 key (JWK) for `label`. */
export function ed25519Jwk(label) {
  const seed = stream('ed25519|' + label)(32);
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  return crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' }).export({ format: 'jwk' });
}
