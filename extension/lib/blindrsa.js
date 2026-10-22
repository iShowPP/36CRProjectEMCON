// RSA blind signatures (Chaum) with a full-domain hash, in the spirit of RFC 9474 /
// Privacy Pass. The issuer signs a token without ever seeing it, so the token it
// later sees redeemed at a website cannot be linked back to the person it was issued to.

import { te, concat, sha256, bytesToBigInt, randomBytes } from './util.js';

export function modPow(b, e, m) {
  let r = 1n;
  b %= m;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    e >>= 1n;
    b = (b * b) % m;
  }
  return r;
}

export function modInv(a, m) {
  let [r0, r1] = [((a % m) + m) % m, m];
  let [s0, s1] = [1n, 0n];
  while (r1) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error('not invertible');
  return ((s0 % m) + m) % m;
}

const byteLen = (n) => Math.ceil(n.toString(16).length / 2);

// Full-domain hash: expand SHA-256 to the modulus size, reduce mod n.
export async function fdh(msg, n) {
  const k = byteLen(n);
  const blocks = [];
  for (let i = 0; blocks.length * 32 < k; i++) blocks.push(await sha256(concat(te.encode('EMCON-FDH-v1'), msg, new Uint8Array([i]))));
  return bytesToBigInt(concat(...blocks).subarray(0, k)) % n;
}

export async function blind(msg, { n, e }) {
  let r;
  do r = bytesToBigInt(randomBytes(byteLen(n))) % n; while (r < 2n);
  const m = await fdh(msg, n);
  return { blinded: (m * modPow(r, e, n)) % n, r };
}

export const unblind = (blindSig, r, n) => (blindSig * modInv(r, n)) % n;

export async function verify(msg, sig, { n, e }) {
  if (sig <= 0n || sig >= n) return false;
  return modPow(sig, e, n) === (await fdh(msg, n));
}

// Issuer side: s' = blinded^d mod n, computed with CRT.
export function signBlinded(blinded, { n, p, q, dp, dq, qi }) {
  if (blinded <= 1n || blinded >= n) throw new Error('blinded value out of range');
  const m1 = modPow(blinded, dp, p);
  const m2 = modPow(blinded, dq, q);
  const h = (qi * (((m1 - m2) % p) + p)) % p;
  return m2 + h * q;
}
