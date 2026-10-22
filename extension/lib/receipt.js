// Evidence receipts: a W3C Verifiable Credential signed by the user's EMCON key, plus an
// independent timestamp from the EMCON server over the receipt's digest. The server only
// ever sees the digest, never the receipt's contents.

import { canonicalJson, sha256, toHex, fromB64u, ed25519Verify, pubFromDidKey } from './util.js';
import { verifyCredential } from './vc.js';

export const TIMESTAMP_PREFIX = 'EMCON-TIMESTAMP-v1';

/** Digest the timestamp covers: the receipt without its proof and without the timestamp itself. */
export async function receiptDigest(doc) {
  const { proof, evidenceTimestamp, ...rest } = doc;
  return toHex(await sha256(canonicalJson(rest)));
}

export async function verifyReceipt(vc, { timestampDid } = {}) {
  const signature = await verifyCredential(vc);
  const t = vc.evidenceTimestamp;
  let timestamp = { status: 'missing' };
  if (t) {
    const digestOk = t.digest === (await receiptDigest(vc));
    let sigOk = false;
    try { sigOk = await ed25519Verify(pubFromDidKey(t.signer), fromB64u(t.sig), `${TIMESTAMP_PREFIX}|${t.digest}|${t.time}`); } catch { /* malformed */ }
    const known = !timestampDid || t.signer === timestampDid;
    timestamp = { status: digestOk && sigOk && known ? 'valid' : 'invalid', time: t.time, signer: t.signer, digestOk, sigOk, known };
  }
  return { signature, signer: vc.issuer, timestamp };
}
