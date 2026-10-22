// Independent timestamps for evidence receipts. The client sends only a SHA-256 digest;
// the server signs "digest + current time" with its own key, so a receipt can prove
// *when* it existed without the server ever seeing what it says.

import { HttpError } from './store.js';
import { ed25519Jwk } from './keys.js';
import { TIMESTAMP_PREFIX } from '../extension/lib/receipt.js';
import { fromB64u, toB64u, ed25519FromSeed, ed25519Sign, didKeyFromPub } from '../extension/lib/util.js';

export default async function timestamp(route) {
  const { privateKey, pub } = await ed25519FromSeed(fromB64u(ed25519Jwk('timestamp').d));
  const did = didKeyFromPub(pub);

  route('GET', '/api/timestamp/key', () => ({ did }));

  route('POST', '/api/timestamp', async ({ body }) => {
    const digest = String(body.digest || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(digest)) throw new HttpError(400, 'digest must be a hex SHA-256');
    const time = new Date().toISOString();
    const sig = toB64u(await ed25519Sign(privateKey, `${TIMESTAMP_PREFIX}|${digest}|${time}`));
    return { digest, time, signer: did, sig };
  });
}
