// W3C Verifiable Credentials 2.0 with a Data Integrity proof using the
// `eddsa-jcs-2022` cryptosuite (Ed25519 over JCS-canonicalised JSON), issued by did:key.

import { concat, sha256, canonicalJson, base58Encode, base58Decode, ed25519Sign, ed25519Verify, pubFromDidKey } from './util.js';

export const VC_CONTEXT = ['https://www.w3.org/ns/credentials/v2'];

async function hashData(doc, proofConfig) {
  return concat(await sha256(canonicalJson(proofConfig)), await sha256(canonicalJson(doc)));
}

export async function signCredential(doc, privateKey, did) {
  const proof = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: new Date().toISOString(),
    verificationMethod: `${did}#${did.slice('did:key:'.length)}`,
    proofPurpose: 'assertionMethod',
  };
  const sig = await ed25519Sign(privateKey, await hashData(doc, { ...proof, '@context': doc['@context'] }));
  return { ...doc, proof: { ...proof, proofValue: 'z' + base58Encode(sig) } };
}

export async function verifyCredential(vc) {
  try {
    const { proof, ...doc } = vc;
    if (!proof || proof.cryptosuite !== 'eddsa-jcs-2022' || !proof.proofValue?.startsWith('z')) return false;
    if (!proof.verificationMethod?.startsWith(doc.issuer + '#')) return false;
    const { proofValue, ...config } = proof;
    return await ed25519Verify(pubFromDidKey(doc.issuer), base58Decode(proofValue.slice(1)), await hashData(doc, { ...config, '@context': doc['@context'] }));
  } catch {
    return false;
  }
}
