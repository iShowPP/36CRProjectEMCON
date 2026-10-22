// Content provenance manifests embedded in PNG / JPEG files ("C2PA-lite").
//
// The manifest binds a publisher's Ed25519 signature to a hash of the image's
// *pixel-defining* bytes, so metadata can change but any pixel edit is detected.
// It also carries a perceptual hash (soft binding) so provenance can be recovered
// from a registry after a platform strips metadata. Real C2PA manifests (JUMBF)
// are detected and reported, not verified here.

import { te, td, concat, sha256, toB64u, fromB64u, canonicalJson, ed25519Sign, ed25519Verify } from './util.js';

const PNG_SIG = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
const PNG_KEYWORD = 'emcon-provenance';
const JPEG_TAG = te.encode('EMCONPROV\0');
const C2PA_LABEL = te.encode('c2pa');

export function detectFormat(b) {
  if (b.length > 8 && PNG_SIG.every((x, i) => b[i] === x)) return 'png';
  if (b.length > 3 && b[0] === 0xff && b[1] === 0xd8) return 'jpeg';
  return null;
}

let CRC_TABLE;
function crc32(bytes) {
  if (!CRC_TABLE) {
    CRC_TABLE = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC_TABLE[n] = c >>> 0;
    }
  }
  let c = 0xffffffff;
  for (const x of bytes) c = CRC_TABLE[(c ^ x) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
const u32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const be32 = (n) => new Uint8Array([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const startsWith = (b, prefix) => prefix.every((x, i) => b[i] === x);
function indexOf(b, needle) {
  outer: for (let i = 0; i + needle.length <= b.length; i++) {
    for (let j = 0; j < needle.length; j++) if (b[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

// ---------- PNG ----------
function pngChunks(b) {
  const out = [];
  let o = 8;
  while (o + 12 <= b.length) {
    const len = u32(b, o);
    const type = td.decode(b.subarray(o + 4, o + 8));
    const end = o + 12 + len;
    if (end > b.length) break;
    out.push({ type, data: b.subarray(o + 8, o + 8 + len), start: o, end });
    o = end;
    if (type === 'IEND') break;
  }
  return out;
}
export function pngChunk(type, data) {
  const body = concat(te.encode(type), data);
  return concat(be32(data.length), body, be32(crc32(body)));
}
const isOurPngChunk = (c) => c.type === 'tEXt' && startsWith(c.data, te.encode(PNG_KEYWORD + '\0'));

// ---------- JPEG ----------
function jpegSegments(b) {
  const segs = [];
  let o = 2;
  while (o + 4 <= b.length) {
    if (b[o] !== 0xff) return null;
    const m = b[o + 1];
    if (m === 0xff) { o++; continue; }
    if (m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { segs.push({ marker: m, start: o, end: o + 2 }); o += 2; continue; }
    const end = o + 2 + ((b[o + 2] << 8) | b[o + 3]);
    if (end > b.length) return null;
    segs.push({ marker: m, start: o, end, payload: b.subarray(o + 4, end) });
    if (m === 0xda) { segs.push({ marker: 'scan', start: end, end: b.length }); break; }
    o = end;
  }
  return segs;
}
const isMetadataSeg = (s) => typeof s.marker === 'number' && ((s.marker >= 0xe0 && s.marker <= 0xef) || s.marker === 0xfe);
const isOurJpegSeg = (s) => s.marker === 0xeb && startsWith(s.payload, JPEG_TAG);

// ---------- format-independent API ----------

// Hash of pixel-defining bytes only: PNG critical chunks, JPEG non-APPn/COM segments + scan.
export async function contentHash(b) {
  const f = detectFormat(b);
  if (f === 'png') {
    const parts = pngChunks(b).filter((c) => /^[A-Z]/.test(c.type)).map((c) => b.subarray(c.start + 4, c.end - 4));
    return toB64u(await sha256(concat(...parts)));
  }
  if (f === 'jpeg') {
    const segs = jpegSegments(b);
    if (!segs) throw new Error('corrupt JPEG');
    return toB64u(await sha256(concat(...segs.filter((s) => !isMetadataSeg(s)).map((s) => b.subarray(s.start, s.end)))));
  }
  throw new Error('unsupported image format (PNG or JPEG only)');
}

export function extractManifest(b) {
  const format = detectFormat(b);
  let raw = null;
  let c2pa = false;
  if (format === 'png') {
    for (const c of pngChunks(b)) {
      if (isOurPngChunk(c)) raw = td.decode(c.data.subarray(PNG_KEYWORD.length + 1));
      if (c.type === 'caBX') c2pa = true;
    }
  } else if (format === 'jpeg') {
    for (const s of jpegSegments(b) || []) {
      if (s.marker !== 0xeb) continue;
      if (isOurJpegSeg(s)) raw = td.decode(s.payload.subarray(JPEG_TAG.length));
      else if (indexOf(s.payload, C2PA_LABEL) >= 0) c2pa = true;
    }
  }
  let manifest = null;
  try { manifest = raw && JSON.parse(raw); } catch { /* unreadable manifest == no manifest */ }
  return { format, manifest, c2pa };
}

const asciiJson = (v) => JSON.stringify(v).replace(/[\u007f-￿]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));

export function embedManifest(b, manifest) {
  const json = te.encode(asciiJson(manifest));
  const f = detectFormat(b);
  if (f === 'png') {
    const chunks = pngChunks(b);
    const rest = chunks.slice(1).filter((c) => !isOurPngChunk(c)).map((c) => b.subarray(c.start, c.end));
    const ours = pngChunk('tEXt', concat(te.encode(PNG_KEYWORD + '\0'), json));
    return concat(PNG_SIG, b.subarray(chunks[0].start, chunks[0].end), ours, ...rest);
  }
  if (f === 'jpeg') {
    const payload = concat(JPEG_TAG, json);
    if (payload.length > 65533) throw new Error('manifest too large for one APP11 segment');
    const seg = concat(new Uint8Array([0xff, 0xeb, (payload.length + 2) >> 8, (payload.length + 2) & 255]), payload);
    const segs = jpegSegments(b).filter((s) => !isOurJpegSeg(s));
    // keep JFIF/EXIF (APP0/APP1) first so strict decoders stay happy
    let i = 0;
    while (i < segs.length && (segs[i].marker === 0xe0 || segs[i].marker === 0xe1)) i++;
    const bytesOf = (s) => b.subarray(s.start, s.end);
    return concat(new Uint8Array([0xff, 0xd8]), ...segs.slice(0, i).map(bytesOf), seg, ...segs.slice(i).map(bytesOf));
  }
  throw new Error('unsupported image format');
}

export function stripManifest(b) {
  const f = detectFormat(b);
  if (f === 'png') {
    const chunks = pngChunks(b);
    return concat(PNG_SIG, ...chunks.filter((c) => !isOurPngChunk(c)).map((c) => b.subarray(c.start, c.end)));
  }
  if (f === 'jpeg') return concat(new Uint8Array([0xff, 0xd8]), ...jpegSegments(b).filter((s) => !isOurJpegSeg(s)).map((s) => b.subarray(s.start, s.end)));
  return b;
}

export async function signManifest(fields, privateKey) {
  return { ...fields, sig: toB64u(await ed25519Sign(privateKey, canonicalJson(fields))) };
}

/**
 * Statuses (deliberately never "fake"/"AI" — absence of provenance proves nothing):
 *   verified   valid signature from a key on the trust list, pixels untouched
 *   untrusted  valid signature, but from a key nobody vouches for
 *   altered    signature valid, pixels changed after signing
 *   forged     manifest present but signature does not verify
 *   c2pa       a real C2PA manifest is present (verify with a full C2PA validator)
 *   none       no provenance information at all
 */
export async function verifyImageBytes(b, trustList = []) {
  const { format, manifest, c2pa } = extractManifest(b);
  if (!format) return { status: 'unsupported' };
  if (!manifest) return { status: c2pa ? 'c2pa' : 'none', format };
  const { sig, ...fields } = manifest;
  const trusted = trustList.find((k) => k.keyId === fields.issuer?.keyId && !k.revoked);
  // A manifest that names a trusted keyId is checked against the trust-list key,
  // never against the public key it carries itself.
  let sigOk = false;
  try { sigOk = !!sig && (await ed25519Verify(fromB64u(trusted ? trusted.pub : fields.issuer?.pub || ''), fromB64u(sig), canonicalJson(fields))); } catch { /* malformed */ }
  if (!sigOk) return { status: 'forged', format, manifest: fields };
  const hashOk = (await contentHash(b)) === fields.contentHash?.value;
  if (!hashOk) return { status: 'altered', format, manifest: fields, trusted: !!trusted, issuerName: trusted?.name };
  return { status: trusted ? 'verified' : 'untrusted', format, manifest: fields, issuerName: trusted?.name };
}
