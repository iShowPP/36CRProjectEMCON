// 64-bit difference hash: survives re-encoding, resizing and metadata stripping,
// which is exactly what social platforms do to uploaded images.
//
// Each of the 9×8 cells is the average of a 16×16 block of a 144×128 copy, close to a true
// area average. The server computes the same hash straight from the file (server/imagehash.js),
// so both sides agree on photos they check independently.

const K = 16;
// a cell counts as brighter only by at least one grey level: flat areas (sky) stay 0 instead of
// following JPEG noise
const TIE = 1000;

export async function dhash(source) {
  const c = new OffscreenCanvas(9 * K, 8 * K);
  const ctx = c.getContext('2d', { willReadFrequently: true });
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = 'high';
  ctx.drawImage(source, 0, 0, 9 * K, 8 * K);
  const d = ctx.getImageData(0, 0, 9 * K, 8 * K).data;
  const lum = new Float64Array(72);
  for (let y = 0; y < 8 * K; y++) {
    for (let x = 0; x < 9 * K; x++) {
      const i = (y * 9 * K + x) * 4;
      lum[Math.floor(y / K) * 9 + Math.floor(x / K)] += d[i] * 299 + d[i + 1] * 587 + d[i + 2] * 114;
    }
  }
  let bits = 0n;
  for (let y = 0; y < 8; y++) {
    for (let x = 0; x < 8; x++) bits = (bits << 1n) | (lum[y * 9 + x] - lum[y * 9 + x + 1] > TIE * K * K ? 1n : 0n);
  }
  return bits.toString(16).padStart(16, '0');
}
