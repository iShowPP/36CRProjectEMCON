// 64-bit difference hash: survives re-encoding, resizing and metadata stripping,
// which is exactly what social platforms do to uploaded images.

export async function dhash(source) {
  const c = new OffscreenCanvas(9, 8);
  const ctx = c.getContext('2d', { willReadFrequently: true });
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = 'high';
  ctx.drawImage(source, 0, 0, 9, 8);
  const d = ctx.getImageData(0, 0, 9, 8).data;
  const lum = (i) => d[i] * 299 + d[i + 1] * 587 + d[i + 2] * 114;
  let bits = 0n;
  for (let y = 0; y < 8; y++) {
    for (let x = 0; x < 8; x++) {
      const i = (y * 9 + x) * 4;
      bits = (bits << 1n) | (lum(i) > lum(i + 4) ? 1n : 0n);
    }
  }
  return bits.toString(16).padStart(16, '0');
}
