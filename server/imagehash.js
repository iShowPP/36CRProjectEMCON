// The extension's 64-bit difference hash (extension/lib/dhash.js), computed on the server from
// the file itself: decode, apply the EXIF orientation like a browser does, average down to 9×8.

import zlib from 'node:zlib';
import jpeg from 'jpeg-js';

const u32 = (b, o) => b.readUInt32BE(o);

function exifOrientation(b) {
  let o = 2;
  while (o + 4 <= b.length && b[o] === 0xff) {
    const m = b[o + 1], len = b.readUInt16BE(o + 2);
    if (m === 0xda) break;
    if (m === 0xe1 && b.toString('latin1', o + 4, o + 10) === 'Exif\0\0') {
      const t = o + 10, le = b.toString('latin1', t, t + 2) === 'II';
      const r16 = (x) => (le ? b.readUInt16LE(x) : b.readUInt16BE(x)), r32 = (x) => (le ? b.readUInt32LE(x) : b.readUInt32BE(x));
      const ifd = t + r32(t + 4);
      for (let i = 0, n = r16(ifd); i < n; i++) {
        const e = ifd + 2 + i * 12;
        if (r16(e) === 0x0112) return r16(e + 8);
      }
      return 1;
    }
    o += 2 + len;
  }
  return 1;
}

// PNG: 8-bit grey, grey+alpha, RGB, RGBA or palette, not interlaced
function decodePng(b) {
  let o = 8, w, h, depth, type, inter, palette;
  const idat = [];
  while (o + 12 <= b.length) {
    const len = u32(b, o), t = b.toString('latin1', o + 4, o + 8), d = b.subarray(o + 8, o + 8 + len);
    if (t === 'IHDR') { w = u32(d, 0); h = u32(d, 4); depth = d[8]; type = d[9]; inter = d[12]; }
    else if (t === 'PLTE') palette = d;
    else if (t === 'IDAT') idat.push(d);
    else if (t === 'IEND') break;
    o += 12 + len;
  }
  if (depth !== 8 || inter) throw new Error('unsupported PNG');
  const ch = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }[type];
  const raw = zlib.inflateSync(Buffer.concat(idat));
  const stride = w * ch, out = Buffer.alloc(w * h * 4), prev = Buffer.alloc(stride), cur = Buffer.alloc(stride);
  for (let y = 0; y < h; y++) {
    const f = raw[y * (stride + 1)], row = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    for (let i = 0; i < stride; i++) {
      const a = i >= ch ? cur[i - ch] : 0, up = prev[i], c = i >= ch ? prev[i - ch] : 0;
      let p = row[i];
      if (f === 1) p += a; else if (f === 2) p += up; else if (f === 3) p += (a + up) >> 1;
      else if (f === 4) { const q = a + up - c, pa = Math.abs(q - a), pb = Math.abs(q - up), pc = Math.abs(q - c); p += pa <= pb && pa <= pc ? a : pb <= pc ? up : c; }
      cur[i] = p & 255;
    }
    for (let x = 0; x < w; x++) {
      const s = x * ch, d = (y * w + x) * 4;
      if (type === 3) { const k = cur[s] * 3; out[d] = palette[k]; out[d + 1] = palette[k + 1]; out[d + 2] = palette[k + 2]; }
      else if (ch <= 2) out[d] = out[d + 1] = out[d + 2] = cur[s];
      else { out[d] = cur[s]; out[d + 1] = cur[s + 1]; out[d + 2] = cur[s + 2]; }
    }
    cur.copy(prev);
  }
  return { width: w, height: h, data: out };
}

export function dhashOf(buf) {
  const b = Buffer.from(buf);
  const isJpeg = b[0] === 0xff && b[1] === 0xd8;
  const img = isJpeg ? jpeg.decode(b, { useTArray: true, formatAsRGBA: true, maxResolutionInMP: 50, maxMemoryUsageInMB: 256 }) : decodePng(b);
  const orient = isJpeg ? exifOrientation(b) : 1;
  const swap = orient >= 5;
  // average into a grid in the file's own orientation, then turn it like the browser would
  const gw = swap ? 8 : 9, gh = swap ? 9 : 8;
  const sum = new Float64Array(gw * gh), cnt = new Float64Array(gw * gh);
  const { width: W, height: H, data } = img;
  for (let y = 0; y < H; y++) {
    const gy = Math.min(gh - 1, Math.floor((y * gh) / H));
    for (let x = 0; x < W; x++) {
      const i = (y * W + x) * 4, g = gy * gw + Math.min(gw - 1, Math.floor((x * gw) / W));
      sum[g] += data[i] * 299 + data[i + 1] * 587 + data[i + 2] * 114;
      cnt[g]++;
    }
  }
  const lum = new Float64Array(72);
  for (let sy = 0; sy < gh; sy++) {
    for (let sx = 0; sx < gw; sx++) {
      let x = sx, y = sy;
      if (orient === 2) x = gw - 1 - sx;
      else if (orient === 3) { x = gw - 1 - sx; y = gh - 1 - sy; }
      else if (orient === 4) y = gh - 1 - sy;
      else if (orient === 5) { x = sy; y = sx; }
      else if (orient === 6) { x = gh - 1 - sy; y = sx; }
      else if (orient === 7) { x = gh - 1 - sy; y = gw - 1 - sx; }
      else if (orient === 8) { x = sy; y = gw - 1 - sx; }
      lum[y * 9 + x] = sum[sy * gw + sx] / cnt[sy * gw + sx];
    }
  }
  let bits = 0n;
  for (let y = 0; y < 8; y++) for (let x = 0; x < 8; x++) bits = (bits << 1n) | (lum[y * 9 + x] > lum[y * 9 + x + 1] ? 1n : 0n);
  return bits.toString(16).padStart(16, '0');
}
