// Renders the EMCON shield icon to extension/icons/icon{16,32,48,128}.png (no dependencies).
// Run: node tools/make-icons.mjs
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { ROOT } from './browser.mjs';
import { pngChunk } from '../extension/lib/provenance.js';
import { concat } from '../extension/lib/util.js';

// Shield outline in unit coordinates: flat top, straight sides, curving to a point.
function insideShield(x, y) {
  const top = 0.07, shoulder = 0.52, bottom = 0.95, half = 0.41;
  if (y < top || y > bottom) return false;
  const w = y < shoulder ? half : half * Math.sqrt(Math.max(0, 1 - ((y - shoulder) / (bottom - shoulder)) ** 2));
  return Math.abs(x - 0.5) <= w;
}

// Same outline scaled about the centre, used for the thin inner line.
const insideInset = (x, y, k) => insideShield(0.5 + (x - 0.5) / k, 0.5 + (y - 0.5) / k);

const INK = [0x17, 0x17, 0x1a], PAPER = [0xf5, 0xf2, 0xeb], SIGNAL = [0xc2, 0x41, 0x0c];

function render(size) {
  const SS = 4; // supersampling for anti-aliased edges
  const line = size >= 32; // the inner line only reads at larger sizes
  const rows = [];
  for (let py = 0; py < size; py++) {
    const row = Buffer.alloc(1 + size * 4);
    for (let px = 0; px < size; px++) {
      let cover = 0;
      const acc = [0, 0, 0];
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const x = (px + (sx + 0.5) / SS) / size, y = (py + (sy + 0.5) / SS) / size;
          if (!insideShield(x, y)) continue;
          cover++;
          // flat ink shield, a paper inner outline, one signal-orange bar
          const bar = y > 0.43 && y < 0.53 && Math.abs(x - 0.5) < 0.2;
          const inner = line && insideInset(x, y, 0.8) && !insideInset(x, y, 0.72);
          const c = bar ? SIGNAL : inner ? PAPER : INK;
          acc[0] += c[0]; acc[1] += c[1]; acc[2] += c[2];
        }
      }
      const rgb = cover ? acc.map((v) => Math.round(v / cover)) : INK;
      row.set([...rgb, Math.round((cover / (SS * SS)) * 255)], 1 + px * 4);
    }
    rows.push(row);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4); ihdr[8] = 8; ihdr[9] = 6; // 8-bit RGBA
  return concat(new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]), pngChunk('IHDR', ihdr), pngChunk('IDAT', zlib.deflateSync(Buffer.concat(rows))), pngChunk('IEND', new Uint8Array(0)));
}

const dir = path.join(ROOT, 'extension', 'icons');
fs.mkdirSync(dir, { recursive: true });
for (const s of [16, 32, 48, 128]) {
  fs.writeFileSync(path.join(dir, `icon${s}.png`), render(s));
  console.log(`wrote extension/icons/icon${s}.png`);
}
