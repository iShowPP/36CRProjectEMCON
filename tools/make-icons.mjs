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

function distToSegment(px, py, [ax, ay], [bx, by]) {
  const dx = bx - ax, dy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}
const CHECK = [[0.31, 0.5], [0.45, 0.64], [0.7, 0.36]];
const onCheck = (x, y) => distToSegment(x, y, CHECK[0], CHECK[1]) < 0.065 || distToSegment(x, y, CHECK[1], CHECK[2]) < 0.065;

function render(size) {
  const SS = 4; // supersampling for anti-aliased edges
  const rows = [];
  for (let py = 0; py < size; py++) {
    const row = Buffer.alloc(1 + size * 4);
    for (let px = 0; px < size; px++) {
      let cover = 0, white = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const x = (px + (sx + 0.5) / SS) / size, y = (py + (sy + 0.5) / SS) / size;
          if (insideShield(x, y)) { cover++; if (onCheck(x, y)) white++; }
        }
      }
      const a = cover / (SS * SS);
      const w = cover ? white / cover : 0;
      const g = py / size; // vertical gradient #3d6bff -> #1f3fbf
      const base = [0x3d + (0x1f - 0x3d) * g, 0x6b + (0x3f - 0x6b) * g, 0xff + (0xbf - 0xff) * g];
      const rgb = base.map((c) => Math.round(c * (1 - w) + 255 * w));
      row.set([...rgb, Math.round(a * 255)], 1 + px * 4);
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
