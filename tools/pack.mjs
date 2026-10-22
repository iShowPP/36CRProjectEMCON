// Packs extension/ into dist/emcon-extension-v<version>.zip for users to install
// (unzip → chrome://extensions → Load unpacked) or to upload to the Chrome Web Store.
// Run: npm run pack
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { ROOT, EXTENSION_DIR } from './browser.mjs';

const manifest = JSON.parse(fs.readFileSync(path.join(EXTENSION_DIR, 'manifest.json'), 'utf8'));
const FOLDER = 'emcon-extension';

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));
}

// Minimal ZIP writer (deflate, no zip64): plenty for an extension bundle.
function zip(entries) {
  const locals = [], central = [];
  let offset = 0;
  const now = new Date();
  const dosTime = (now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1);
  const dosDate = ((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate();
  for (const { name, data } of entries) {
    const nameBuf = Buffer.from(name, 'utf8');
    const deflated = zlib.deflateRawSync(data, { level: 9 });
    const crc = zlib.crc32(data);
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0); head.writeUInt16LE(20, 4); head.writeUInt16LE(0x0800, 6); head.writeUInt16LE(8, 8);
    head.writeUInt16LE(dosTime, 10); head.writeUInt16LE(dosDate, 12); head.writeUInt32LE(crc, 14);
    head.writeUInt32LE(deflated.length, 18); head.writeUInt32LE(data.length, 22); head.writeUInt16LE(nameBuf.length, 26);
    locals.push(head, nameBuf, deflated);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6); cd.writeUInt16LE(0x0800, 8); cd.writeUInt16LE(8, 10);
    cd.writeUInt16LE(dosTime, 12); cd.writeUInt16LE(dosDate, 14); cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(deflated.length, 20); cd.writeUInt32LE(data.length, 24); cd.writeUInt16LE(nameBuf.length, 28); cd.writeUInt32LE(offset, 42);
    central.push(cd, nameBuf);
    offset += head.length + nameBuf.length + deflated.length;
  }
  const cdBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cdBuf.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cdBuf, end]);
}

const files = walk(EXTENSION_DIR).sort();
const entries = files.map((f) => ({ name: `${FOLDER}/${path.relative(EXTENSION_DIR, f).split(path.sep).join('/')}`, data: fs.readFileSync(f) }));
const out = path.join(ROOT, 'dist', `emcon-extension-v${manifest.version}.zip`);
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, zip(entries));
console.log(`Packed ${entries.length} files → ${path.relative(ROOT, out)} (${(fs.statSync(out).size / 1024).toFixed(1)} KB)`);
console.log(`Users: unzip it, open chrome://extensions, turn on Developer mode, click "Load unpacked" and pick the "${FOLDER}" folder.`);
