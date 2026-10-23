import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DATA_DIR = process.env.EMCON_DATA || path.join(ROOT, 'data');
export const MEDIA_DIR = path.join(DATA_DIR, 'media');
fs.mkdirSync(MEDIA_DIR, { recursive: true });

const FILE = path.join(DATA_DIR, 'db.json');

// One JSON document holds everything. With DATABASE_URL (Postgres, e.g. Render's) it is kept in
// the database, so accounts, family, keys and ratings survive restarts and redeploys; without
// it, in data/db.json for local development and tests.
const DATABASE_URL = process.env.DATABASE_URL || '';
let pool = null;

async function load() {
  if (!DATABASE_URL) return fs.existsSync(FILE) ? JSON.parse(fs.readFileSync(FILE, 'utf8')) : {};
  const { default: pg } = await import('pg');
  const local = /@(localhost|127\.0\.0\.1)[:/]/.test(DATABASE_URL);
  pool = new pg.Pool({ connectionString: DATABASE_URL, max: 2, ssl: local ? false : { rejectUnauthorized: false } });
  pool.on('error', (e) => console.error('[store] Postgres pool error:', e.message));
  await pool.query('create table if not exists emcon_state (id int primary key, doc jsonb not null, saved_at timestamptz not null default now())');
  const r = await pool.query('select doc from emcon_state where id = 1');
  console.log(`[store] using Postgres (${r.rows.length ? 'existing data' : 'new database'})`);
  return r.rows[0]?.doc || {};
}
async function loadSafely() {
  try { return await load(); } catch (e) {
    // never take the site down because the database is unreachable: fall back to the file
    console.error('[store] Postgres unavailable, using local file storage:', e.message);
    pool = null;
    return fs.existsSync(FILE) ? JSON.parse(fs.readFileSync(FILE, 'utf8')) : {};
  }
}
export const db = await loadSafely();
export const persistent = !!pool;

let timer;
let writing = Promise.resolve();
export function save() {
  clearTimeout(timer);
  timer = setTimeout(flush, 150);
}
export function flush() {
  clearTimeout(timer);
  const json = JSON.stringify(db);
  if (!pool) { fs.writeFileSync(FILE, json); return writing; }
  // writes go one after another, newest last
  writing = writing.then(() => pool.query(
    'insert into emcon_state (id, doc, saved_at) values (1, $1, now()) on conflict (id) do update set doc = excluded.doc, saved_at = now()', [json],
  )).catch((e) => console.error('[store] save failed:', e.message));
  return writing;
}

export class HttpError extends Error {
  constructor(status, message, data) {
    super(message);
    this.status = status;
    this.data = data;
  }
}
