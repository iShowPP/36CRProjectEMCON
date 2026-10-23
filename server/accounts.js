// EMCON accounts: the SaaS layer. Email + password or EMCON Ghost sign-in, cookie sessions,
// a recovery key instead of email resets, family devices that report weekly counts (never
// which sites anyone visits), plans, and API keys for the paid link-check API.
//
// Security: scrypt password hashes, only SHA-256 hashes of session tokens / API keys /
// recovery keys are stored, HttpOnly + SameSite=Lax cookies (Secure when hosted), same-origin
// check on every state-changing call, rate limits on sign-in, single-use Ghost challenges.

import crypto from 'node:crypto';
import { db, save, HttpError } from './store.js';
import { HOSTED } from './config.js';
import { checkPresentation, spendToken } from './rp.js';
import { expandLink, assertPublic } from './link.js';
import { signForPublisher } from './prov.js';
import dns from 'node:dns/promises';
import { REAL_BRANDS } from './brands.js';
import { normDomain, registrable, imitation } from '../extension/lib/domains.js';
import { lureFindings, urlsIn, SHORTENERS } from '../extension/lib/signals.js';

export const PLANS = {
  free: { id: 'free', name: 'Free', price: 0, devices: 2, apiPerDay: 50, blurb: 'For you, on up to 2 browsers' },
  family: { id: 'family', name: 'Family', price: 149, devices: 8, apiPerDay: 500, blurb: 'Protect parents and kids, see every blocked scam' },
  business: { id: 'business', name: 'Business', price: 2999, devices: 100, apiPerDay: 20000, blurb: 'Link-check API, team browsers, signed evidence' },
};
const SESSION_DAYS = 30;
const COOKIE = 'emcon_session';
const CHALLENGE_TTL = 5 * 60e3;
const PAIR_TTL = 10 * 60e3;

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const token = (prefix, bytes = 24) => prefix + crypto.randomBytes(bytes).toString('base64url');
const id = () => crypto.randomBytes(8).toString('hex');
const day = () => new Date().toISOString().slice(0, 10);
const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? rej(e) : res(k.toString('hex')))));
async function hashPassword(pw) { const salt = crypto.randomBytes(16).toString('hex'); return `scrypt$${salt}$${await scrypt(pw, salt)}`; }
async function passwordOk(pw, stored) {
  const [, salt, hash] = String(stored || '').split('$');
  if (!salt) { await scrypt(pw, 'x'.repeat(32)); return false; } // same cost either way
  const got = Buffer.from(await scrypt(pw, salt), 'hex');
  const want = Buffer.from(hash, 'hex');
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}
const cleanEmail = (e) => String(e || '').trim().toLowerCase();
const validEmail = (e) => /^[^\s@]{1,64}@[^\s@]{1,190}\.[a-z]{2,}$/i.test(e);
function checkPassword(pw) {
  pw = String(pw || '');
  if (pw.length < 10) throw new HttpError(400, 'Use at least 10 characters for your password.');
  if (pw.length > 200) throw new HttpError(400, 'That password is too long.');
  if (/^(.)\1+$/.test(pw) || /^(0123456789|1234567890|password\d*|qwertyuiop)/i.test(pw)) throw new HttpError(400, 'That password is too easy to guess.');
  return pw;
}
const recoveryKey = () => crypto.randomBytes(15).toString('base64url').toUpperCase().replace(/[^A-Z0-9]/g, 'X').match(/.{5}/g).join('-');

// Simple sliding-window limiter: key -> timestamps.
const hits = new Map();
function limit(key, max, windowMs) {
  const now = Date.now();
  const recent = (hits.get(key) || []).filter((t) => now - t < windowMs);
  if (recent.length >= max) throw new HttpError(429, 'Too many attempts. Wait a few minutes and try again.');
  recent.push(now);
  hits.set(key, recent);
  if (hits.size > 5000) hits.delete(hits.keys().next().value);
}

export default async function accounts(route) {
  db.accounts ||= { users: {}, sessions: {}, byEmail: {}, byGhost: {}, challenges: {}, spent: {}, pairCodes: {}, devices: {}, keys: {} };
  const A = db.accounts;

  // ---------- helpers ----------
  const publicUser = (u) => ({
    id: u.id, email: u.email || null, name: u.name, plan: PLANS[u.plan] || PLANS.free, createdAt: u.createdAt,
    signIn: { password: !!u.pass, ghost: !!u.ghost }, recoverySet: !!u.recovery,
  });
  function audit(u, what, ctx) {
    u.audit ||= [];
    u.audit.unshift({ at: Date.now(), what, agent: String(ctx.headers['user-agent'] || '').slice(0, 120) });
    u.audit.length = Math.min(u.audit.length, 30);
  }
  function startSession(u, ctx, how) {
    const t = token('s_', 32);
    A.sessions[sha(t)] = { uid: u.id, created: Date.now(), expires: Date.now() + SESSION_DAYS * 864e5 };
    ctx.setCookie(COOKIE, t, { maxAge: SESSION_DAYS * 86400, secure: HOSTED });
    audit(u, `Signed in with ${how}`, ctx);
    save();
  }
  function sameOrigin(ctx) {
    // Cookies are SameSite=Lax, and every write must also come from our own pages.
    const o = ctx.headers.origin;
    if (o && o !== ctx.origin) throw new HttpError(403, 'cross-site request refused');
  }
  function sessionUser(ctx) {
    const t = ctx.cookies[COOKIE];
    const s = t && A.sessions[sha(t)];
    if (!s || s.expires < Date.now()) return null;
    return A.users[s.uid] || null;
  }
  function me(ctx) {
    const u = sessionUser(ctx);
    if (!u) throw new HttpError(401, 'Please sign in.');
    if (ctx.method === 'POST') sameOrigin(ctx);
    return u;
  }
  function newUser(fields) {
    const u = { id: id(), plan: 'free', createdAt: Date.now(), family: [], invoices: [], usage: {}, ...fields };
    A.users[u.id] = u;
    return u;
  }
  const userDevices = (u) => Object.entries(A.devices).filter(([, d]) => d.uid === u.id).map(([did, d]) => ({ id: did, ...d, tokenHash: undefined }));

  // ---------- sign up / sign in ----------
  route('POST', '/api/auth/signup', async (ctx) => {
    sameOrigin(ctx);
    limit('signup:' + ctx.ip, 10, 60 * 60e3);
    const email = cleanEmail(ctx.body.email);
    if (!validEmail(email)) throw new HttpError(400, 'Enter a valid email address.');
    if (A.byEmail[email]) throw new HttpError(409, 'An account with this email already exists. Sign in instead.');
    const pass = await hashPassword(checkPassword(ctx.body.password));
    const name = String(ctx.body.name || '').trim().slice(0, 60) || email.split('@')[0];
    const rk = recoveryKey();
    const u = newUser({ email, name, pass, recovery: sha(rk) });
    A.byEmail[email] = u.id;
    startSession(u, ctx, 'password (new account)');
    return { user: publicUser(u), recoveryKey: rk };
  });

  route('POST', '/api/auth/login', async (ctx) => {
    sameOrigin(ctx);
    const email = cleanEmail(ctx.body.email);
    limit('login:' + ctx.ip, 30, 15 * 60e3);
    limit('login:' + email, 8, 15 * 60e3);
    const u = A.users[A.byEmail[email]];
    const ok = await passwordOk(String(ctx.body.password || ''), u?.pass);
    if (!u || !ok) throw new HttpError(401, 'That email and password don’t match.');
    startSession(u, ctx, 'password');
    return { user: publicUser(u) };
  });

  route('POST', '/api/auth/logout', (ctx) => {
    const t = ctx.cookies[COOKIE];
    if (t) delete A.sessions[sha(t)];
    ctx.setCookie(COOKIE, '', { maxAge: 0, secure: HOSTED });
    save();
    return { ok: true };
  });

  // Recovery key: no email provider needed, and nobody at EMCON can take over your account.
  route('POST', '/api/auth/recover', async (ctx) => {
    sameOrigin(ctx);
    const email = cleanEmail(ctx.body.email);
    limit('recover:' + ctx.ip, 10, 60 * 60e3);
    const u = A.users[A.byEmail[email]];
    const key = String(ctx.body.recoveryKey || '').trim().toUpperCase();
    if (!u?.recovery || sha(key) !== u.recovery) throw new HttpError(401, 'That email and recovery key don’t match.');
    u.pass = await hashPassword(checkPassword(ctx.body.newPassword));
    for (const [h, s] of Object.entries(A.sessions)) if (s.uid === u.id) delete A.sessions[h]; // sign out everywhere
    const rk = recoveryKey();
    u.recovery = sha(rk);
    audit(u, 'Password reset with recovery key', ctx);
    startSession(u, ctx, 'recovery key');
    return { user: publicUser(u), recoveryKey: rk };
  });

  // EMCON Ghost: sign in with a per-site pseudonym; new accounts spend one humanity token.
  route('GET', '/api/auth/ghost/challenge', () => {
    const now = Date.now();
    for (const [c, t] of Object.entries(A.challenges)) if (now - t > CHALLENGE_TTL) delete A.challenges[c];
    const challenge = crypto.randomBytes(16).toString('hex');
    A.challenges[challenge] = now;
    return { challenge };
  });
  route('POST', '/api/auth/ghost', async (ctx) => {
    sameOrigin(ctx);
    const { challenge, presentation: p } = ctx.body;
    const issued = A.challenges[challenge];
    delete A.challenges[challenge];
    if (!issued || Date.now() - issued > CHALLENGE_TTL) throw new HttpError(400, 'Sign-in request expired. Try again.');
    await checkPresentation(ctx.origin, challenge, p);
    let u = A.users[A.byGhost[p.pseudonym]];
    const isNew = !u;
    if (isNew) {
      const claims = await spendToken(p.token, A.spent);
      u = newUser({ name: 'Ghost ' + p.pseudonym.replace(/[^a-z0-9]/gi, '').slice(0, 6), ghost: p.pseudonym, claims });
      A.byGhost[p.pseudonym] = u.id;
    }
    startSession(u, ctx, 'EMCON Ghost');
    return { user: publicUser(u), newAccount: isNew };
  });

  // ---------- account ----------
  route('GET', '/api/me', (ctx) => {
    const u = me(ctx);
    const devices = userDevices(u);
    const week = devices.reduce((t, d) => { for (const [k, n] of Object.entries(d.stats || {})) t[k] = (t[k] || 0) + n; return t; }, {});
    return {
      user: publicUser(u), plans: Object.values(PLANS), devices, family: u.family, week,
      alerts: (u.alerts || []).slice(0, 20), invoices: u.invoices, audit: (u.audit || []).slice(0, 10),
      approvals: (u.approvals || []).slice(0, 20),
      publisher: u.publisher ? { domain: u.publisher.domain, token: u.publisher.token, verified: !!u.publisher.verified, method: u.publisher.method || null } : null,
      keys: Object.entries(A.keys).filter(([, k]) => k.uid === u.id).map(([kid, k]) => ({ id: kid, name: k.name, prefix: k.prefix, created: k.created, lastUsed: k.lastUsed || null })),
      usage: { today: u.usage[day()] || 0, limit: (PLANS[u.plan] || PLANS.free).apiPerDay },
    };
  });
  route('POST', '/api/me/profile', (ctx) => {
    const u = me(ctx);
    u.name = String(ctx.body.name || '').trim().slice(0, 60) || u.name;
    save();
    return { user: publicUser(u) };
  });
  route('POST', '/api/me/password', async (ctx) => {
    const u = me(ctx);
    if (u.pass && !(await passwordOk(String(ctx.body.current || ''), u.pass))) throw new HttpError(401, 'Your current password is not right.');
    if (!u.email) {
      const email = cleanEmail(ctx.body.email);
      if (!validEmail(email)) throw new HttpError(400, 'Add an email address to sign in with a password.');
      if (A.byEmail[email]) throw new HttpError(409, 'That email is already used by another account.');
      u.email = email;
      A.byEmail[email] = u.id;
    }
    u.pass = await hashPassword(checkPassword(ctx.body.next));
    audit(u, 'Password changed', ctx);
    save();
    return { user: publicUser(u) };
  });
  route('POST', '/api/me/recovery', (ctx) => {
    const u = me(ctx);
    const rk = recoveryKey();
    u.recovery = sha(rk);
    audit(u, 'New recovery key created', ctx);
    save();
    return { recoveryKey: rk };
  });
  route('POST', '/api/me/signout-all', (ctx) => {
    const u = me(ctx);
    for (const [h, s] of Object.entries(A.sessions)) if (s.uid === u.id) delete A.sessions[h];
    ctx.setCookie(COOKIE, '', { maxAge: 0, secure: HOSTED });
    save();
    return { ok: true };
  });
  route('GET', '/api/me/export', (ctx) => {
    const u = me(ctx);
    const { pass, recovery, ...rest } = u;
    return { exportedAt: new Date().toISOString(), account: rest, devices: userDevices(u), note: 'Password and recovery key are stored only as hashes and are not included.' };
  });
  route('POST', '/api/me/delete', async (ctx) => {
    const u = me(ctx);
    if (String(ctx.body.confirm || '') !== 'DELETE') throw new HttpError(400, 'Type DELETE to confirm.');
    if (u.pass && !(await passwordOk(String(ctx.body.password || ''), u.pass))) throw new HttpError(401, 'Your password is not right.');
    for (const [h, s] of Object.entries(A.sessions)) if (s.uid === u.id) delete A.sessions[h];
    for (const [d, dev] of Object.entries(A.devices)) if (dev.uid === u.id) delete A.devices[d];
    for (const [k, key] of Object.entries(A.keys)) if (key.uid === u.id) delete A.keys[k];
    if (u.email) delete A.byEmail[u.email];
    if (u.ghost) delete A.byGhost[u.ghost];
    delete A.users[u.id];
    ctx.setCookie(COOKIE, '', { maxAge: 0, secure: HOSTED });
    save();
    return { deleted: true };
  });

  // ---------- plans (demo billing: no payment provider connected) ----------
  route('POST', '/api/me/plan', (ctx) => {
    const u = me(ctx);
    const plan = PLANS[ctx.body.plan];
    if (!plan) throw new HttpError(400, 'Unknown plan.');
    if (plan.id === u.plan) return { user: publicUser(u) };
    if (userDevices(u).length > plan.devices) throw new HttpError(409, `Remove some browsers first: ${plan.name} covers ${plan.devices}.`);
    const before = PLANS[u.plan] || PLANS.free;
    u.plan = plan.id;
    u.invoices.unshift({ id: 'INV-' + id().slice(0, 8).toUpperCase(), at: Date.now(), plan: plan.name, amount: plan.price, currency: 'INR', status: plan.price ? 'demo (no charge)' : 'free', note: `${before.name} → ${plan.name}` });
    audit(u, `Plan changed to ${plan.name}`, ctx);
    save();
    return { user: publicUser(u), demoBilling: true };
  });

  // ---------- family & devices ----------
  route('POST', '/api/me/family', (ctx) => {
    const u = me(ctx);
    const name = String(ctx.body.name || '').trim().slice(0, 40);
    if (!name) throw new HttpError(400, 'Give them a name, like "Mum" or "Ravi".');
    if (u.family.length >= 20) throw new HttpError(400, 'That’s a big family. Remove someone first.');
    const m = { id: id(), name, relation: String(ctx.body.relation || '').slice(0, 30), added: Date.now() };
    u.family.push(m);
    save();
    return { member: m };
  });
  route('POST', '/api/me/family/:mid/remove', (ctx) => {
    const u = me(ctx);
    u.family = u.family.filter((m) => m.id !== ctx.params.mid);
    for (const [d, dev] of Object.entries(A.devices)) if (dev.uid === u.id && dev.member === ctx.params.mid) delete A.devices[d];
    save();
    return { ok: true };
  });
  // A short code, typed into the EMCON extension on the browser you want to protect.
  route('POST', '/api/me/pair', (ctx) => {
    const u = me(ctx);
    const plan = PLANS[u.plan] || PLANS.free;
    if (userDevices(u).length >= plan.devices) throw new HttpError(409, `Your ${plan.name} plan covers ${plan.devices} browsers. Upgrade or remove one.`);
    const member = ctx.body.member ? u.family.find((m) => m.id === ctx.body.member) : null;
    for (const [c, p] of Object.entries(A.pairCodes)) if (p.expires < Date.now()) delete A.pairCodes[c];
    let code;
    do { code = String(crypto.randomInt(0, 1e6)).padStart(6, '0'); } while (A.pairCodes[code]);
    A.pairCodes[code] = { uid: u.id, member: member?.id || null, expires: Date.now() + PAIR_TTL };
    save();
    return { code, expiresIn: PAIR_TTL / 1000, for: member?.name || 'you' };
  });
  route('POST', '/api/me/devices/:did/remove', (ctx) => {
    const u = me(ctx);
    if (A.devices[ctx.params.did]?.uid === u.id) delete A.devices[ctx.params.did];
    save();
    return { ok: true };
  });
  // Called by the extension (no cookie): exchange the code for a device token.
  route('POST', '/api/devices/pair', (ctx) => {
    limit('pair:' + ctx.ip, 20, 15 * 60e3);
    const code = String(ctx.body.code || '').replace(/\D/g, '');
    const p = A.pairCodes[code];
    delete A.pairCodes[code];
    if (!p || p.expires < Date.now()) throw new HttpError(400, 'That code is wrong or has expired. Make a new one in your EMCON dashboard.');
    const u = A.users[p.uid];
    if (!u) throw new HttpError(400, 'That account no longer exists.');
    const t = token('d_', 32);
    const did = id();
    const member = u.family.find((m) => m.id === p.member);
    A.devices[did] = { uid: u.id, member: member?.id || null, owner: member?.name || u.name, name: String(ctx.body.name || 'Browser').slice(0, 60), linkedAt: Date.now(), lastSeen: Date.now(), stats: {}, tokenHash: sha(t) };
    save();
    return { deviceToken: t, account: { name: u.name }, owner: A.devices[did].owner };
  });
  // Weekly counts only (pages checked, scams blocked…). Never addresses or page content.
  route('POST', '/api/devices/report', (ctx) => {
    const h = sha(String(ctx.body.token || ''));
    const entry = Object.entries(A.devices).find(([, d]) => d.tokenHash === h);
    if (!entry) throw new HttpError(401, 'This browser is no longer connected to an EMCON account.');
    const [, d] = entry;
    const stats = {};
    for (const k of ['pages', 'blocked', 'warned', 'links', 'photos', 'trackers']) stats[k] = Math.max(0, Math.min(1e6, Math.floor(Number(ctx.body.stats?.[k]) || 0)));
    const u = A.users[d.uid];
    const newlyBlocked = stats.blocked - (d.stats?.blocked || 0);
    if (u && newlyBlocked > 0) {
      u.alerts ||= [];
      u.alerts.unshift({ at: Date.now(), owner: d.owner, device: d.name, text: `EMCON blocked ${newlyBlocked === 1 ? 'a scam page' : `${newlyBlocked} scam pages`} on ${d.owner}'s browser` });
      u.alerts.length = Math.min(u.alerts.length, 50);
    }
    d.stats = stats;
    d.version = String(ctx.body.version || '').slice(0, 20);
    d.lastSeen = Date.now();
    save();
    return { ok: true, account: u ? { name: u.name } : null, owner: d.owner };
  });

  // ---------- publishers: prove you own a website, then sign your photos ----------
  const cleanDomain = (d) => String(d || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/?#:].*$/, '').replace(/^www\./, '');
  route('POST', '/api/me/publisher', (ctx) => {
    const u = me(ctx);
    const domain = cleanDomain(ctx.body.domain);
    if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain)) throw new HttpError(400, 'Enter your website, like news.example.com.');
    const taken = Object.values(A.users).find((x) => x.id !== u.id && x.publisher?.verified && x.publisher.domain === domain);
    if (taken) throw new HttpError(409, 'Another account has already verified that website.');
    u.publisher = { domain, token: 'emcon-publisher=' + crypto.randomBytes(12).toString('hex'), verified: false, started: Date.now() };
    save();
    return { publisher: { domain, token: u.publisher.token, verified: false } };
  });
  route('POST', '/api/me/publisher/verify', async (ctx) => {
    const u = me(ctx);
    const p = u.publisher;
    if (!p) throw new HttpError(400, 'Add your website first.');
    limit('pubverify:' + u.id, 20, 60 * 60e3);
    let found = false, how = '';
    // 1. a file on the website itself
    try {
      await assertPublic(p.domain);
      const r = await fetch(`https://${p.domain}/.well-known/emcon-publisher.txt`, { redirect: 'manual', signal: AbortSignal.timeout(8000), headers: { 'user-agent': 'EMCON publisher check' } });
      if (r.ok) { const text = (await r.text()).slice(0, 4096); if (text.includes(p.token)) { found = true; how = 'file'; } }
    } catch { /* try DNS next */ }
    // 2. or a DNS TXT record
    if (!found) {
      try { if ((await dns.resolveTxt('_emcon.' + p.domain)).some((rec) => rec.join('').includes(p.token))) { found = true; how = 'DNS'; } } catch { /* not found */ }
    }
    if (!found) throw new HttpError(400, `We couldn't find the code yet. Put it in https://${p.domain}/.well-known/emcon-publisher.txt or in a DNS TXT record for _emcon.${p.domain}, then try again.`);
    p.verified = true; p.verifiedAt = Date.now(); p.method = how;
    audit(u, `Publisher website ${p.domain} verified by ${how}`, ctx);
    save();
    return { publisher: { domain: p.domain, verified: true, method: how } };
  });
  route('POST', '/api/me/sign', async (ctx) => {
    const u = me(ctx);
    limit('sign:' + u.id, 200, 24 * 3600e3);
    const { bytes, manifest } = await signForPublisher(u, ctx.body.image, ctx.body.title, ctx.body.dhash);
    return { image: Buffer.from(bytes).toString('base64'), manifest, verified: !!u.publisher?.verified };
  });

  // ---------- payment brake: a family member checks a risky payment first ----------
  // A connected browser that EMCON blocked on a page asking for card/OTP/bank details can ask
  // the account owner to look. They see the site and EMCON's reasons, and approve or stop it.
  const deviceByToken = (t) => Object.entries(A.devices).find(([, d]) => d.tokenHash === sha(String(t || '')));
  route('POST', '/api/devices/approval', (ctx) => {
    const found = deviceByToken(ctx.body.token);
    if (!found) throw new HttpError(401, 'This browser is not connected to an EMCON account.');
    const [did, d] = found;
    limit('approval:' + did, 10, 60 * 60e3);
    const u = A.users[d.uid];
    if (!u) throw new HttpError(401, 'That account no longer exists.');
    const domain = String(ctx.body.domain || '').toLowerCase().replace(/[^a-z0-9.:-]/g, '').slice(0, 120);
    const reasons = (Array.isArray(ctx.body.reasons) ? ctx.body.reasons : []).map((r) => String(r).slice(0, 220)).slice(0, 5);
    const a = { id: id(), device: did, owner: d.owner, deviceName: d.name, domain, reasons, at: Date.now(), status: 'pending' };
    u.approvals = [a, ...(u.approvals || [])].slice(0, 50);
    u.alerts ||= [];
    u.alerts.unshift({ at: a.at, owner: d.owner, device: d.name, text: `${d.owner} asked you to check a payment on ${domain}` });
    u.alerts.length = Math.min(u.alerts.length, 50);
    save();
    return { id: a.id, account: u.name };
  });
  route('GET', '/api/devices/approval/:aid', (ctx) => {
    const found = deviceByToken(ctx.headers['x-device-token']);
    if (!found) throw new HttpError(401, 'This browser is not connected to an EMCON account.');
    const a = (A.users[found[1].uid]?.approvals || []).find((x) => x.id === ctx.params.aid && x.device === found[0]);
    if (!a) throw new HttpError(404, 'No such request.');
    return { status: a.status, decidedAt: a.decidedAt || null, note: a.note || '' };
  });
  route('POST', '/api/me/approvals/:aid', (ctx) => {
    const u = me(ctx);
    const a = (u.approvals || []).find((x) => x.id === ctx.params.aid);
    if (!a) throw new HttpError(404, 'No such request.');
    if (a.status !== 'pending') return { status: a.status };
    a.status = ctx.body.decision === 'approve' ? 'approved' : 'denied';
    a.decidedAt = Date.now();
    a.note = String(ctx.body.note || '').slice(0, 200);
    audit(u, `${a.status === 'approved' ? 'Approved' : 'Stopped'} a payment on ${a.domain} for ${a.owner}`, ctx);
    save();
    return { status: a.status };
  });

  // ---------- API keys + the link-check API ----------
  route('POST', '/api/me/keys', (ctx) => {
    const u = me(ctx);
    const mine = Object.values(A.keys).filter((k) => k.uid === u.id);
    if (mine.length >= 10) throw new HttpError(400, 'You have 10 keys already. Revoke one first.');
    const secret = token('emk_live_', 24);
    const kid = id();
    A.keys[kid] = { uid: u.id, name: String(ctx.body.name || 'API key').slice(0, 40), prefix: secret.slice(0, 13) + '…', hash: sha(secret), created: Date.now() };
    audit(u, `API key "${A.keys[kid].name}" created`, ctx);
    save();
    return { id: kid, key: secret, prefix: A.keys[kid].prefix };
  });
  route('POST', '/api/me/keys/:kid/revoke', (ctx) => {
    const u = me(ctx);
    if (A.keys[ctx.params.kid]?.uid === u.id) { audit(u, `API key "${A.keys[ctx.params.kid].name}" revoked`, ctx); delete A.keys[ctx.params.kid]; }
    save();
    return { ok: true };
  });

  async function checkApi(ctx) {
    let u = null, viaKey = null;
    const bearer = /^Bearer\s+(\S+)$/i.exec(String(ctx.headers.authorization || ''))?.[1];
    if (bearer) {
      const k = Object.values(A.keys).find((x) => x.hash === sha(bearer));
      if (!k) throw new HttpError(401, 'Invalid API key.');
      u = A.users[k.uid];
      viaKey = k;
    } else { u = sessionUser(ctx); if (u && ctx.method === 'POST') sameOrigin(ctx); }
    if (!u) throw new HttpError(401, 'Send your API key as "Authorization: Bearer emk_live_…".');
    const plan = PLANS[u.plan] || PLANS.free;
    const today = day();
    if ((u.usage[today] || 0) >= plan.apiPerDay) throw new HttpError(429, `Daily limit reached (${plan.apiPerDay} checks on ${plan.name}).`);
    const input = String((ctx.method === 'POST' ? ctx.body.text || ctx.body.url : ctx.query.url) || '').slice(0, 2000);
    const link = urlsIn(input)[0];
    if (!link) throw new HttpError(400, 'Send a link (url) or a message containing one (text).');
    u.usage[today] = (u.usage[today] || 0) + 1;
    for (const d of Object.keys(u.usage).sort().slice(0, -31)) delete u.usage[d];
    if (viaKey) viaKey.lastUsed = Date.now();
    save();
    return { result: await verdictFor(link, /\s/.test(input) ? input : ''), usage: { today: u.usage[today], limit: plan.apiPerDay } };
  }
  route('GET', '/api/v1/check', checkApi);
  route('POST', '/api/v1/check', checkApi);
}

/** Server-side verdict for the API: where a link lands, and the evidence about it. */
export async function verdictFor(link, message = '') {
  let exp;
  try { exp = await expandLink(link); } catch (e) { exp = { hops: [{ url: link }], final: link, complete: false, error: e.message }; }
  const host = normDomain(new URL(exp.final).hostname);
  const reasons = [];
  let risk = 0;
  const add = (id, text, pts) => { reasons.push({ id, text, points: pts }); risk += pts; };
  const reports = (db.wot?.attestations || []).filter((a) => a.domain === host && a.verdict === 'scam');
  if (reports.length) add('reports', `Reported as a scam: ${reports[0].note || 'listed by a security source'}`, 70);
  const brands = REAL_BRANDS.filter((b) => !b.domains.some((d) => host === d || host.endsWith('.' + d)));
  for (const b of brands) { const im = imitation(host, b); if (im) { add('lookalike', `The address ${im.text}, but it is not an official ${b.name} domain`, im.strong ? 45 : 25); break; } }
  const shorteners = exp.hops.map((h) => normDomain(new URL(h.url).hostname)).filter((h) => SHORTENERS.has(h));
  if (shorteners.length) add('shortener', `A link shortener (${shorteners[0]}) hid the real address`, 10);
  if (exp.hops.length > 2) add('redirects', `${exp.hops.length - 1} redirects before the final page`, 5);
  const lure = lureFindings(message);
  if (lure.length) add('wording', `Scam-style wording in the message: ${lure.map((l) => `"${l.phrase}"`).join(', ')}`, lure.some((l) => l.kind !== 'urgency') ? 15 : 5);
  if (!exp.complete) reasons.push({ id: 'unreachable', text: exp.error || 'The link could not be followed to the end', points: 0 });
  risk = Math.min(100, risk);
  return {
    verdict: risk >= 60 ? 'scam' : risk >= 30 ? 'suspicious' : 'no_warnings',
    risk, link, final: exp.final, site: registrable(host), hops: exp.hops.map((h) => h.url), reasons,
    checkedAt: new Date().toISOString(),
  };
}
