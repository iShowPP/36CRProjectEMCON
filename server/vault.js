// Kestrel Bank "Honey-Vault": time-locks, guardian co-signing, duress PIN and
// scam-script interruption for a (simulated) bank account.
//
// Loopholes in the original pitch and how they are closed here:
//  * "Just add a 15-minute lock" -> scammers simply tell victims to wait. So the delay
//    scales with risk, and release also requires a scam-script check-in; any red flag
//    escalates to guardians, who see the answers.
//  * Attacker with the PIN first raises the limits / removes guardians, then drains
//    -> loosening any protection is itself time-locked (24 h) and announced to guardians.
//    Tightening applies instantly.
//  * Stolen session cookie -> every transfer needs PIN step-up; a cookie alone moves nothing.
//  * Duress PIN that "aborts loud" or shows an error -> endangers the victim. Here the whole
//    session becomes a consistent decoy: transfers look successful, balance drops,
//    while money is parked in a freeze vault and guardians are silently alerted.
//  * Panic freeze undone by the attacker -> unfreezing requires a guardian.
//  * Guardian collusion / one compromised guardian -> m-of-n approvals, and any single
//    guardian can veto.

import crypto from 'node:crypto';
import { db, save, HttpError } from './store.js';
import { groupVerdict } from './wot.js';

const MIN = 60e3, HOUR = 36e5, DAY = 864e5;
const SALT = 'kestrel-demo-salt';
const MAX_PIN_FAILS = 5;
const QUIZ = [
  { id: 'contacted', q: 'Did someone contact you first (call, SMS, dating app, social media, "support agent") and ask for this payment?' },
  { id: 'secret', q: 'Were you told to keep it secret, act urgently, or that you\'d face a penalty, arrest or a missed opportunity?' },
  { id: 'returns', q: 'Were you promised profits, a prize, a refund or a job that requires sending money first?' },
  { id: 'watched', q: 'Is someone on the phone with you, or asking you to share your screen, right now?' },
];
const TIGHTER = { instantLimit: 'lower', guardianLimit: 'lower', coolingMinutes: 'higher', guardiansRequired: 'higher', settingsDelayHours: 'higher', newPayeeHours: 'higher' };

const id = () => crypto.randomBytes(6).toString('hex');
const hashPin = (pin) => crypto.scryptSync(String(pin), SALT, 32).toString('hex');
const eq = (a, b) => crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
const money = (n) => '$' + Number(n).toLocaleString('en-US', { maximumFractionDigits: 2 });

let v;
const now = () => Date.now() + (v.clockOffset || 0);

function fresh() {
  const t = Date.now();
  return {
    clockOffset: 0,
    pinHash: hashPin('1234'),
    duressPinHash: hashPin('9999'),
    pinFails: 0, lockedUntil: 0,
    balance: 25000, freezeVault: 0, frozen: false, duressActive: false,
    settings: { instantLimit: 500, guardianLimit: 5000, coolingMinutes: 15, guardiansRequired: 2, settingsDelayHours: 24, newPayeeHours: 24 },
    guardians: [
      { id: 'g1', name: 'Asha (sister)', token: id() + id() },
      { id: 'g2', name: 'Ravi (dad)', token: id() + id() },
      { id: 'g3', name: 'Kestrel Bank fraud desk', token: id() + id() },
    ],
    payees: [
      { id: 'p1', name: 'Landlord — R. Mehta', account: 'KEST-0042-1180', domain: null, addedAt: t - 400 * DAY },
      { id: 'p2', name: 'Electricity — GridCo', account: 'GRID-77-310', domain: null, addedAt: t - 200 * DAY },
      { id: 'p3', name: 'CryptoYield Pro (wallet top-up)', account: 'XFER-7781-0099', domain: 'cryptoyield-pro.xyz', addedAt: t - 2 * HOUR },
    ],
    txs: [], pendingSettings: [], alerts: [], sessions: {}, clearVotes: [],
  };
}

export default async function vault(route) {
  v = db.vault ||= fresh();
  setInterval(tick, 5000).unref();

  // ---------- owner ----------
  route('POST', '/api/vault/login', ({ body }) => {
    const mode = checkPin(body.pin);
    const token = id() + id();
    v.sessions[token] = { mode, at: now() };
    if (mode === 'duress') {
      v.duressActive = true;
      alert('critical', 'DURESS PIN used to log in. Session is a decoy; all outgoing money is being diverted to the freeze vault.');
    }
    save();
    return { token }; // identical response for real and duress logins
  });

  route('GET', '/api/vault/state', ({ headers }) => view(session(headers)));

  route('POST', '/api/vault/payees', ({ headers, body }) => {
    const s = session(headers);
    stepUp(s, body.pin);
    const name = String(body.name || '').trim().slice(0, 60);
    if (!name || !body.account) throw new HttpError(400, 'name and account required');
    v.payees.push({ id: id(), name, account: String(body.account).slice(0, 40), domain: body.domain ? String(body.domain).slice(0, 80) : null, addedAt: now() });
    save();
    return view(s);
  });

  route('POST', '/api/vault/transfer', ({ headers, body }) => {
    const s = session(headers);
    const mode = stepUp(s, body.pin);
    const payee = v.payees.find((p) => p.id === body.payeeId);
    const amount = Math.round(Number(body.amount) * 100) / 100;
    if (!payee) throw new HttpError(400, 'unknown payee');
    if (!(amount > 0)) throw new HttpError(400, 'amount must be positive');
    if (amount > v.balance) throw new HttpError(400, 'insufficient funds');
    if (mode === 'duress' || s.mode === 'duress') return duressTransfer(s, payee, amount, body.memo);
    if (v.frozen) throw new HttpError(423, 'account is frozen — ask a guardian to unfreeze');

    const risk = assess(payee, amount);
    const tx = {
      id: id(), payeeId: payee.id, payeeName: payee.name, amount, memo: String(body.memo || '').slice(0, 80),
      createdAt: now(), risk, approvals: [], vetoes: [], quiz: null, needsGuardians: risk.route === 'guardians',
    };
    v.balance -= amount; // held until completion / cancellation
    if (risk.route === 'instant') {
      tx.status = 'completed';
      tx.completedAt = now();
    } else {
      tx.status = risk.route === 'guardians' ? 'awaiting_guardians' : 'cooling';
      tx.releaseAt = now() + risk.coolingMinutes * MIN;
      if (tx.needsGuardians) alert('warning', `Approval needed: ${money(amount)} to ${payee.name}. Reasons: ${risk.reasons.join('; ')}`);
    }
    v.txs.unshift(tx);
    save();
    return { tx: publicTx(tx, s), state: view(s) };
  });

  route('POST', '/api/vault/tx/:id/quiz', ({ headers, params, body }) => {
    const s = session(headers);
    const tx = findTx(params.id);
    if (s.mode === 'duress') return view(s);
    if (!['cooling', 'awaiting_guardians'].includes(tx.status)) throw new HttpError(409, 'nothing to check in for');
    const answers = Object.fromEntries(QUIZ.map((q) => [q.id, body.answers?.[q.id] === 'yes' ? 'yes' : body.answers?.[q.id] === 'no' ? 'no' : null]));
    if (Object.values(answers).includes(null)) throw new HttpError(400, 'answer every question');
    const flags = QUIZ.filter((q) => answers[q.id] === 'yes');
    tx.quiz = { answers, flags: flags.map((f) => f.id), at: now() };
    if (flags.length) {
      tx.needsGuardians = true;
      tx.status = 'awaiting_guardians';
      tx.risk.reasons.push(`Scam-script indicators: ${flags.map((f) => f.id).join(', ')}`);
      tx.releaseAt = Math.max(tx.releaseAt, now() + 60 * MIN);
      alert('warning', `Possible scam in progress: ${money(tx.amount)} to ${tx.payeeName}. Customer answered YES to: ${flags.map((f) => f.q).join(' | ')}`);
    }
    tick();
    save();
    return view(s);
  });

  route('POST', '/api/vault/tx/:id/cancel', ({ headers, params }) => {
    const s = session(headers);
    const tx = findTx(params.id);
    if (s.mode !== 'duress' && ['cooling', 'awaiting_guardians'].includes(tx.status)) refund(tx, 'cancelled');
    save();
    return view(s);
  });

  route('POST', '/api/vault/settings', ({ headers, body }) => {
    const s = session(headers);
    stepUp(s, body.pin);
    if (s.mode === 'duress') return view(s); // decoy: pretend it worked
    const applied = [], delayed = [];
    for (const [k, raw] of Object.entries(body.changes || {})) {
      if (!(k in TIGHTER)) continue;
      const val = Math.max(0, Number(raw));
      if (!Number.isFinite(val) || val === v.settings[k]) continue;
      if (k === 'guardiansRequired' && (val < 1 || val > v.guardians.length)) throw new HttpError(400, `guardiansRequired must be 1..${v.guardians.length}`);
      const tighter = TIGHTER[k] === 'lower' ? val < v.settings[k] : val > v.settings[k];
      if (tighter) { v.settings[k] = val; applied.push(k); }
      else {
        const p = { id: id(), key: k, from: v.settings[k], to: val, requestedAt: now(), effectiveAt: now() + v.settings.settingsDelayHours * HOUR, vetoed: false };
        v.pendingSettings.push(p);
        delayed.push(p);
        alert('warning', `Protection being LOOSENED: ${k} ${p.from} → ${p.to}, takes effect in ${v.settings.settingsDelayHours} h unless a guardian vetoes.`);
      }
    }
    save();
    return { applied, delayed, state: view(s) };
  });

  route('POST', '/api/vault/settings/:id/cancel', ({ headers, params }) => {
    const s = session(headers);
    v.pendingSettings = v.pendingSettings.filter((p) => p.id !== params.id);
    save();
    return view(s);
  });

  route('POST', '/api/vault/freeze', ({ headers }) => {
    const s = session(headers);
    if (s.mode !== 'duress') { v.frozen = true; alert('critical', 'Owner pressed PANIC FREEZE. All outgoing transfers halted.'); save(); }
    return view(s);
  });

  // ---------- guardians ----------
  route('GET', '/api/vault/guardian/:token', ({ params }) => guardianView(guardian(params.token)));

  route('POST', '/api/vault/guardian/:token/decide', ({ params, body }) => {
    const g = guardian(params.token);
    const tx = findTx(body.txId);
    if (tx.status !== 'awaiting_guardians') throw new HttpError(409, 'not awaiting guardians');
    tx.approvals = tx.approvals.filter((a) => a !== g.id);
    if (body.decision === 'veto') {
      tx.vetoes.push(g.id);
      refund(tx, 'vetoed');
      alert('info', `${g.name} vetoed ${money(tx.amount)} to ${tx.payeeName}. Funds returned.`);
    } else tx.approvals.push(g.id);
    tick();
    save();
    return guardianView(g);
  });

  route('POST', '/api/vault/guardian/:token/veto-setting', ({ params, body }) => {
    const g = guardian(params.token);
    const p = v.pendingSettings.find((x) => x.id === body.id);
    if (p) { p.vetoed = true; v.pendingSettings = v.pendingSettings.filter((x) => x !== p); alert('info', `${g.name} vetoed loosening ${p.key}.`); }
    save();
    return guardianView(g);
  });

  route('POST', '/api/vault/guardian/:token/freeze', ({ params, body }) => {
    const g = guardian(params.token);
    v.frozen = !!body.frozen;
    alert(v.frozen ? 'critical' : 'info', `${g.name} ${v.frozen ? 'FROZE' : 'unfroze'} the account.`);
    save();
    return guardianView(g);
  });

  // Ending a duress episode returns diverted money; needs m-of-n guardians.
  route('POST', '/api/vault/guardian/:token/clear-duress', ({ params }) => {
    const g = guardian(params.token);
    if (!v.duressActive) throw new HttpError(409, 'no duress episode active');
    if (!v.clearVotes.includes(g.id)) v.clearVotes.push(g.id);
    if (v.clearVotes.length >= v.settings.guardiansRequired) {
      v.balance += v.freezeVault;
      alert('info', `Duress episode closed by guardians. ${money(v.freezeVault)} returned from the freeze vault.`);
      for (const t of v.txs) if (t.duress && t.status === 'diverted') t.status = 'reversed';
      v.freezeVault = 0;
      v.duressActive = false;
      v.clearVotes = [];
      for (const s of Object.values(v.sessions)) if (s.mode === 'duress') s.mode = 'expired';
    }
    save();
    return guardianView(g);
  });

  // ---------- demo helpers ----------
  route('GET', '/api/vault/demo/info', ({ origin }) => ({
    pins: { real: '1234', duress: '9999' },
    guardians: v.guardians.map((g) => ({ name: g.name, url: `${origin}/guardian.html?g=${g.token}` })),
    clock: new Date(now()).toISOString(),
  }));
  route('POST', '/api/vault/demo/fast-forward', ({ body }) => {
    v.clockOffset += Math.max(0, Number(body.minutes) || 0) * MIN;
    tick();
    save();
    return { clock: new Date(now()).toISOString() };
  });
  route('POST', '/api/vault/demo/reset', () => { v = db.vault = fresh(); save(); return { ok: true }; });
}

// ---------- engine ----------
function checkPin(pin) {
  if (now() < v.lockedUntil) throw new HttpError(429, 'too many wrong PINs — try again later');
  const h = hashPin(pin ?? '');
  const real = eq(h, v.pinHash), duress = eq(h, v.duressPinHash); // always compute both: constant time
  if (!real && !duress) {
    if (++v.pinFails >= MAX_PIN_FAILS) { v.lockedUntil = now() + 15 * MIN; v.pinFails = 0; alert('warning', 'PIN locked after repeated wrong attempts.'); }
    save();
    throw new HttpError(401, 'wrong PIN');
  }
  v.pinFails = 0;
  return real ? 'real' : 'duress';
}

function session(headers) {
  const s = v.sessions[headers['x-vault-session']];
  if (!s || s.mode === 'expired') throw new HttpError(401, 'not logged in');
  return s;
}

function stepUp(s, pin) {
  const mode = checkPin(pin);
  if (mode === 'duress' && s.mode !== 'duress') {
    s.mode = 'duress';
    v.duressActive = true;
    alert('critical', 'DURESS PIN entered during a session. Session switched to decoy mode.');
  }
  return mode;
}

function assess(payee, amount) {
  const st = v.settings;
  const reasons = [];
  let score = 0;
  const ageH = (now() - payee.addedAt) / HOUR;
  if (ageH < st.newPayeeHours) { score += 35; reasons.push(`New payee (added ${ageH < 1 ? Math.round(ageH * 60) + ' min' : Math.round(ageH) + ' h'} ago)`); }
  if (amount > st.instantLimit) { score += 15; reasons.push(`Above instant limit (${money(st.instantLimit)})`); }
  if (amount >= st.guardianLimit) { score += 30; reasons.push(`At or above guardian limit (${money(st.guardianLimit)})`); }
  if (amount > (v.balance + amount) * 0.5 && amount > st.instantLimit) { score += 15; reasons.push('More than half of your balance'); }
  const recent = v.txs.filter((t) => now() - t.createdAt < 10 * MIN && !['cancelled', 'vetoed'].includes(t.status));
  const dests = new Set(recent.map((t) => t.payeeId)).add(payee.id);
  if (recent.length >= 3 || dests.size >= 3) { score += 30; reasons.push(`Rapid transfers: ${recent.length + 1} in 10 min to ${dests.size} payee(s)`); }
  if (payee.domain) {
    const w = groupVerdict(payee.domain);
    if (w?.verdict === 'scam') { score += 60; reasons.push(`Payee site ${payee.domain} is flagged by ${w.source}: "${w.note}"`); }
  }
  const route = score >= 60 || amount >= st.guardianLimit ? 'guardians' : score >= 15 ? 'cooling' : 'instant';
  const coolingMinutes = route === 'instant' ? 0 : Math.round(st.coolingMinutes * (1 + score / 50));
  return { score, reasons, route, coolingMinutes };
}

function duressTransfer(s, payee, amount, memo) {
  v.balance -= amount;
  v.freezeVault += amount;
  const tx = {
    id: id(), payeeId: payee.id, payeeName: payee.name, amount, memo: String(memo || '').slice(0, 80),
    createdAt: now(), completedAt: now(), status: 'diverted', duress: true, risk: { score: 0, reasons: [], route: 'instant' }, approvals: [], vetoes: [],
  };
  v.txs.unshift(tx);
  alert('critical', `DURESS transfer: ${money(amount)} "to ${payee.name}" was diverted to the freeze vault. Owner may be coerced — call them / contact police.`);
  save();
  return { tx: publicTx(tx, s), state: view(s) };
}

function tick() {
  if (!v) return;
  let changed = false;
  for (const p of v.pendingSettings) {
    if (!p.vetoed && now() >= p.effectiveAt) { v.settings[p.key] = p.to; p.applied = true; changed = true; alert('info', `Setting ${p.key} changed to ${p.to}.`); }
  }
  v.pendingSettings = v.pendingSettings.filter((p) => !p.applied);
  for (const tx of v.txs) {
    if (!['cooling', 'awaiting_guardians'].includes(tx.status)) continue;
    if (now() - tx.createdAt > 2 * DAY) { refund(tx, 'expired'); changed = true; continue; }
    if (v.frozen || now() < tx.releaseAt || !tx.quiz || tx.quiz.flags.length && !tx.needsGuardians) continue;
    if (tx.needsGuardians && tx.approvals.length < v.settings.guardiansRequired) continue;
    tx.status = 'completed';
    tx.completedAt = now();
    changed = true;
  }
  if (changed) save();
}

function refund(tx, status) {
  v.balance += tx.amount;
  tx.status = status;
  tx.closedAt = now();
}

function alert(level, text) {
  v.alerts.unshift({ at: now(), level, text });
  v.alerts.length = Math.min(v.alerts.length, 100);
  console.log(`[vault alert:${level}] ${text}`);
  const hook = process.env.EMCON_ALERT_WEBHOOK; // e.g. https://ntfy.sh/<your-topic>
  if (hook) fetch(hook, { method: 'POST', body: `[Kestrel ${level}] ${text}` }).catch(() => {});
}

const findTx = (txId) => v.txs.find((t) => t.id === txId) || (() => { throw new HttpError(404, 'no such transaction'); })();
const guardian = (token) => v.guardians.find((g) => g.token === token) || (() => { throw new HttpError(403, 'unknown guardian link'); })();

// In decoy mode the attacker sees a believable, internally consistent account.
function publicTx(tx, s) {
  const decoy = s.mode === 'duress';
  const status = decoy && tx.duress ? 'completed' : tx.status;
  return {
    id: tx.id, payeeName: tx.payeeName, amount: tx.amount, memo: tx.memo, status, createdAt: tx.createdAt, completedAt: tx.completedAt,
    releaseAt: tx.releaseAt, risk: decoy ? undefined : tx.risk, quiz: tx.quiz, needsGuardians: tx.needsGuardians,
    approvals: tx.approvals.length, required: v.settings.guardiansRequired, duress: decoy ? undefined : tx.duress,
    ref: 'KST' + tx.id.toUpperCase(),
  };
}

function view(s) {
  tick();
  const decoy = s.mode === 'duress';
  return {
    balance: v.balance,
    freezeVault: decoy ? undefined : v.freezeVault,
    frozen: decoy ? false : v.frozen,
    duressActive: decoy ? undefined : v.duressActive,
    settings: v.settings,
    payees: v.payees.map((p) => ({ ...p, isNew: now() - p.addedAt < v.settings.newPayeeHours * HOUR })),
    txs: v.txs.slice(0, 30).map((t) => publicTx(t, s)),
    pendingSettings: decoy ? [] : v.pendingSettings,
    alerts: decoy ? [] : v.alerts.slice(0, 15),
    quiz: QUIZ,
    clock: now(),
  };
}

function guardianView(g) {
  tick();
  return {
    guardian: { id: g.id, name: g.name },
    frozen: v.frozen,
    duressActive: v.duressActive,
    freezeVault: v.freezeVault,
    clearVotes: v.clearVotes.length,
    required: v.settings.guardiansRequired,
    pending: v.txs.filter((t) => t.status === 'awaiting_guardians').map((t) => ({ ...publicTx(t, { mode: 'real' }), approvedByMe: t.approvals.includes(g.id) })),
    pendingSettings: v.pendingSettings,
    alerts: v.alerts.slice(0, 20),
    quiz: QUIZ,
    clock: now(),
  };
}
