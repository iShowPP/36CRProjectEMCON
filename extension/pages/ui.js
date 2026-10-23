// Shared rendering for extension pages: one status said three ways (icon, colour, word),
// plain advice first, evidence one tap away, the path drawn like order tracking.
import { icon, LEVEL, STATUS, ORDER } from '../lib/icons.js';
import { esc } from './msg.js';

export { icon, LEVEL, STATUS };

/** Replace every <span data-icon="name"> with its SVG. */
export function fillIcons(root = document) {
  for (const el of root.querySelectorAll('[data-icon]')) {
    el.innerHTML = icon(el.dataset.icon, Number(el.dataset.size) || 18);
    el.removeAttribute('data-icon');
  }
}

// status first, then the heaviest evidence (most points) first
export const byOrder = (a, b) => (ORDER[a.status] ?? 9) - (ORDER[b.status] ?? 9) || Math.abs(b.pts || b.points || 0) - Math.abs(a.pts || a.points || 0);

export const pill = (status) => {
  const s = STATUS[status] || { word: status, role: 'neutral', icon: 'info' };
  return `<span class="pill role-${s.role}">${icon(s.icon, 13)}${esc(s.word)}</span>`;
};

/** All checks, each with its status pill and the detail underneath. */
export const evList = (rows) => `<ol class="ev">${rows.map((r) => `<li class="${esc(r.status)}"><b>${esc(r.label)}</b>${pill(r.status)}<span class="d">${esc(r.detail)}${r.points ? ` <span class="mono">(${r.points > 0 ? '+' : ''}${r.points})</span>` : ''}</span></li>`).join('')}</ol>`;

const VIA = {
  typed: 'You opened it', link: 'You followed a link', redirect: 'Redirected automatically', 'page redirect': 'The page sent you on',
  form: 'After a form was sent', reload: 'Reloaded', 'new tab': 'Opened in a new tab', message: 'From the message you pasted',
};

/** The path to a page, drawn like a parcel-tracking timeline. */
export function pathHtml(chain, title, role = 'calm', start = null) {
  if (!chain || chain.length < 2) return '';
  return `<div class="section-title">${esc(title)}</div>
    <div class="card"><ol class="steps role-${role}">${chain.map((h, i) => `<li class="${i === chain.length - 1 ? 'end' : ''}"><span class="host">${esc(h.label || h.host)}</span><span class="via">${esc(i === 0 ? start || (VIA[h.via] === 'Reloaded' ? 'Start' : VIA[h.via] || 'Start') : VIA[h.via] || h.via)}${i === chain.length - 1 ? ' · you are here' : ''}</span></li>`).join('')}</ol></div>`;
}

/**
 * A verdict: tinted status panel (icon + headline + where + advice), the top reasons as
 * sentences, the path, then every check behind "See all".
 */
export function verdictHtml(v, { where, pathTitle = 'How you got here', open = false, start = null } = {}) {
  const L = LEVEL[v.level] || LEVEL.unknown;
  const rows = [...v.checks].sort(byOrder);
  const loud = v.level === 'danger' || v.level === 'caution';
  // A calm verdict never shows warnings inside its green/blue panel: weaker findings go below it.
  const reasons = loud ? rows.filter((c) => c.status === 'found' || c.status === 'unknown').slice(0, 3) : rows.filter((c) => c.status === 'good').slice(0, 2);
  const worth = loud ? [] : rows.filter((c) => c.status === 'found');
  const quiet = rows.filter((c) => c.status === 'clear' || c.status === 'na').length;
  return `
    <div class="panel role-${L.role}">
      <div class="hero"><span class="dot-icon">${icon(L.icon, 26)}</span><div><h1>${esc(L.head)}</h1><div class="where">${where || `on <b>${esc(v.domain)}</b>`}</div></div></div>
      <p class="advice">${esc(rows.some((c) => c.id === 'scripts' && c.status === 'found') && v.level !== 'danger' ? "Don't type card details here until you know why this payment page changed." : L.advice)}</p>
      ${reasons.length ? `<ul class="reasons">${reasons.map((c) => `<li class="role-${(STATUS[c.status] || STATUS.note).role}">${icon((STATUS[c.status] || STATUS.note).icon, 16)}<div><b>${esc(c.label)}.</b> ${esc(c.detail)}</div></li>`).join('')}</ul>`
        : `<ul class="reasons"><li class="role-ok">${icon('check', 16)}<div>${quiet} checks found nothing wrong.</div></li></ul>`}
    </div>
    ${worth.length ? `<div class="section-title">Worth knowing</div><div class="card" style="padding:4px 14px"><ul class="reasons" style="margin:0">${worth.map((c) => `<li class="role-caution" style="border:0">${icon('alert', 16)}<div><b>${esc(c.label)}.</b> ${esc(c.detail)}</div></li>`).join('')}</ul></div>` : ''}
    ${pathHtml(v.chain, pathTitle, L.role, start)}
    <details class="more"${open ? ' open' : ''}><summary>See all ${rows.length} checks ${icon('chevronDown', 18)}</summary>
      <div class="card" style="padding:2px 14px">${evList(rows)}</div>
      <p class="tiny faint" style="margin:8px 2px 0">Risk ${v.risk}/100: the sum of the points in the signed receipt. Every row is a deterministic check or a signed report. No AI guesses.</p>
    </details>`;
}
