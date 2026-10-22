export const $ = (s, el = document) => el.querySelector(s);
export const $$ = (s, el = document) => [...el.querySelectorAll(s)];
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const money = (n) => '$' + Number(n || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

export function ago(ts, clock = Date.now()) {
  const s = Math.round((clock - ts) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}
export function until(ts, clock = Date.now()) {
  const s = Math.max(0, Math.round((ts - clock) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`;
}

export async function api(path, { method = 'GET', body, headers = {} } = {}) {
  const r = await fetch(path, { method, headers: { 'content-type': 'application/json', ...headers }, body: body && JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(j.error || `HTTP ${r.status}`), { status: r.status, data: j });
  return j;
}

export function hubNav(active) {
  const links = [['/', 'Overview'], ['/rp.html', 'Ghost sign-in'], ['/sign.html', 'Provenance'], ['/feed.html', 'Feed'], ['/vault.html', 'Vault'], ['/sms.html', 'Scam chain'], ['/news.html', 'Privacy'], ['/verify.html', 'Verify receipt']];
  const h = document.createElement('header');
  h.className = 'top';
  h.innerHTML = `<a class="brand" href="/">EMCON<small>demo</small></a><nav>${links.map(([href, t]) => `<a href="${href}" class="${href === active ? 'on' : ''}">${t}</a>`).join('')}</nav>`;
  document.body.prepend(h);
}

export const hasExtension = () => document.documentElement.getAttribute('data-emcon') === '1';
