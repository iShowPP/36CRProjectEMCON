// Shared helpers for the product site (landing, sign-in, dashboard).
export const $ = (s, el = document) => el.querySelector(s);
export const $$ = (s, el = document) => [...el.querySelectorAll(s)];
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export async function api(path, { method = 'GET', body } = {}) {
  const r = await fetch(path, { method, headers: { 'content-type': 'application/json' }, body: body && JSON.stringify(body), credentials: 'same-origin' });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(j.error || `Something went wrong (${r.status})`), { status: r.status, data: j });
  return j;
}

export const ICON = {
  shield: '<path d="M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6z"/><path d="M9 12l2 2 4-4.5"/>',
  home: '<path d="M3.5 11 12 4l8.5 7"/><path d="M6 9.5V20h12V9.5"/><path d="M10 20v-5h4v5"/>',
  devices: '<rect x="3" y="4" width="14" height="10" rx="1.5"/><path d="M1.5 18h17"/><rect x="18" y="8" width="4.5" height="10" rx="1"/>',
  users: '<circle cx="9" cy="8.5" r="3.2"/><path d="M3 20a6 6 0 0 1 12 0"/><path d="M15.5 5.6a3.2 3.2 0 0 1 0 5.8"/><path d="M17.5 14.4A6 6 0 0 1 21 20"/>',
  code: '<path d="M8 7l-5 5 5 5M16 7l5 5-5 5M13.5 4l-3 16"/>',
  card: '<rect x="3" y="6" width="18" height="13" rx="2"/><path d="M3 10h18M7 15h4"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M12 2.8v2.4M12 18.8v2.4M2.8 12h2.4M18.8 12h2.4M5.5 5.5l1.7 1.7M16.8 16.8l1.7 1.7M5.5 18.5l1.7-1.7M16.8 7.2l1.7-1.7"/>',
  ghost: '<path d="M6 20.5V11a6 6 0 0 1 12 0v9.5l-2-1.5-2 1.5-2-1.5-2 1.5-2-1.5z"/><path d="M10 10.5v.5M14 10.5v.5"/>',
  bell: '<path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15z"/><path d="M10 20.5a2 2 0 0 0 4 0"/>',
  link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 1 0-5.7-5.7l-1.1 1.1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 1 0 5.7 5.7l1.1-1.1"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l2.5 2.5M14.5 8.5 17 11"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
  logout: '<path d="M15 4h4v16h-4"/><path d="M10 8l-4 4 4 4M6 12h11"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  image: '<rect x="3.5" y="4.5" width="17" height="15" rx="2"/><circle cx="9" cy="10" r="1.8"/><path d="M20.5 15.5 15.5 11 6 19.5"/>',
};
export const icon = (n, s = 20) => `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON[n] || ''}</svg>`;

export function toast(msg) {
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  document.body.append(t);
  setTimeout(() => t.remove(), 2800);
}

export const hasExtension = () => document.documentElement.getAttribute('data-emcon') === '1';

/** Ask the EMCON extension for a Ghost sign-in presentation for this page. */
export function ghost(req) {
  return new Promise((resolve, reject) => {
    if (!hasExtension()) return reject(new Error('Install the EMCON extension to sign in with Ghost.'));
    const id = crypto.randomUUID();
    const timer = setTimeout(() => { removeEventListener('message', on); reject(new Error('Timed out waiting for EMCON.')); }, 180e3);
    function on(e) {
      if (e.source !== window || e.data?.type !== 'EMCON_GHOST_RESPONSE' || e.data.id !== id) return;
      clearTimeout(timer); removeEventListener('message', on);
      e.data.ok ? resolve(e.data.result) : reject(new Error(e.data.error));
    }
    addEventListener('message', on);
    postMessage({ type: 'EMCON_GHOST_REQUEST', id, ...req }, location.origin);
  });
}

/** Full Ghost sign-in against EMCON accounts; spends a humanity token only for a new account. */
export async function ghostSignIn(forceToken = false) {
  const { challenge } = await api('/api/auth/ghost/challenge');
  const presentation = await ghost({ challenge, claims: ['human'], forceToken });
  try {
    return await api('/api/auth/ghost', { method: 'POST', body: { challenge, presentation } });
  } catch (e) {
    if (e.status === 428 && !forceToken) return ghostSignIn(true);
    throw e;
  }
}

/** Password strength 0–4, plain feedback. */
export function strength(pw) {
  let s = 0;
  if (pw.length >= 10) s++;
  if (pw.length >= 14) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw) && /[^a-z0-9]/i.test(pw)) s++;
  return { score: s, text: ['Too short', 'Weak', 'Okay', 'Good', 'Strong'][s], color: ['var(--bad)', 'var(--bad)', 'var(--warn)', 'var(--ok)', 'var(--ok)'][s] };
}

export const footer = () => `<footer class="site-foot"><div class="in">
  <div><a class="brand" href="/" style="display:flex;align-items:center;gap:8px;font-weight:750;color:var(--text);font-size:17px"><img src="/emcon-mark.svg" alt="" width="24" height="24">EMCON</a><p style="margin:8px 0 0">Scams explained before they cost you. Evidence, not AI guesses.</p></div>
  <div><h4>Product</h4><a href="/#features">Features</a><a href="/#pricing">Pricing</a><a href="/real.html">See it live</a><a href="https://github.com/iShowPP/36CRProjectEMCON/releases/latest">Download</a></div>
  <div><h4>Developers</h4><a href="/app#api">Link-check API</a><a href="https://github.com/iShowPP/36CRProjectEMCON">Source code</a></div>
  <div><h4>Legal</h4><a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/verify.html">Verify a receipt</a></div>
</div></footer>`;
