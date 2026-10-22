// Hostname helpers shared by the analysis and the per-tab observers.

const TWO_LEVEL = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'co.in', 'net.in', 'org.in', 'co.jp', 'com.br', 'co.nz', 'co.za', 'com.mx', 'com.sg', 'bank.in']);

export const normDomain = (host) => String(host || '').toLowerCase().replace(/^www\./, '');
export const isIp = (h) => /^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(':') || h.startsWith('[');
export const isLocal = (h) => h === 'localhost' || /\.(localhost|local|test|internal|example)$/.test(h) || isIp(h);

// "Registrable domain" (eTLD+1) with a small built-in suffix list.
export function registrable(host) {
  host = normDomain(host);
  if (isIp(host)) return host;
  const p = host.split('.');
  if (p.length <= 2) return host;
  return TWO_LEVEL.has(p.slice(-2).join('.')) ? p.slice(-3).join('.') : p.slice(-2).join('.');
}

export const sameSite = (a, b) => registrable(a) === registrable(b);
