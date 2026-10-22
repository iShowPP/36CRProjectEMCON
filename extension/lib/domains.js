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

// Undo the look-alike tricks phishers use in hostnames: digits for letters, "rn" for "m",
// accented letters. (Non-Latin look-alikes arrive as punycode and are flagged separately.)
const CONFUSABLE = { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b' };
const skeleton = (s) => s.normalize('NFKD').replace(/[̀-ͯ]/g, '').replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/[0-9]/g, (c) => CONFUSABLE[c] || c);

function editDistance(a, b) {
  const row = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let prev = row[0];
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cur = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = cur;
    }
  }
  return row[b.length];
}

// Does this hostname borrow a brand's name? Whole hostname parts only, so "applebees" is not "apple".
export function imitation(domain, brand) {
  const labels = domain.split('.').slice(0, -1); // the TLD can't imitate anything
  for (const part of labels.flatMap((l) => l.split('-')).filter(Boolean)) {
    const sk = skeleton(part);
    for (const t of brand.tokens || []) {
      if (part === t) return { strong: false, text: `uses the name "${t}"` };
      if (sk === t) return { strong: true, text: `spells "${t}" with look-alike characters ("${part}")` };
      if (t.length >= 6 && editDistance(sk, t) === 1) return { strong: true, text: `is one letter away from "${t}" ("${part}")` };
    }
  }
  return null;
}
