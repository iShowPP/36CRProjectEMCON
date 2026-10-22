// Deterministic DOM-structure fingerprint (no AI, no vision): tokenise the tag tree,
// shingle it, SimHash the shingles. Clones of a page keep a near-identical SimHash
// even when text, classes, ids and asset URLs are changed.

const VOID = new Set('area base br col embed hr img input link meta source track wbr'.split(' '));
const OPAQUE = /<(script|style|noscript|template|svg)\b[\s\S]*?<\/\1\s*>/gi;

export function domTokens(html) {
  html = html.replace(/<!--[\s\S]*?-->/g, '').replace(OPAQUE, (_, t) => `<${t}></${t}>`);
  const re = /<(\/?)([a-zA-Z][\w-]*)([^>]*)>/g;
  const stack = [];
  const seq = [];
  let m;
  while ((m = re.exec(html))) {
    const [, close, rawTag, attrs] = m;
    const tag = rawTag.toLowerCase();
    if (tag.startsWith('emcon-')) continue; // our own injected UI
    if (close) {
      const i = stack.lastIndexOf(tag);
      if (i >= 0) stack.length = i;
      continue;
    }
    let label = tag;
    if (tag === 'input') {
      const t = /\btype\s*=\s*["']?([\w-]+)/i.exec(attrs);
      label += ':' + (t ? t[1].toLowerCase() : 'text');
    }
    seq.push(`${stack.length}>${stack[stack.length - 1] || ''}>${label}`);
    if (!VOID.has(tag) && !attrs.trim().endsWith('/')) stack.push(tag);
  }
  return seq;
}

// 64-bit FNV-1a, split into two 32-bit halves to stay fast without BigInt in the hot loop.
function fnv1a64(s) {
  let h0 = 0x84222325, h1 = 0xcbf29ce4;
  for (let i = 0; i < s.length; i++) {
    h0 = (h0 ^ s.charCodeAt(i)) >>> 0;
    // multiply (h1:h0) by FNV prime 0x100000001b3
    const l = h0 * 0x1b3;
    const carry = Math.floor(l / 0x100000000);
    h1 = (Math.imul(h1, 0x1b3) + Math.imul(h0, 0x100) + carry) >>> 0;
    h0 = l >>> 0;
  }
  return [h0 >>> 0, h1 >>> 0];
}

export function simhash64(tokens, shingle = 3) {
  const v = new Int32Array(64);
  for (let i = 0; i + shingle <= tokens.length; i++) {
    const [lo, hi] = fnv1a64(tokens.slice(i, i + shingle).join('|'));
    for (let b = 0; b < 32; b++) {
      v[b] += (lo >>> b) & 1 ? 1 : -1;
      v[b + 32] += (hi >>> b) & 1 ? 1 : -1;
    }
  }
  let hi = 0, lo = 0;
  for (let b = 0; b < 32; b++) {
    if (v[b] > 0) lo |= 1 << b;
    if (v[b + 32] > 0) hi |= 1 << b;
  }
  return (hi >>> 0).toString(16).padStart(8, '0') + (lo >>> 0).toString(16).padStart(8, '0');
}
