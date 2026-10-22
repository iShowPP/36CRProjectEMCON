// Personal web-of-trust scoring.
//
// Sybil resistance comes from two rules:
//  1. Only identities reachable from *your own* roots (you, friends you added,
//     security groups you follow) count at all. A scammer minting 10,000 DIDs gains
//     nothing unless someone you trust vouches for them.
//  2. Every root has a total budget of 1.0. However many accounts hang off one
//     compromised friend, that friend's branch can never contribute more than 1.0.

export const DECAY = 0.6;
export const MAX_HOPS = 3;
const clamp01 = (x) => Math.min(1, Math.max(0, Number(x) || 0));

// roots: [{did, weight}], vouches: [{issuer, subject, weight}] -> Map(did -> {t, root, hops})
export function computeTrust(roots, vouches) {
  const trust = new Map();
  for (const r of roots) {
    const t = clamp01(r.weight);
    if (t > (trust.get(r.did)?.t ?? 0)) trust.set(r.did, { t, root: r.did, hops: 1 });
  }
  for (let round = 1; round < MAX_HOPS; round++) {
    let changed = false;
    for (const v of vouches) {
      const from = trust.get(v.issuer);
      if (!from || from.hops > round) continue;
      const t = from.t * clamp01(v.weight) * DECAY;
      const cur = trust.get(v.subject);
      if (t > 0.01 && (!cur || t > cur.t)) {
        trust.set(v.subject, { t, root: from.root, hops: from.hops + 1 });
        changed = true;
      }
    }
    if (!changed) break;
  }
  return trust;
}

// attestations: [{issuer, verdict: 'trusted'|'scam', transacted, issued, note}]
export function scoreDomain(attestations, trust) {
  const latest = new Map();
  for (const a of attestations) {
    const prev = latest.get(a.issuer);
    if (!prev || a.issued > prev.issued) latest.set(a.issuer, a);
  }
  // spend strongest evidence first so the per-root budget favours it
  const ranked = [...latest.values()].sort((a, b) => (trust.get(b.issuer)?.t ?? 0) - (trust.get(a.issuer)?.t ?? 0));
  const budget = new Map();
  let pos = 0, neg = 0, ignored = 0;
  const evidence = [];
  for (const a of ranked) {
    const tr = trust.get(a.issuer);
    if (!tr) { ignored++; continue; }
    const left = budget.get(tr.root) ?? 1;
    const w = Math.min(tr.t, left);
    budget.set(tr.root, left - w);
    if (w <= 0) continue;
    if (a.verdict === 'scam') neg += w;
    else pos += w * (a.transacted ? 1 : 0.5);
    evidence.push({ issuer: a.issuer, verdict: a.verdict, transacted: !!a.transacted, weight: +w.toFixed(2), hops: tr.hops, note: a.note || '' });
  }
  return { pos, neg, ignored, evidence };
}
