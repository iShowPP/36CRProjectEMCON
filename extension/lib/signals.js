// Deterministic scam-chain signals: lure wording and link shorteners. Plain word lists,
// so every finding can be quoted back to the user exactly as it appeared.

export const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'v.gd', 'cutt.ly', 'rb.gy', 'shorturl.at', 'ow.ly', 'buff.ly',
  'rebrand.ly', 'tiny.cc', 's.id', 't.ly', 'shorte.st', 'adf.ly', 'bl.ink', 'lnkd.in', 'surl.li', 'qrco.de', 'tny.sh',
]);

// kind -> pattern. "urgency" alone is weak (shops use it too); the others are classic scam openers.
const LURES = [
  ['prize', /\b(you(?:'ve| have)? won|congratulations|lucky (?:draw|winner)|lottery|claim (?:your|the|now)|free (?:gift|iphone|recharge|voucher)|gift card|reward points?)\b/i],
  ['account threat', /\b(account (?:will be |has been |is )?(?:suspended|blocked|deactivated|locked)|kyc (?:is )?(?:pending|update|expired|incomplete)|verify your (?:account|identity) (?:now|immediately|today))\b/i],
  ['authority', /\b(arrest warrant|cyber ?crime (?:cell|department)|income tax (?:refund|notice)|customs (?:duty|fee|clearance)|electricity (?:will be )?disconnect\w*|parcel (?:is )?(?:held|on hold)|courier (?:is )?(?:held|pending))\b/i],
  ['money first', /\b(processing fee|small fee|registration fee|release fee|guaranteed returns?|double your money|task(?:-based)? earning)\b/i],
  ['urgency', /\b(within \d+ ?(?:hours?|hrs|minutes?|mins)|expires? (?:today|soon|tonight)|act now|last chance|immediately)\b/i],
];

export const STRONG_LURE = (l) => l.kind !== 'urgency';

/** All lure phrases found in `text`: [{kind, phrase}] (first hit per kind). */
export function lureFindings(text) {
  const out = [];
  for (const [kind, re] of LURES) {
    const m = re.exec(String(text || ''));
    if (m) out.push({ kind, phrase: m[0].trim().slice(0, 60) });
  }
  return out;
}

/** Links mentioned in a pasted message (with or without scheme). */
export function urlsIn(text) {
  const out = [];
  const re = /\b(?:https?:\/\/)?(?:localhost|\d{1,3}(?:\.\d{1,3}){3}|(?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?(?:\/[^\s<>"')]*)?/gi;
  for (const m of String(text || '').matchAll(re)) {
    try { out.push(new URL(/^https?:/i.test(m[0]) ? m[0] : 'http://' + m[0]).href); } catch { /* not a URL */ }
  }
  return out.slice(0, 10);
}

// Form-field kinds that make a scam chain dangerous (credentials and money).
export const SENSITIVE_FIELDS = new Set(['password', 'card number', 'CVV', 'card expiry', 'one-time code (OTP)', 'PIN', 'ID number (Aadhaar / PAN / SSN)', 'bank account']);
