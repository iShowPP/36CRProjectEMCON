// EMCON line icons (24×24, 2px stroke, currentColor). Drawn for EMCON; shared by the
// extension pages. content/bridge.js keeps its own copy (content scripts aren't modules).
const P = {
  shield: '<path d="M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6z"/>',
  shieldCheck: '<path d="M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6z"/><path d="M9 12l2 2 4-4.5"/>',
  alert: '<path d="M12 4 2.8 19.5h18.4z"/><path d="M12 10v4.5"/><path d="M12 17.3v.2"/>',
  stop: '<path d="M8.3 3h7.4L21 8.3v7.4L15.7 21H8.3L3 15.7V8.3z"/><path d="M9.5 9.5l5 5M14.5 9.5l-5 5"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5"/><path d="M12 7.6v.2"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.6 9.6a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.5v.6"/><path d="M12 16.9v.2"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
  checkCircle: '<circle cx="12" cy="12" r="9"/><path d="M8 12.3l2.8 2.8L16 9.6"/>',
  x: '<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>',
  xCircle: '<circle cx="12" cy="12" r="9"/><path d="M9.2 9.2l5.6 5.6M14.8 9.2l-5.6 5.6"/>',
  minus: '<circle cx="12" cy="12" r="9"/><path d="M8.5 12h7"/>',
  home: '<path d="M3.5 11 12 4l8.5 7"/><path d="M6 9.5V20h12V9.5"/><path d="M10 20v-5h4v5"/>',
  link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 1 0-5.7-5.7l-1.1 1.1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 1 0 5.7 5.7l1.1-1.1"/>',
  eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/>',
  more: '<circle cx="5.5" cy="12" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="18.5" cy="12" r="1.3"/>',
  image: '<rect x="3.5" y="4.5" width="17" height="15" rx="2"/><circle cx="9" cy="10" r="1.8"/><path d="M20.5 15.5 15.5 11 6 19.5"/>',
  fingerprint: '<path d="M6.3 17.5A9 9 0 0 1 5 12.6a7 7 0 0 1 12.2-4.7"/><path d="M19 11.5c.1.7.1 1.4 0 2"/><path d="M9 19.6c1-1.9 1.5-4 1.5-6.4a1.5 1.5 0 0 1 3 0c0 .6 0 1.2-.1 1.8"/><path d="M8 12.6a4 4 0 0 1 8 0c0 2.6-.5 5-1.6 7.2"/>',
  ghost: '<path d="M6 20.5V11a6 6 0 0 1 12 0v9.5l-2-1.5-2 1.5-2-1.5-2 1.5-2-1.5z"/><path d="M10 10.5v.5M14 10.5v.5"/>',
  users: '<circle cx="9" cy="8.5" r="3.2"/><path d="M3 20a6 6 0 0 1 12 0"/><path d="M15.5 5.6a3.2 3.2 0 0 1 0 5.8"/><path d="M17.5 14.4A6 6 0 0 1 21 20"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M12 2.8v2.4M12 18.8v2.4M2.8 12h2.4M18.8 12h2.4M5.5 5.5l1.7 1.7M16.8 16.8l1.7 1.7M5.5 18.5l1.7-1.7M16.8 7.2l1.7-1.7"/>',
  receipt: '<path d="M6 3h8.5L19 7.5V21H6z"/><path d="M14 3v5h5"/><path d="M9 12.5h6M9 16.5h6"/>',
  flag: '<path d="M5 21V4"/><path d="M5 4.5h11.5L14.5 9l2 4.5H5"/>',
  thumb: '<path d="M7 11v9H4v-9z"/><path d="M7 11l4-7c1.4 0 2.3 1 2 2.4L12.5 10H19a1.6 1.6 0 0 1 1.6 1.9l-1.3 6.6A2 2 0 0 1 17.4 20H7"/>',
  message: '<path d="M4 5h16v11H9.5L5 19.5V16H4z"/>',
  back: '<path d="M19 12H5"/><path d="M11 6l-6 6 6 6"/>',
  chevron: '<path d="M9.5 6l6 6-6 6"/>',
  chevronDown: '<path d="M6 9.5l6 6 6-6"/>',
  copy: '<rect x="8.5" y="8.5" width="12" height="12" rx="2"/><path d="M15.5 8.5V5a1.5 1.5 0 0 0-1.5-1.5H5A1.5 1.5 0 0 0 3.5 5v9A1.5 1.5 0 0 0 5 15.5h3.5"/>',
  external: '<path d="M14 4h6v6"/><path d="M20 4l-9 9"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
  download: '<path d="M12 4v11"/><path d="M7 10.5l5 5 5-5"/><path d="M4.5 20h15"/>',
  recover: '<path d="M20 12a8 8 0 1 1-2.4-5.7"/><path d="M20 4.5V9h-4.5"/>',
  pin: '<path d="M9 4h6l-1 6 3 3H7l3-3z"/><path d="M12 13v7.5"/>',
  lock: '<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l2.5 2.5M14.5 8.5 17 11"/>',
  server: '<rect x="4" y="4" width="16" height="7" rx="1.5"/><rect x="4" y="13" width="16" height="7" rx="1.5"/><path d="M8 7.5h.01M8 16.5h.01"/>',
  spark: '<path d="M12 3v4M12 17v4M3 12h4M17 12h4"/>',
};

/** <svg> markup for an icon; size in px. */
export const icon = (name, size = 20, cls = '') =>
  `<svg class="ic ${cls}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || ''}</svg>`;

// One meaning per status: icon, plain word, colour role.
export const LEVEL = {
  danger: { icon: 'stop', role: 'danger', head: 'Very likely a scam', advice: "Don't enter passwords, card numbers, UPI PIN or OTP here. Close this page." },
  caution: { icon: 'alert', role: 'caution', head: 'Be careful here', advice: 'Double-check the web address before you sign in or pay.' },
  trusted: { icon: 'shieldCheck', role: 'safe', head: 'Trusted by your network', advice: 'People and sources you follow have used this site safely.' },
  unknown: { icon: 'shieldCheck', role: 'calm', head: 'No warning signs found', advice: "That's not a guarantee. Never share an OTP you didn't ask for." },
};
export const STATUS = {
  found: { word: 'Warning', role: 'danger', icon: 'alert' },
  unknown: { word: "Couldn't check", role: 'caution', icon: 'help' },
  good: { word: 'Good sign', role: 'safe', icon: 'checkCircle' },
  clear: { word: 'OK', role: 'ok', icon: 'check' },
  note: { word: 'Info', role: 'neutral', icon: 'info' },
  na: { word: 'Not needed', role: 'neutral', icon: 'minus' },
  kept: { word: 'Kept', role: 'safe', icon: 'checkCircle' },
  broken: { word: 'Broken', role: 'danger', icon: 'xCircle' },
  untested: { word: 'Not tested yet', role: 'caution', icon: 'help' },
};
export const ORDER = { found: 0, broken: 0, unknown: 1, untested: 1, good: 2, kept: 2, note: 3, clear: 4, na: 5 };
