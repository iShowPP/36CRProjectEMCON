// Where this server lives. Local dev needs no config: localhost is the "official" site and
// 127.0.0.1 plays the second company / the phishing host. When hosted, set EMCON_PUBLIC_URL
// (Render provides RENDER_EXTERNAL_URL automatically) and optionally EMCON_ALT_URL for a
// second hostname that reaches the same server.

const PUBLIC_URL = (process.env.EMCON_PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || '').replace(/\/+$/, '');
const ALT_URL = (process.env.EMCON_ALT_URL || '').replace(/\/+$/, '');

export const HOSTED = !!PUBLIC_URL;
export const OFFICIAL_HOST = HOSTED ? new URL(PUBLIC_URL).hostname : 'localhost';
export const ALT_HOST = ALT_URL ? new URL(ALT_URL).hostname : HOSTED ? null : '127.0.0.1';

/** Public URLs for the demo pages, as seen from this request. */
export function publicUrls(requestOrigin) {
  if (HOSTED) return { hosted: true, official: PUBLIC_URL, alt: ALT_URL || null };
  const port = new URL(requestOrigin).port;
  const withPort = (host) => `http://${host}${port ? ':' + port : ''}`;
  return { hosted: false, official: withPort('localhost'), alt: withPort('127.0.0.1') };
}
