# Test site (never served by the real product)

Made-up pages the automated tests drive: a fictional bank and its phishing clone, a prize-SMS scam chain, a newspaper with trackers, a photo feed, a bank vault, a Ghost sign-in shop and a checkout with an injected script.

The server serves this folder only when `EMCON_DEMO_SITE=1` (set by `test/e2e.mjs` and `test/extension.mjs`). The live EMCON site never does: every feature is shown on real websites instead (`/real.html`).
