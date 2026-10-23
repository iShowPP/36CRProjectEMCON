# EMCON: evidence, not guesses

**One browser extension + one tiny server that protect people from phishing, scam chains, fake media, broken privacy promises, payment scams and tracking, using cryptography and deterministic checks instead of probabilistic AI detectors. Every conclusion comes with the evidence behind it, and you can export that evidence as a signed receipt.**

**Live: https://emcon-e2tu.onrender.com** (free hosting, so the first visit after a quiet spell takes ~50 s to wake up). **Every feature on real websites: [/real.html](https://emcon-e2tu.onrender.com/real.html).**

AI detectors fail in two directions: they flag real content, and attackers learn to slip past them. EMCON asks questions that have provable answers:

| Protection | Instead of asking… | EMCON asks… | Built on |
|---|---|---|---|
| **Phishing & look-alikes** | "Does an algorithm think this site is safe?" | "Has anyone *I* trust reported it? Is it a clone or a look-alike of a brand? How old is the domain?" | W3C VC 2.0 + `eddsa-jcs-2022`, did:key, SimHash, RDAP, OpenPhish feed |
| **Scam chain detector** | "Is this one URL bad?" | "Did prize or threat wording, redirects and an unofficial site all lead to a form asking for my card and OTP?" | `webNavigation` + `webRequest` redirect tracking, quoted lure phrases, sensitive-field detection |
| **Privacy promise monitor** | "Does the privacy policy sound nice?" | "Which third parties did the page actually contact, and did tracking stop after I said no?" | Per-tab request log, page-side feature monitor, `<meta name="privacy-promise">`, legal baseline |
| **Evidence receipts** | "Trust our 82% risk score." | "Here is every check: found, clear, unknown or not applicable. Signed and timestamped." | VC signed by your did:key + server timestamp over the digest |
| **Provenance** | "Is this image AI-generated?" | "Who signed it, has it changed since, and is the signer on the C2PA trust list?" | Content Credentials (C2PA) validation: COSE signature, assertion hashes, data hash, X.509 chain to the official trust anchors; publisher signing; perceptual-hash soft binding |
| **Ghost sign-in** | "Who is this user?" | "Can they *prove* they're a verified adult, without revealing who they are?" | RSA blind signatures (RFC 9474-style), per-site Ed25519 keys, WebAuthn. Runs on EMCON's own login without email or password |
| **Payment brake** | "Does this payment look fraudulent?" | "Has it waited out a cooling-off pause and passed family approval?" | Real-time family approval via EMCON dashboard, 5-minute cooling off pause on flagged payment pages |
| **Anti-fingerprinting** | (nothing) | "Can a tracker recognise this device on the next visit?" | Secret per-visit noise applied before any page script, bucketed hardware values, Global Privacy Control |
| **Checkout alarm** | "Is this shop reputable?" | "Has a new outside script appeared on this payment page since my first visit?" | Trust-on-first-use script inventory per payment page, content fingerprints |
| **Trust by QR code & ratings** | "What do anonymous reviews say?" | "What do people I actually know, and verified people, say?" | Signed QR vouches between contacts, ratings counted only after one blind humanity token |

---

## Install the extension (for users)

EMCON is a browser extension for **Chrome, Edge and Brave** (version 137+).

1. Download the `emcon-extension-v<version>.zip` file from the **[latest release](https://github.com/iShowPP/36CRProjectEMCON/releases/latest)** (already set to the live server) and unzip it. (Building it yourself: `npm run pack -- --server=<your server>` writes it to `dist/`.)
2. Open `chrome://extensions` (`edge://extensions` in Edge) and turn on **Developer mode**.
3. Click **Load unpacked** and choose the unzipped **`emcon-extension`** folder.
4. A welcome page opens. Pin EMCON to the toolbar, enter your EMCON server address, and optionally set up Ghost.

What works where:
- **No server needed:** anti-fingerprinting and image signature checks start working straight away.
- **Needs an EMCON server:** Ghost sign-in, scam and phishing reports (including the live feed), and recovering provenance for stripped images. See *Host the server* below.

The same zip is what you'd upload to the Chrome Web Store.

## Works on real websites

Everything below runs on websites we don't control. **Step-by-step guide for every feature on real sites: [emcon-e2tu.onrender.com/real.html](https://emcon-e2tu.onrender.com/real.html)** (also `/real.html` on your own server), and `npm run test:real` checks all of it automatically against the live internet.

| On real sites | How |
|---|---|
| **Live phishing sites are blocked** | The server imports the [OpenPhish](https://openphish.com) community feed every 6 hours (≈250–300 live phishing sites) and signs each entry as an attestation. The extension follows the feed by default (you can remove it like any other source). Shared hosts such as `sites.google.com` and brands' own domains are never flagged. |
| **Look-alike addresses are flagged** | `paypa1-secure.com`, `micros0ft-login.net`, `hdfcbank-kyc.top`: the hostname borrows a real brand (PayPal, Google, Microsoft, Apple, Amazon, Meta, SBI, HDFC, ICICI, Axis, Paytm and more), with digit-for-letter swaps and one-letter typos undone, without being that brand's official domain. RBI's verified `.bank.in` zone counts as official for Indian banks. |
| **Brand-new domains** | Registration dates come from the public RDAP registry. |
| **Check a link** | Paste a link or a whole SMS into the popup. The server follows its redirects (HTTP 3xx and `<meta refresh>`) so your browser never opens it, then the usual checks run on where it lands. Tested with live OpenPhish sites (risk 93, "very likely a scam") and real short links (`aka.ms`, `bit.ly`, `wa.me`: no warning). Some sites answer data-centre addresses differently (YouTube shows Google's "unusual traffic" page), and EMCON reports where the link went for the server. |
| **Anti-fingerprinting** | Registered to run before any page script, so [browserleaks.com/canvas](https://browserleaks.com/canvas) shows a new signature on every visit, and your real, stable one when you turn protection off for the site. [browserleaks.com/webgl](https://browserleaks.com/webgl) sees a common GPU. |
| **Privacy promises** | Most sites outside Europe never show a cookie banner, so EMCON sends **Global Privacy Control** (`Sec-GPC: 1` and `navigator.globalPrivacyControl`), a "do not sell or share" signal the site receives, then checks whether trackers still load. In our tests Times of India, CNN, Forbes and Wired loaded 43–48 tracking domains each despite it. |
| **Content Credentials (C2PA)** | EMCON validates real C2PA files: the claim signature, every assertion, the image hash and the signer's certificate chain against the trust lists the official verifier uses. On the C2PA standards body's [public test files](https://github.com/c2pa-org/public-testfiles/tree/main/legacy/1.4/image) it gives the official verifier's verdicts: Truepic's camera capture is *Verified · Truepic*, the C2PA test certificate is *unknown signer*, the edited copy is *Altered after signing*, the broken signature and the tampered assertion are *Forged*. Click *Recognise copies* on a verified photo and the server re-checks it and keeps its visual fingerprint: the same photo resized by the public images.weserv.nl CDN (credentials stripped) then shows *Recovered · Truepic*. |
| **Checkout alarm** | On a real card form ([W3Schools' checkout form](https://www.w3schools.com/howto/howto_css_checkout_form.asp), or [EFF's donation page](https://supporters.eff.org/donate/join-eff-4) with Stripe's card field) the first visit is recorded and a return visit stays quiet; a script injected from a new domain raises the alarm before you type. |
| **Payment brake** | Live phishing pages that ask for card, OTP, PIN or bank details get a 5-minute pause and an "ask your family" button on the block page. |

Checked against real sites (Google, GitHub, Amazon, Wikipedia, Hacker News, PayPal, SBI, HDFC NetBanking, Instagram login): none of them triggers a warning.

## Host the server

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/iShowPP/36CRProjectEMCON)

1. Click the button, sign in to Render (free), and click **Apply**. `render.yaml` sets everything up, including a generated `EMCON_SECRET`.
2. After about a minute you have `https://emcon-xxxx.onrender.com` and a free Postgres database (`emcon-db`) for accounts and settings. Open it: that's your EMCON site.
3. Build the zip for users with your address baked in:
   ```bash
   npm run pack -- --server=https://emcon-xxxx.onrender.com
   ```
4. Attach `dist/emcon-extension-v1.5.0.zip` to a GitHub Release so people can download it.

Anywhere else: `docker build -t emcon . && docker run -p 8787:8787 -e EMCON_SECRET=<random> -e EMCON_PUBLIC_URL=https://your.host emcon`.

| Variable | Meaning |
|---|---|
| `EMCON_SECRET` | All server keys are derived from it. Keep it fixed and the keys survive restarts, even on hosts that wipe the disk. |
| `DATABASE_URL` | PostgreSQL connection string (provided automatically by Render's Postgres `emcon-db`). When present, state is kept in Postgres; otherwise, falls back to `data/db.json`. |
| `EMCON_PUBLIC_URL` | Public https address (auto-detected on Render). |
| `EMCON_ALT_URL` | Optional second hostname for the same server. |
| `EMCON_FEED=off` / `EMCON_FEED_URL` | Disable or replace the live phishing feed. |
| `EMCON_ALERT_WEBHOOK` | e.g. `https://ntfy.sh/<topic>` to push guardian alerts to phones. |
| `EMCON_DATA`, `PORT` | Data folder and port. |

## Quick start (local development)

Requires **Node 22+** and **Chrome, Edge or Brave**.

```bash
npm install            # pg (Postgres) and jpeg-js (photo fingerprints on the server)
npm start              # starts server on :8787
```

Load the extension into your browser:
1. Open `chrome://extensions` (or `edge://extensions`) and turn on **Developer mode**.
2. Click **Load unpacked** and select the `extension/` folder.
3. Open `http://localhost:8787/` to view the SaaS landing page, `/app` for the dashboard, or `/real.html` for the real-internet guide.

### Tests

```bash
npm test               # 67 API tests: every server feature, C2PA validation, accounts, family, API
npm run test:browser   # 32 tests that load the real extension into headless Chrome: install flow, every protection, scam chain, link check, GPC, privacy promises, receipts, Magecart alarms
npm run test:prod      # the server as deployed: no test site, no demo APIs, no made-up brands
npm run test:all       # all three
npm run test:real      # needs internet: every feature on real websites (OpenPhish, C2PA files, Times of India, browserleaks, W3Schools, EFF, live phishing pages)
```

Set `HEADED=1` to watch the browser tests, or `EMCON_BROWSER=<path to browser exe>` to pick a browser. The browser and API tests use a made-up test site (`test/site`, served only with `EMCON_DEMO_SITE=1`) so every case is guaranteed to appear; `test:real` and `node tools/real-screens.mjs` (the product screenshots) use only real websites. Phishing pages open in a throwaway headless profile with downloads blocked, and nothing is typed into them.

## Checkout script-change alarm (Magecart)

Card skimmers ("Magecart") are scripts slipped into a real shop's payment page, often injected after it loads, that copy card details as you type. Few consumer tools watch for them.

- **Trust on first use.** The first time you see a payment page (card number, CVV or expiry fields, or a Stripe, Braintree, Adyen, Razorpay or Shopify card frame), EMCON records its scripts and a fingerprint of each one's content. Everything the page loads during that first visit, including ad and tag-manager scripts that arrive late, is the baseline.
- **Alarm.** On later visits, a script from a **new outside domain** raises an amber warning before you type, and again when you click into a card field: *"A script from cdn-x.com appeared on this payment page since your visit on 23 Oct… Don't enter card details unless you know why it changed."* Scripts injected after load are caught too.
- **Low noise.** Sites redeploy and ad scripts update constantly, so content changes, renamed bundles (`app.3f2a.js`), new files from domains the page already used and new scripts from known ad or analytics services are shown as notes, not warnings.
- **Reputation doesn't cancel it.** Magecart hits reputable shops, so a good reputation never outweighs this alarm.
- **Trust this change** accepts a legitimate change for that page.
- **On a real site:** open [W3Schools' checkout form](https://www.w3schools.com/howto/howto_css_checkout_form.asp), close it, open it again (quiet), then add a script from another domain in the DevTools console, as a skimmer would. The alarm appears before you type.

## Trust by QR code, and community ratings

**QR codes (EMCON → More → Share trust by QR code).** Friends swap *contact codes* once, in person (a self-signed did:key, so the key is really theirs). After that, a friend's *vouch code* ("I used shop.com safely") or *warning code* ("this is a scam") counts in your checks, with no server in the middle. Codes are compact signed JSON (about 330 characters, QR level M), bound to one domain, with a nonce and a 90-day expiry; a newer code from the same person replaces the old one. A code from someone who isn't in your contacts is refused (strangers can't vote), and changing one character breaks the signature. Scan with the camera, upload a photo or screenshot, or paste the text. Drawing uses qrcode-generator (MIT) and scanning uses jsQR (Apache-2.0), both in `extension/vendor`.

**Community ratings (popup → This site → Community rating).** 1–5 stars plus plain tags ("never delivered", "asked for OTP or PIN"…), signed with your EMCON key, one per person per site. A rater counts as a *verified person* only after spending one blind humanity token (Ghost), so a bot farm can't mint thousands of reviewers; unverified ratings are shown but not counted. Lookups use the same 5-character hash prefix as scam reports. Ratings feed the site check with small weight (a crowd can be wrong): 3+ verified ratings averaging ≤2 add a finding, ≥4 a good sign. Ratings from people in your trust network are listed by name.

## The product site (SaaS)

`/` is the SaaS product site: accounts, plans, family protection, a link-check API, publisher photo signing and real-time payment approvals. The real-internet guide is at [/real.html](/real.html). Test fixtures live in `test/site/` and are never served by the product.

| Page | What it does |
|---|---|
| `/signup`, `/login` | Email + password (scrypt) or **Continue with EMCON Ghost** (no email at all). Signup shows a **recovery key**: no email resets, so nobody can talk support into handing over an account. |
| `/recover` | Reset the password with the recovery key; signs out every other session and issues a new key. |
| `/app` | Dashboard: weekly protection across your browsers, alerts, **Waiting for you** (payment brake approvals), **Photos** (publisher domain verification & photo signing), a message/link checker, **Browsers & family** (6-digit pairing codes typed into the extension), **Link-check API** keys, **Plan & billing**, settings (password, recovery key, sign-out everywhere, data export, account deletion). |
| `/real.html` | Real-world interactive guide: walk through every shield on live websites across the real internet. |
| `/verify.html` | Receipt verifier: check any EMCON evidence receipt and its cryptographic timestamp signature. |
| `/privacy`, `/terms` | Privacy policy and terms of service. |

Connected browsers report **weekly counts only** (pages checked, scams blocked…), never addresses; a family member's new block shows up as an alert. Sessions are HttpOnly SameSite cookies, every write must come from our own origin, sign-in is rate-limited, and session tokens, API keys and recovery keys are stored only as hashes.

**API:** `POST /api/v1/check` with `Authorization: Bearer emk_live_…` and `{"text": "<message or link>"}` returns `verdict` (scam / suspicious / no_warnings), `risk`, `final`, `hops` and `reasons`. Daily limits by plan: Free 50, Family 500, Business 20,000.

**Card payments aren't switched on yet.** Plans (Free ₹0, Family ₹149/month, Business ₹2,999/month) switch instantly and their limits apply, with a ₹0 invoice. Charging cards needs a Razorpay or Stripe merchant account in the owner's name; the plan switch is where its checkout goes.

## Design

The interface was rebuilt from a study of the five closest consumer products (Malwarebytes Browser Guard, Ghostery, Bitdefender Web Sage / Scamio, DuckDuckGo, Norton 360 / Genie) plus Chrome's Safe Browsing page and Truecaller: one status said three ways (icon, colour, plain word), advice before evidence, the path drawn like parcel tracking, scam phrases highlighted in your message, a red *Back to safety* page, and nothing smaller than 12 px. The study, our users and the rules we adopted: [docs/ui-research.md](docs/ui-research.md).

## 5-minute walkthrough on real websites

Install the extension from the latest release (it points at the live server), then:

1. **Scam SMS.** On [/real.html](https://emcon-e2tu.onrender.com/real.html), copy the test message: a KYC threat with a link that is in the live OpenPhish feed right now. EMCON icon → *Check message* → paste → *Check safely*: **Very likely a scam**, with the feed report, the threat wording and where the link really goes. Your browser never opens it.
2. **Real logins stay quiet.** [paypal.com/signin](https://www.paypal.com/signin), [SBI](https://www.onlinesbi.sbi.bank.in/), [accounts.google.com](https://accounts.google.com/): no warning.
3. **Photos.** Open the [Truepic photo](https://github.com/c2pa-org/public-testfiles/blob/main/legacy/1.4/image/jpeg/truepic-20230212-camera.jpg): *Verified · Truepic*. The [edited one](https://github.com/c2pa-org/public-testfiles/blob/main/legacy/1.4/image/jpeg/adobe-20220124-XCA.jpg): *Altered after signing*. On the Truepic label click *Recognise copies*, then open the [CDN copy](https://images.weserv.nl/?url=raw.githubusercontent.com/c2pa-org/public-testfiles/main/legacy/1.4/image/jpeg/truepic-20230212-camera.jpg&w=1200&output=jpg): *Recovered · Truepic*.
4. **Privacy.** Open [timesofindia.indiatimes.com](https://timesofindia.indiatimes.com/) → EMCON → *Privacy*: dozens of tracking domains despite your Global Privacy Control signal, each named.
5. **Fingerprinting.** [browserleaks.com/canvas](https://browserleaks.com/canvas): a new signature on every reload.
6. **Checkout alarm.** [W3Schools' checkout form](https://www.w3schools.com/howto/howto_css_checkout_form.asp): open, close, open again, then inject a script from the console (the line is on /real.html). Amber alarm before you type.
7. **Family and the payment brake.** Sign up, *Browsers & family* → *Connect a browser*, type the code into a second browser's EMCON settings. A live phishing page that asks for card or OTP details shows *Continue in 5:00* and *Ask … to check it*; the request appears under *Waiting for you*.
8. **Ghost.** EMCON → More → Ghost sign-in → *Set up Ghost*, then [/login](https://emcon-e2tu.onrender.com/login) → *Continue with EMCON Ghost*: an account with no email or password.
9. **Receipts.** Anywhere above, *Save signed proof*, then [/verify.html](https://emcon-e2tu.onrender.com/verify.html): valid; change one character: not genuine.

---

## Loopholes in the original ideas, and how EMCON closes them

### 👻 1. Ghost Engine
| Loophole in the pitch | Fix in EMCON |
|---|---|
| A self-generated zk proof of "over 18" proves nothing. *Someone* must attest it. | A one-time **issuer** verifies the person, then signs tokens **blind** (`server/issuer.js`, `extension/lib/blindrsa.js`). It can't link a token back to the person. |
| One human could mint unlimited "verified humans" (Sybil). | Tokens are **single-use** per site, with a **monthly quota** per verified human (20). The spent-token check is tested. |
| A malicious issuer can tag users by giving each one a unique key. | Issuer keys live at one public URL. The extension **pins** them and refuses a key change (key-consistency check). |
| A phishing site can relay your sign-in to the real site. | The extension signs over the **real origin from Chrome** (`sender.origin`), not one the page claims. Relayed presentations fail. |
| Any page could silently request your identity. | Every request opens a **consent window** gated by passkey (WebAuthn UV) or PIN. |
| Reusing one token on two sites would link them. | Tokens are consumed on use and never shown twice. Logins on a returning site need no token. |
| "Randomise screen size / locale" breaks sites, gets caught by CSS media queries and `Intl`, and random-per-read noise is *itself* a fingerprint. | Noise is a **pure function of a secret seed and the pixel index**: reading twice on a page gives the same answer, but every visit (and every site) gets a new seed, so visits can't be linked. The seed is made inside the page guard's closure and never exposed. High-entropy values are **bucketed to the most common value**. Screen, locale and timezone are never faked. |
| An extension that injects after the page loads is too late: fingerprinting code runs first. | The guard is a **registered MAIN-world script at `document_start`**, so Chrome runs it before the page's first script (verified on browserleaks.com). A fresh `about:blank` iframe can't be used to fetch untouched functions: same-origin frames are patched the moment the page touches `.contentWindow`. Wrappers look native: `toString()`, no `prototype`, not constructible. |

### 🖼️ 2. Provenance
| Loophole | Fix |
|---|---|
| Twitter/Reddit/WhatsApp **strip metadata**, so the signature is gone. | **Soft binding**: a 64-bit perceptual hash goes into a registry at signing time. Stripped copies show *"↺ Provenance recovered"* and link to the original so the viewer can compare. |
| 🔴 "Unverified = synthetic" is false. Most real photos are unsigned, so this would smear real content. | Unsigned images get **no badge**. EMCON only shows positive evidence or tampering. |
| Copy a real manifest onto an edited image. | The signature covers a hash of the **pixel-defining bytes** (PNG critical chunks / JPEG non-APPn segments), so pixel edits show as **✖ Altered**. |
| Anyone can sign anything. | Only keys on the **trust list** earn ✔ Verified. Others show "Signed, unknown signer". A manifest claiming a trusted keyId is checked against the trust-list key, never the key it carries. |
| Perceptual-hash collisions could borrow legitimacy. | A recovered match is labelled as *evidence, not proof*, with a link to the original image so people can compare it with their own eyes. |
| Real C2PA files exist in the wild. | EMCON **validates** them (`extension/lib/c2pa.js`): the COSE signature, every assertion hash, the data hash over the file, and the certificate chain to the official trust anchors. Same verdicts as the official verifier on the C2PA public test files. |
| A self-signed certificate can claim any name ("Reuters"). | Only a chain to the C2PA trust anchors (or a certificate on the known-signer list) earns *Verified*. Anything else is *unknown signer*. |
| A client could plant a fake fingerprint for a trusted photo. | *Recognise copies* sends only the address; the server downloads the file, re-validates it, requires a trusted signer and computes the fingerprint itself. |

### 🏦 3. Payment brake (and the Honey-Vault engine for banks)
On real websites EMCON can't hold money, so it slows the moment of payment instead: a scam page that asks for card, OTP, PIN or bank details gets a 5-minute pause (it survives a reload) and an *Ask … to check it* button that puts the request, with EMCON's reasons, on the account owner's dashboard. The Honey-Vault engine below (`server/vault.js`) is the design for a bank that adopts EMCON; it runs only in test mode, because EMCON is not a bank.

| Loophole | Fix |
|---|---|
| Scammers tell victims to hurry. | The brake can't be skipped for 5 minutes, and a family member can be asked with one tap. |
| A flat 15-minute lock: scammers just tell victims to wait. | The delay **scales with risk** (new payee, amount, velocity, flagged website). Release also needs a **scam-script check-in**, and any *yes* escalates to guardians, who see the answers. |
| A thief with the PIN first raises limits or removes guardians. | **Loosening** any protection is time-locked (24 h) and announced to guardians, who can veto. **Tightening** applies instantly. |
| A stolen session cookie drains the account. | Every money movement needs **PIN step-up**, and wrong PINs lock out after 5 tries. |
| The duress PIN "silently redirects" funds, but the attacker sees money never arrived or the UI glitches, and could escalate violence. | The **whole session becomes a consistent decoy**: success screens, a falling balance, plausible reference numbers. The real money sits in a freeze vault, and only m-of-n guardians can release it. |
| On-chain duress is visible to anyone watching the chain. | The Solidity `GuardedVault` covers time-locks, guardians, veto and settings delays, and **deliberately leaves duress to the custodial layer** (documented in the contract). |
| A panic freeze can be undone by the thief. | Only a **guardian** can unfreeze. |
| One compromised or colluding guardian. | m-of-n approvals to release, and **any single guardian can veto**. |

### 🕸️ 4. Web of Trust
| Loophole | Fix |
|---|---|
| Sybil attestations: 10,000 fake accounts vouch for a scam shop. | Only identities **reachable from your own trust roots** count, and each root's branch has a **total budget of 1.0**. A compromised friend's sybil swarm is capped (tested with 500 sybils plus 1,000 strangers). |
| Looking up every domain leaks your browsing history to the server. | **k-anonymity**: only a 5-hex-char SHA-256 prefix leaves the browser. |
| A compromised relay could forge reputation. | The relay is a dumb mailbox. Every W3C credential is **re-verified in the browser**. |
| DOM hashing alone flags every generic login page. | A clone needs a **structure match *and*** a brand mention or credential form, on a domain that **isn't official**. Unrelated pages land 29–32 bits away, clones under 12. |
| Attackers shuffle the DOM to dodge the hash. | Several independent signals add up: domain age (RDAP), cross-domain password forms, raw-IP logins, HTTP-only password forms, and community reports. |
| SPA phishing kits inject the form after load. | A MutationObserver **re-analyses** when a password field appears. |
| Griefing: false "scam" reports against a competitor. | Same trust-path rules apply, and the popup shows each piece of evidence with its weight. |

### 5. Scam chain detector
| Loophole | Fix |
|---|---|
| Judging only the final URL misses that the victim was walked there by a lure and a redirect maze. | Every tab keeps its path: link clicks, server redirects (`webRequest.onBeforeRedirect`), page redirects, link shorteners, tabs opened from other tabs. The warning names each stage and quotes the exact wording found. |
| "We read your messages to find scams" is a privacy disaster. | EMCON never reads messages. You can paste one into the popup; it's stored only in this browser and checked against the chain (does its link lead into this path?). |
| Checkouts also redirect and ask for card numbers, so a naive chain rule cries wolf. | A chain needs **all** stages: strong lure wording (prize, threat, fee; urgency alone doesn't count) + card/OTP/password fields + page-level evidence such as a look-alike address, a brand name on an unofficial site, a scam report or a brand-new domain. |
| Scammers plant kits on hacked but reputable sites. | A site's good reputation never cancels scam evidence found on the page itself; the vouch is shown as *not counted*. |

### 6. Privacy promise monitor
| Loophole | Fix |
|---|---|
| "We respect your privacy" can't be checked. | Promises are machine-readable (`<meta name="privacy-promise" content="no-third-party-tracking respects-consent">`), and every site is also held to the legal baseline (tracking stops after you say no, under GDPR and India's DPDP Act). Each result cites the domains and features your browser actually observed. |
| Fingerprinting scripts look innocent in the network log. | A page-side monitor shares the anti-fingerprinting wrappers (so it passes `toString()` checks) and counts canvas readback, GPU queries, audio probing, font probing, location, camera, clipboard and beacons, per frame. |
| Outside Europe most sites never show a cookie banner, so there is no "no" to test. | EMCON sends **Global Privacy Control** with every request (`Sec-GPC: 1` via declarativeNetRequest) and to page scripts (`navigator.globalPrivacyControl`), then reports every tracking domain that still loads. The row says where GPC is a legal opt-out (California, Colorado and other US states) and that elsewhere it is a request. |
| Did the user actually say no? | Clicking a banner's "Reject all" / "Decline" / "Only necessary" is recorded automatically, including inside consent-manager iframes, or you press **I said no to tracking here** in the popup. Everything after that moment is counted separately. |

### 7. Evidence receipts
| Loophole | Fix |
|---|---|
| A risk percentage explains nothing and can't be challenged. | Every check is a row: **found**, **clear**, **unknown** (couldn't check, e.g. registry down) or **not applicable**, with its exact points. The score is just their sum. |
| A screenshot of a warning can be faked. | The receipt is a W3C Verifiable Credential signed by your EMCON did:key; changing one character breaks it. |
| "When did you see this?" | The EMCON server countersigns a SHA-256 digest of the receipt with its own key and clock. It never sees the contents. |
| Overclaiming. | The receipt states what EMCON observed and when. It does not claim a site *is* a scam. |

**Cross-shield synergy:** the vault's risk engine queries the Web of Trust, so paying a payee whose website a trusted security group flagged sends the payment straight to guardians.

---

## Architecture

```
extension/  (Chrome MV3, no build step)
  background.js     service worker: holds every secret, makes every decision, builds receipts
  watch.js          per-tab observers: redirect chain + third-party requests and consent
  content/bridge.js page facts → worker; renders labels / warnings in a closed shadow DOM (every frame)
  content/guard.js  anti-fingerprinting + privacy feature monitor + GPC, MAIN world at document_start;
                    content/cfg/*.js switch its parts on (registered by the worker from your settings)
  lib/              shared code, also imported by the server and the demo pages
    signals.js      lure phrases, link shorteners, sensitive form fields
    icons.js        line icons + the one-meaning-per-status table (icon, colour, plain word)
    trackers.js     known tracking domains
    receipt.js      receipt digest + verification (signature and timestamp)
    domains.js      registrable-domain helpers
    blindrsa.js     RSA-FDH blind signatures (BigInt, CRT)
    provenance.js   PNG/JPEG manifest embed/extract, pixel hash, verification
    c2pa.js         Content Credentials validation: JUMBF, CBOR, COSE, X.509 chains
    vc.js           W3C VC 2.0 + Data Integrity eddsa-jcs-2022
    trustgraph.js   personal trust propagation with per-root Sybil budgets
    simhash.js      DOM-structure SimHash
    dhash.js        perceptual hash
  pages/            popup, receipt, welcome (first install), Ghost setup, sign-in consent window;
                    pages.css + ui.js: the shared design system (see docs/ui-research.md)
  icons/            toolbar + store icons

server/  (Node 22+; dependencies: pg for Postgres, jpeg-js to fingerprint photos)
  link.js    "Check a link": follows redirects server-side (SSRF guard, timeouts, rate limit)
  issuer.js  blind-token issuer        rp.js     "ShopNorth" relying party
  prov.js    publisher signing, C2PA trust lists, soft-binding registry
  imagehash.js  the extension's photo fingerprint, computed from the file
  accounts.js   SaaS accounts, family, approvals, API keys, plans
  ratings.js    community ratings      rp.js, vault.js: test mode only (sample site, bank engine)
  wot.js     attestation relay + brand fingerprints + live phishing feed
  timestamp.js  receipt timestamps (signs digest + time, never sees contents)

web/        SaaS product pages (landing page, dashboard, login/signup, password recovery, real-internet guide, receipt verifier, legal)
contracts/  GuardedVault.sol, the on-chain time-lock / guardian vault
test/       e2e.mjs (67 API tests) · extension.mjs (32 real-browser tests) · production.mjs (the deployed server) ·
            real-internet.mjs (live websites) · fixtures/ (real C2PA sample from c2pa-rs) · site/ (test-only pages)
tools/      browser.mjs: launches Chrome/Edge with the extension loaded via the DevTools protocol
            pack.mjs: builds dist/emcon-extension-v<version>.zip · make-icons.mjs: renders the icons
            real-screens.mjs: product screenshots, taken on real websites
```

## Honest limitations (say these before a judge does)

- **Not audited.** This is hackathon code. `GuardedVault.sol` has not been compiled in CI or audited.
- **Blind RSA vs zk-SNARKs:** blind signatures give unlinkability and simple, fast verification. Selective disclosure of arbitrary attributes (e.g. "lives in EU") would need BBS+ or zk circuits (Circom). That's the roadmap.
- **The Ghost issuer** checks only a date of birth. Production plugs in real KYC, a bank, or a government eID.
- **Anti-fingerprinting runs as an extension.** It starts before page scripts, but Web Workers (an `OffscreenCanvas` in a worker) aren't covered, nor is a same-origin frame reached through `window[0]` before anything touches its `.contentWindow`. Determined scripts can spot that values are noised (they can't undo it). Brave-grade protection lives in the browser engine; in Brave, its own randomisation already applies.
- **GPC is a request, not a block.** It is legally binding in California, Colorado and several other US states. Elsewhere a site may ignore it, and the privacy report shows exactly that. A tracker loading isn't proof that data was sold; the report lists what loaded, not what happened to the data.
- **Check a link fetches the link from the EMCON server**, so the scam site sees the server's address, not yours. Sites that only show their scam to phones or to certain countries may look harmless to the server.
- **The WebAuthn gate is a local user-presence check.** Encrypting the master secret with the passkey's PRF output is next on the roadmap.
- **Content Credentials:** EMCON validates the active manifest (signature, assertions, data hash, certificate chain to the trust anchors). It doesn't yet check ingredient manifests, OCSP revocation, or box/BMFF hashes (those files show *Content Credentials* without a verdict), and it reads the signing time from the timestamp token without verifying the timestamp authority's own signature. Publisher signing uses EMCON's compact manifest format, not C2PA.
- **Registrable-domain logic** uses a small built-in suffix list rather than the full Public Suffix List.
- **Render's free web service sleeps when idle.** With `DATABASE_URL` configured (free Render Postgres), all accounts, family devices, approvals and ratings survive restarts and redeploys. On cold start after sleeping, the free instance takes about 50 s to spin up.
- **Scam wording lists are English-only for now** (prize, threat, fee, urgency phrases). Hindi and other languages are the obvious next step.
- **The privacy monitor sees requests and API calls, not data contents.** A hostile page could also block the page-side feature events (not the network log). The network observations come from the browser itself and can't be hidden by the page.
- **The OpenPhish community feed** is free for non-commercial use. Commercial deployments need their premium feed or another source (`EMCON_FEED_URL`).
