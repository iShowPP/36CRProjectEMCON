# EMCON: evidence, not guesses

**One browser extension + one tiny server that protect people from phishing, scam chains, fake media, broken privacy promises, payment scams and tracking, using cryptography and deterministic checks instead of probabilistic AI detectors. Every conclusion comes with the evidence behind it, and you can export that evidence as a signed receipt.**

**Live demo: https://emcon-e2tu.onrender.com** (free hosting, so the first visit after a quiet spell takes ~50 s to wake up)

AI detectors fail in two directions: they flag real content, and attackers learn to slip past them. EMCON asks questions that have provable answers:

| Protection | Instead of asking… | EMCON asks… | Built on |
|---|---|---|---|
| **Phishing & look-alikes** | "Does an algorithm think this site is safe?" | "Has anyone *I* trust reported it? Is it a clone or a look-alike of a brand? How old is the domain?" | W3C VC 2.0 + `eddsa-jcs-2022`, did:key, SimHash, RDAP, OpenPhish feed |
| **Scam chain detector** | "Is this one URL bad?" | "Did prize or threat wording, redirects and an unofficial site all lead to a form asking for my card and OTP?" | `webNavigation` + `webRequest` redirect tracking, quoted lure phrases, sensitive-field detection |
| **Privacy promise monitor** | "Does the privacy policy sound nice?" | "Which third parties did the page actually contact, and did tracking stop after I said no?" | Per-tab request log, page-side feature monitor, `<meta name="privacy-promise">`, legal baseline |
| **Evidence receipts** | "Trust our 82% risk score." | "Here is every check: found, clear, unknown or not applicable. Signed and timestamped." | VC signed by your did:key + server timestamp over the digest |
| **Provenance** | "Is this image AI-generated?" | "Who signed it, and has it changed since?" | Ed25519 manifests in PNG/JPEG (C2PA-lite), perceptual-hash soft binding |
| **Ghost sign-in** | "Who is this user?" | "Can they *prove* they're a verified adult, without revealing who they are?" | RSA blind signatures (RFC 9474-style), per-site Ed25519 keys, WebAuthn |
| **Honey-Vault** | "Does this payment look fraudulent?" | "Has it waited out a risk-scaled delay and passed check-ins and guardians?" | Time-locks, m-of-n guardians, duress decoy, Solidity contract |
| **Anti-fingerprinting** | (nothing) | "Can a tracker recognise this device on the next site?" | Deterministic per-site noise, bucketed hardware values |

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

EMCON protects the whole web, not just the demo pages:

| On real sites | How |
|---|---|
| **Live phishing sites are blocked** | The server imports the [OpenPhish](https://openphish.com) community feed every 6 hours (≈250–300 live phishing sites) and signs each entry as an attestation. The extension follows the feed by default (you can remove it like any other source). Shared hosts such as `sites.google.com` and brands' own domains are never flagged. |
| **Look-alike addresses are flagged** | `paypa1-secure.com`, `micros0ft-login.net`, `hdfcbank-kyc.top`: the hostname borrows a real brand (PayPal, Google, Microsoft, Apple, Amazon, Meta, SBI, HDFC, ICICI, Axis, Paytm and more), with digit-for-letter swaps and one-letter typos undone, without being that brand's official domain. RBI's verified `.bank.in` zone counts as official for Indian banks. |
| **Brand-new domains** | Registration dates come from the public RDAP registry. |
| **Anti-fingerprinting** | Works everywhere. Try [browserleaks.com/canvas](https://browserleaks.com/canvas). |
| **Real Content Credentials** | Photos carrying C2PA manifests get an ⓘ badge on any site. |

Checked against real sites (Google, GitHub, Amazon, Wikipedia, Hacker News, SBI): none of them triggers a warning.

## Host the server

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/iShowPP/36CRProjectEMCON)

1. Click the button, sign in to Render (free), and click **Apply**. `render.yaml` sets everything up, including a generated `EMCON_SECRET`.
2. After about a minute you have `https://emcon-xxxx.onrender.com`. Open it: that's the hosted demo hub.
3. Build the zip for users with your address baked in:
   ```bash
   npm run pack -- --server=https://emcon-xxxx.onrender.com
   ```
4. Attach `dist/emcon-extension-v1.0.0.zip` to a GitHub Release so people can download it.

Anywhere else: `docker build -t emcon . && docker run -p 8787:8787 -e EMCON_SECRET=<random> -e EMCON_PUBLIC_URL=https://your.host emcon`.

| Variable | Meaning |
|---|---|
| `EMCON_SECRET` | All server keys are derived from it. Keep it fixed and the keys survive restarts, even on hosts that wipe the disk. |
| `EMCON_PUBLIC_URL` | Public https address (auto-detected on Render). |
| `EMCON_ALT_URL` | Optional second hostname for the same server. It enables the "different company" and Kestrel-clone demos when hosted. |
| `EMCON_FEED=off` / `EMCON_FEED_URL` | Disable or replace the live phishing feed. |
| `EMCON_ALERT_WEBHOOK` | e.g. `https://ntfy.sh/<topic>` to push guardian alerts to phones. |
| `EMCON_DATA`, `PORT` | Data folder and port. |

## Quick start for the demo (one command)

Requires **Node 22+** (no `npm install`, zero dependencies) and **Chrome, Edge or Brave**.

```bash
npm run demo
```

On Windows you can also just double-click **`start-demo.cmd`**.

This starts the server on `:8787` and opens a browser window with the EMCON extension **already loaded**, in its own profile (`data/browser-profile`), so your normal browser is never touched. It also sets up Ghost with demo PIN **2468**, so every flow works straight away. Close the window (or press Ctrl+C) to stop.

- Pick the browser: `npm run demo -- --browser=brave` (or `edge` / `chrome`), or `start-demo.cmd --browser=brave`. Each browser gets its own demo profile.
- `npm run demo:fresh` starts from a clean profile so you can show the Ghost setup (passkey/PIN) yourself.
- `npm start` runs only the server. Then load the extension by hand: `chrome://extensions` → **Developer mode** → **Load unpacked** → pick `extension/`.

| PIN | Where |
|---|---|
| `2468` | Ghost sign-in consent window |
| `1234` | Kestrel Bank vault (real) |
| `9999` | Kestrel Bank vault (duress) |

### Tests

```bash
npm test               # 41 API tests against the live server
npm run test:browser   # 22 tests that load the real extension into headless Chrome: install flow, every protection, scam chain, privacy promises, receipts
npm run test:all       # both
```

Set `HEADED=1` to watch the browser test, or `EMCON_BROWSER=<path to browser exe>` to pick a browser.

## 5-minute judge demo

1. **Ghost sign-in.** Open `localhost:8787/rp.html` → *Continue with EMCON Ghost* → approve. ShopNorth creates an 18+ account knowing **no email, name or phone**. Then open `127.0.0.1:8787/rp.html` (playing a *different company*) and sign in again: you get a **different, unlinkable pseudonym**.
2. **Fake media.** Open `/sign.html` → *Generate a sample photo* → *Build the full demo feed* → open `/feed.html`. Labels: *Verified* original, *Altered after signing* on the doctored copy that carries the real signature, *Recovered* for the stripped re-upload, *Signed · unknown signer*. The unsigned photo gets **no** label. Click a label → *Export evidence receipt*.
3. **Phishing clone.** Open `127.0.0.1:8787/phish-login.html` and EMCON puts up a full-page block. Its reasons: structural match to Kestrel Bank's login (clone distance 0/64) on a non-official domain, a credential form on a raw IP, and a scam report from a security group in your web of trust. The real `localhost:8787/bank-login.html` stays clean.
4. **Pig-butchering payment.** On `/vault.html` log in with PIN `1234`. Send $2,500 to *CryptoYield Pro*: it's held for guardians, because the payee is new **and** its website is flagged in the web of trust. Open a guardian console from *Demo controls* and veto it. The money comes back.
5. **Scam-script check-in.** Send $800 to the landlord → cooling-off. Answer **Yes** to "were you told to keep it secret?" and the payment escalates to guardians, who see your answers.
6. **Duress.** Log out and log in with PIN `9999`. Send money: it *looks* successful and the balance drops. Log in again with `1234` (or open a guardian console): the money is in the freeze vault and guardians got a duress alert. Two guardians close the episode and the money returns.
7. **Thief disables protections first.** In settings, try raising the instant limit. It's **time-locked for 24 h** and guardians are notified. Lowering it applies instantly.
8. **Scam chain.** Open `/sms.html` and tap the link in the "prize" SMS. It redirects twice (`/s/qk50` → `/r`) to a QuickKart "claim" page asking for card number, CVV and OTP. EMCON blocks it, and the block page lists every stage: prize wording → 2 redirects → QuickKart's name on an unofficial site → card and OTP fields, plus the exact path.
9. **Privacy promise.** Open `/news.html`. The page declares *no third-party tracking* and *respects consent*. Click **Reject all**, then the EMCON icon → **Privacy**: both promises are **broken**, with the tracker domain contacted after you said no and the canvas fingerprinting that followed.
10. **Evidence receipt.** On the blocked claim page, click the EMCON icon → **Export signed receipt**. Download it, open `/verify.html` and drop the file in: *signature valid, timestamped by this server*. Change one character and verify again: *altered or forged*.

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
| "Randomise screen size / locale" breaks sites, gets caught by CSS media queries and `Intl`, and random-per-read noise is *itself* a fingerprint. | Noise is a **pure function of a secret seed and the pixel index**, so it's stable within a site and different across sites (and per top-site/iframe pair, which defeats third-party tracker iframes). High-entropy values are **bucketed to the most common value**. Screen, locale and timezone are never faked. Wrappers pass `toString()` checks. |

### 🖼️ 2. Provenance
| Loophole | Fix |
|---|---|
| Twitter/Reddit/WhatsApp **strip metadata**, so the signature is gone. | **Soft binding**: a 64-bit perceptual hash goes into a registry at signing time. Stripped copies show *"↺ Provenance recovered"* and link to the original so the viewer can compare. |
| 🔴 "Unverified = synthetic" is false. Most real photos are unsigned, so this would smear real content. | Unsigned images get **no badge**. EMCON only shows positive evidence or tampering. |
| Copy a real manifest onto an edited image. | The signature covers a hash of the **pixel-defining bytes** (PNG critical chunks / JPEG non-APPn segments), so pixel edits show as **✖ Altered**. |
| Anyone can sign anything. | Only keys on the **trust list** earn ✔ Verified. Others show "Signed, unknown signer". A manifest claiming a trusted keyId is checked against the trust-list key, never the key it carries. |
| Perceptual-hash collisions could borrow legitimacy. | A recovered match is labelled as *evidence, not proof*, with a link to the original image so people can compare it with their own eyes. |
| Real C2PA files exist in the wild. | C2PA (JUMBF) manifests are **detected** and the badge links to a full C2PA validator. |

### 🏦 3. Honey-Vault
| Loophole | Fix |
|---|---|
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
| Did the user actually say no? | Clicking a banner's "Reject all" / "Decline" / "Only necessary" is recorded automatically, including inside consent-manager iframes, or you press **I said no** in the popup. Everything after that moment is counted separately. |

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
  lib/              shared code, also imported by the server and the demo pages
    signals.js      lure phrases, link shorteners, sensitive form fields
    trackers.js     known tracking domains
    receipt.js      receipt digest + verification (signature and timestamp)
    domains.js      registrable-domain helpers
    blindrsa.js     RSA-FDH blind signatures (BigInt, CRT)
    provenance.js   PNG/JPEG manifest embed/extract, pixel hash, verification
    vc.js           W3C VC 2.0 + Data Integrity eddsa-jcs-2022
    trustgraph.js   personal trust propagation with per-root Sybil budgets
    simhash.js      DOM-structure SimHash
    dhash.js        perceptual hash
    farble.js       anti-fingerprinting + privacy feature monitor (MAIN world)
  pages/            popup, receipt, welcome (first install), Ghost setup, sign-in consent window
  icons/            toolbar + store icons

server/  (Node 22+, zero dependencies)
  issuer.js  blind-token issuer        rp.js     "ShopNorth" relying party
  prov.js    signing + soft-binding    vault.js  Kestrel Bank Honey-Vault engine
  wot.js     attestation relay + brand fingerprints + live phishing feed
  timestamp.js  receipt timestamps (signs digest + time, never sees contents)

web/        demo pages (overview, ShopNorth, Provenance Studio, feed, vault, guardian, bank login, phishing clone,
            prize SMS + claim page, newspaper, receipt verifier)
contracts/  GuardedVault.sol, the on-chain time-lock / guardian vault
test/       e2e.mjs (41 API tests) · extension.mjs (22 real-browser tests)
tools/      browser.mjs: launches Chrome/Edge with the extension loaded via the DevTools protocol
            pack.mjs: builds dist/emcon-extension-v<version>.zip · make-icons.mjs: renders the icons
scripts/    demo.mjs: the one-command demo launcher (npm run demo / start-demo.cmd)
```

## Honest limitations (say these before a judge does)

- **Not audited.** This is hackathon code. `GuardedVault.sol` has not been compiled in CI or audited.
- **Blind RSA vs zk-SNARKs:** blind signatures give unlinkability and simple, fast verification. Selective disclosure of arbitrary attributes (e.g. "lives in EU") would need BBS+ or zk circuits (Circom). That's the roadmap.
- **Demo issuer** checks only a date of birth. Production plugs in real KYC, a bank, or a government eID.
- **Anti-fingerprinting runs as an extension**, injected at navigation commit. A page script that runs extremely early could, in rare cases, read values before the wrappers are in place. Brave-grade protection needs to live in the browser engine. Web Workers aren't covered yet.
- **The WebAuthn gate is a local user-presence check.** Encrypting the master secret with the passkey's PRF output is next on the roadmap.
- **"C2PA-lite"** uses its own manifest format. It detects real C2PA but doesn't fully validate it (that needs the c2pa-rs SDK).
- **Registrable-domain logic** uses a small built-in suffix list rather than the full Public Suffix List.
- Stores data in a single JSON file (`data/db.json`). Swap in SQLite/Postgres for real use.
- **Render's free plan sleeps when idle and wipes its disk.** Keys survive (they come from `EMCON_SECRET`), but demo data such as shop accounts, user reports and signed photos resets. Add a persistent disk (paid) or Postgres to keep it. The first request after sleeping takes about 50 s.
- **Scam wording lists are English-only for now** (prize, threat, fee, urgency phrases). Hindi and other languages are the obvious next step.
- **The privacy monitor sees requests and API calls, not data contents.** A hostile page could also block the page-side feature events (not the network log). The network observations come from the browser itself and can't be hidden by the page.
- **Ghost needs websites to adopt it.** Only the demo shop accepts EMCON sign-in today. Phishing, look-alike, fingerprinting and provenance protection work on every site.
- **The OpenPhish community feed** is free for non-commercial use. Commercial deployments need their premium feed or another source (`EMCON_FEED_URL`).
