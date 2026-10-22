# 🛡️ EMCON — Four Shields, Zero AI Guesswork

**One browser extension + one tiny server that protect people from tracking, fake media, payment scams and phishing using cryptography and deterministic checks instead of probabilistic AI detectors.**

AI detectors fail in two directions: they flag real content, and attackers learn to slip past them. EMCON asks questions that have provable answers:

| Shield | Instead of asking… | EMCON asks… | Built on |
|---|---|---|---|
| 👻 **Ghost Engine** | "Who is this user?" | "Can they *prove* they're a verified adult, without revealing who they are?" | RSA blind signatures (RFC 9474-style), per-site Ed25519 keys, WebAuthn |
| 🖼️ **Provenance** | "Is this image AI-generated?" | "Who signed it, and has it changed since?" | Ed25519 manifests in PNG/JPEG (C2PA-lite), perceptual-hash soft binding |
| 🏦 **Honey-Vault** | "Does this payment look fraudulent?" | "Has it waited out a risk-scaled delay and passed check-ins and guardians?" | Time-locks, m-of-n guardians, duress decoy, Solidity contract |
| 🕸️ **Web of Trust** | "Does an algorithm think this site is safe?" | "Has anyone *I* trust safely used it? Is it a structural clone of a brand?" | W3C VC 2.0 + `eddsa-jcs-2022`, did:key, SimHash, RDAP |

---

## Quick start (2 minutes)

Requires **Node 22+** (no `npm install`, zero dependencies) and **Chrome/Edge 137+**.

```bash
npm start
```

1. Open **http://localhost:8787**. That's the demo hub.
2. `chrome://extensions` → enable **Developer mode** → **Load unpacked** → pick the `extension/` folder.
3. Click the 🛡️ toolbar icon → **Ghost** → **Set up Ghost** (passkey, or a PIN as fallback).

Run the test suite (34 end-to-end tests against the real server):

```bash
npm test
```

## 5-minute judge demo

1. **Ghost sign-in.** Open `localhost:8787/rp.html` → *Continue with EMCON Ghost* → approve. ShopNorth creates an 18+ account knowing **no email, name or phone**. Then open `127.0.0.1:8787/rp.html` (playing a *different company*) and sign in again: you get a **different, unlinkable pseudonym**.
2. **Fake media.** Open `/sign.html` → *Generate a sample photo* → *Build the full demo feed* → open `/feed.html`. Badges: ✔ verified original, ✖ doctored copy carrying the *real* signature, ↺ provenance recovered from a stripped re-upload, ? self-signed. The unsigned photo gets **no** badge.
3. **Phishing clone.** Open `127.0.0.1:8787/phish-login.html` and EMCON puts up a full-page block. Its reasons: structural match to Kestrel Bank's login (clone distance 0/64) on a non-official domain, a credential form on a raw IP, and a scam report from a security group in your web of trust. The real `localhost:8787/bank-login.html` stays clean.
4. **Pig-butchering payment.** On `/vault.html` log in with PIN `1234`. Send $2,500 to *CryptoYield Pro*: it's held for guardians, because the payee is new **and** its website is flagged in the web of trust. Open a guardian console from *Demo controls* and veto it. The money comes back.
5. **Scam-script check-in.** Send $800 to the landlord → cooling-off. Answer **Yes** to "were you told to keep it secret?" and the payment escalates to guardians, who see your answers.
6. **Duress.** Log out and log in with PIN `9999`. Send money: it *looks* successful and the balance drops. Log in again with `1234` (or open a guardian console): the money is in the freeze vault and guardians got a 🚨 alert. Two guardians close the episode and the money returns.
7. **Thief disables protections first.** In settings, try raising the instant limit. It's **time-locked for 24 h** and guardians are notified. Lowering it applies instantly.

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

**Cross-shield synergy:** the vault's risk engine queries the Web of Trust, so paying a payee whose website a trusted security group flagged sends the payment straight to guardians.

---

## Architecture

```
extension/  (Chrome MV3, no build step)
  background.js     service worker: holds every secret, makes every decision
  content/bridge.js page facts → worker; renders badges / warnings in a closed shadow DOM
  lib/              shared crypto, also imported by the server and the demo pages
    blindrsa.js     RSA-FDH blind signatures (BigInt, CRT)
    provenance.js   PNG/JPEG manifest embed/extract, pixel hash, verification
    vc.js           W3C VC 2.0 + Data Integrity eddsa-jcs-2022
    trustgraph.js   personal trust propagation with per-root Sybil budgets
    simhash.js      DOM-structure SimHash
    dhash.js        perceptual hash
    farble.js       anti-fingerprinting (MAIN world)
  pages/            popup, Ghost setup, sign-in consent window

server/  (Node 22+, zero dependencies)
  issuer.js  blind-token issuer        rp.js     "ShopNorth" relying party
  prov.js    signing + soft-binding    vault.js  Kestrel Bank Honey-Vault engine
  wot.js     attestation relay + brand fingerprints

web/        demo pages (hub, ShopNorth, Provenance Studio, feed, vault, guardian, bank login, phishing clone)
contracts/  GuardedVault.sol, the on-chain time-lock / guardian vault
test/       e2e.mjs, 34 tests against the live server
```

Optional: set `EMCON_ALERT_WEBHOOK=https://ntfy.sh/<topic>` to push guardian alerts to phones.

## Honest limitations (say these before a judge does)

- **Not audited.** This is hackathon code. `GuardedVault.sol` has not been compiled in CI or audited.
- **Blind RSA vs zk-SNARKs:** blind signatures give unlinkability and simple, fast verification. Selective disclosure of arbitrary attributes (e.g. "lives in EU") would need BBS+ or zk circuits (Circom). That's the roadmap.
- **Demo issuer** checks only a date of birth. Production plugs in real KYC, a bank, or a government eID.
- **Anti-fingerprinting runs as an extension**, injected at navigation commit. A page script that runs extremely early could, in rare cases, read values before the wrappers are in place. Brave-grade protection needs to live in the browser engine. Web Workers aren't covered yet.
- **The WebAuthn gate is a local user-presence check.** Encrypting the master secret with the passkey's PRF output is next on the roadmap.
- **"C2PA-lite"** uses its own manifest format. It detects real C2PA but doesn't fully validate it (that needs the c2pa-rs SDK).
- **Registrable-domain logic** uses a small built-in suffix list rather than the full Public Suffix List.
- Stores data in a single JSON file (`data/db.json`). Swap in SQLite/Postgres for real use.
