# EMCON UI research: what the top consumer-safety products do, and what we take

Studied 2026-10-23 from each vendor's own Chrome Web Store screenshots and product pages
(Malwarebytes Browser Guard, Ghostery, Bitdefender Web Sage / Scamio, DuckDuckGo, Guardio,
Norton 360 / Genie), plus the two warning screens our users already know: Chrome's Safe
Browsing page and Truecaller's spam screen.

## Who we design for

- **The person a scammer targets**: often a parent or first-time online banker, in India,
  on a laptop but with phone-app habits (UPI apps, WhatsApp, order tracking). English may be
  a second language.
- **Their state of mind**: the scammer has made them hurried and anxious ("account will be
  blocked today"). Our screen has to be the calm, certain voice in the room.
- **What they need from a glance**: *Is this OK? What should I do?* Everything else is for
  later, or for the family member they forward it to.
- **What earns their trust**: being told *why*, in words they'd use, with proof they can show
  someone. Truecaller's "reported by 2,341 people" works for this reason.

## The five products, side by side

| | Malwarebytes Browser Guard | Ghostery | Bitdefender Web Sage / Scamio | DuckDuckGo | Norton 360 / Genie |
|---|---|---|---|---|---|
| **First thing you see** | Big shield + one word: *Protected* | The site name, then one big number (26) in a ring | "Checking https://…" then a list of checks performed | One sentence: "We blocked Google, Amazon and 4 others…" | *You are protected* + one yellow button |
| **Danger screen** | Centred card, red-tinted box, big blue *Go back*, outline *Continue* | n/a (blocks silently) | Calm white page, small text, *Show details* | n/a | Full-screen block |
| **How it explains** | "Our recommendation: **Use caution**" + one line; then a long AI essay | Categories with counts (Advertising 3, Analytics 6) | "Be careful here. Avoid entering personal info, passwords or payment details" (plain advice) | Names the companies; rows with ✓ and › to drill down | Chat answers ("Do not share your one-time password") |
| **Navigation** | Segmented control + 2-icon bottom bar | Header menu, list/ring toggle | Single scroll | Single scroll with drill-down rows | App tabs |
| **Type** | Geometric sans, 14–16 px body, bold 24 px status | Inter-like, 13–14 px, 26 px numbers | IBM Plex Sans + Plex Mono for URLs and checks | Rounded sans, big friendly headings | Bold sans, yellow CTAs |
| **Colour** | Blue brand, green/amber/red status only | Light blue tints, category colours | Dark marketing, white product UI, tinted status cards | Blue + duck orange | Yellow + black |
| **Weak spot** | AI analysis is a wall of text; upsell block on the danger page | Numbers without meaning ("26" what?) | Danger page text is tiny; "AI advisor" can't show proof | No scam protection | Verdicts are AI black boxes |

Also noted: Chrome's Safe Browsing page (full red, *Back to safety* is the only big button,
"proceed" hidden under *Details*): the most-seen warning in the world, so its shape is already
learned. Guardio's tinted pills (HARMFUL, DISABLED) read at a glance. Scamio and Truecaller
meet Indian users where they are: chat bubbles and red/green caller screens.

## What every winner does (and EMCON didn't)

1. **One status, said three ways**: icon + colour + a plain word. Never colour alone.
   *Before: a 10.5 px mono label "VERDICT · RISK 0/100" over a serif headline.*
2. **One obvious next action** per screen (*Go back*, *Back to safety*, *Run Smart Scan*).
   *Before: three equal buttons under every verdict.*
3. **Plain advice before evidence.** Bitdefender: "Avoid entering personal info, passwords or
   payment details." *Before: 9 evidence rows, technical wording first.*
4. **Progressive disclosure**: the "why" is one tap away, not in your face. *Before: every row
   always open.*
5. **Big numbers with a meaning attached**: "45 tracking companies", not "45".
6. **App-style navigation**: a bottom bar with icons, 3–4 destinations. *Before: six text tabs
   squeezed into 410 px.*
7. **Readable sizes**: 14–16 px body, nothing under 12 px, 40 px+ buttons. *Before: 10–10.5 px
   uppercase mono labels, 12 px secondary text.*
8. **Reassurance over time** (DuckDuckGo: "20,241 tracking attempts blocked, past 7 days").
   *Before: nothing told you what EMCON had done for you.*

## Where EMCON should beat them

- **Evidence, translated.** Keep our USP (every check, signed) but lead with the sentence a
  person would say, and show the proof as tinted pills (*Warning · OK · Couldn't check*).
- **The path, drawn like order tracking.** Indian users read Flipkart/Amazon tracking steppers
  every week: SMS → short link → redirect → this page.
- **Messages shown like WhatsApp**, with the scam phrases highlighted in place.
- **Name the companies** (DuckDuckGo) and **who reported it** (Truecaller).
- **A danger page as familiar as Chrome's**: full red, *Back to safety*, continue as a small link.
- **No upsell, no AI essay, no gradients or glow.** Calm surfaces, colour only for status.

## Design rules we adopted

| Token | Value | Why |
|---|---|---|
| Font | System UI (Segoe UI / SF / Roboto / Noto Sans) | Native, fast, covers Indic scripts later, and no third-party font requests from a privacy product |
| Sizes (popup) | Status 22/28 bold · titles 16 · body 14 · small 13 · min 12 | Older eyes; Malwarebytes/Norton range |
| Sizes (pages) | H1 34–40 · body 16 | |
| Colour | Ink #101828 on white/#F4F6FA; action blue #1D4ED8; safe #067647, caution #B54708, danger #B42318, each with a pale tint | Status colours mean one thing only; tints carry hierarchy without gradients |
| Shape | 12 px cards, 10 px buttons, full pills | Matches every app our users already use |
| Icons | 2 px line icons, status icon in a 48 px tinted circle | Malwarebytes/Ghostery pattern |
| Status words | Warning, Couldn't check, Good sign, OK, Info, Not needed, Kept, Broken, Not tested yet | No jargon in the pill |
| Navigation | Bottom bar: This site · Check a link · Privacy · More | Phone-app habit; 4 destinations max |
