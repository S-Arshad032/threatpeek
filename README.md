# ThreatPeek

**Paste a suspicious email, SMS or link. Get a 0–100 risk estimate, red-flag cards that explain why, and a haunted ghost that reacts: Pookie (low risk), Skeptical (medium) or Poltergeist (high).**

Built for Kiroween 2026. The spooky look serves a purpose: the ghost is the warning signal.

## Live demo

**https://threatpeek-7pw7.onrender.com**

It runs on a free host that goes to sleep when nobody uses it. The first visit can take up to a minute to load.

## How it works

ThreatPeek checks a message in three layers. Only the first one is needed. The app works fully with the rules engine alone.

| Layer | What it does | Where it runs | Default |
|---|---|---|---|
| **1. Rules engine** | Checks 20 warning signals in English text and gives a score with an explanation for each signal found | In your browser | Always on |
| **2. Google Safe Browsing** | Follows shortened or redirecting links, then asks Google if a link is on its list of known bad sites | Through our server | Off unless a key is set |
| **3. AI second opinion** | Asks an AI model (through OpenRouter) to rate the message | Through our server | Off |

### Layer 1: the rules engine

- Plain JavaScript with no dependencies, no network calls and no browser or Node.js APIs. The browser and the server share the same code ([backend/engine](backend/engine)).
- **Deterministic:** the same text always gives the same result.
- **Explainable:** every point of the score comes from a named signal, and each signal comes with the text that triggered it and a plain-English explanation.
- **33 signals in 4 groups** (English text only):
  - **Identity:** look-alike domains (typosquatting), disguised letters (homograph / punycode), and sender names that don't match the address.
  - **Email auth headers:** SPF, DKIM or DMARC failures, if headers are pasted.
  - **Links:** links to a bare IP address, risky domain endings, link text that points somewhere else, disguised ("defanged") links such as `evil[.]com` or `hxxps://`, and look-alike "lure" addresses stitched from official-sounding words such as `secure-login-help` or `billing-update-verify`. Disguised links are turned back into real links first, so every other link check still sees them.
  - **Content:** urgency, requests for passwords or codes, risky attachments, prize and lottery bait (including "guaranteed returns"), inheritance and advance-fee stories (including "pay a small fee to release your parcel"), requests for card or bank details, payment by gift card, crypto or money transfer, requests to keep the message secret, requests to pass on a one-time code, "I sent you money by mistake, please send it back", and requests for remote access to your device. Six scam families each need several clues in the same message: a failed-delivery notice with a link, a request for a crypto wallet's recovery phrase, guaranteed or multiplied investment returns, paid "like videos" or "rate products" task jobs, a fine or tax demand with a deadline or threat and a link, and an unsolicited recruiter sending a "brief" on an unfamiliar link. Round 2 added three more: a threat to cut off electricity, gas, water or internet over an unpaid bill with a link or "pay now", a "payment failed, update your card" message with a suspicious link or a deadline, and a strange sign-in alert that sends you to a lure address. A job or hiring message that asks for an onboarding, registration or training fee counts as an advance-fee scam, and remote data-entry work with daily pay, "no experience" and a Telegram or WhatsApp contact counts as a task job. Round 3 added one general signal: a link to an unfamiliar website (a URL shortener, a bare IP address, a risky ending, or an address like `foo-bar-baz.com` or `brand-kyc.com` stitched from hyphens and official-sounding words), written normally or disguised, together with pressure in the text: a deadline, a threat to an account, SIM or page, or a request to pay a fee, verify or claim something. A short list of well-known real domains (Google, Microsoft, LinkedIn, Facebook, Instagram, Apple, Amazon, PayPal, bKash, Nagad, Grameenphone, Robi) never counts as unfamiliar. A password, PIN or code only counts as requested when the message asks you to send, enter, share or confirm it; a notice such as "your password was changed" or "your OTP is 123456" does not. A tech-support scam is a security scare about your device or account (a virus or malware "detected", "your computer is infected", "your passwords are at risk", an error code) together with an order to call a support number or to install a remote-control app such as AnyDesk or TeamViewer; naming such an app with "install" or "open" also counts as a remote-access request.
- **Sees through simple disguises:** before the content checks, the text is normalized (Unicode, upper/lower case, hidden zero-width characters, l33t spellings like "p@ssw0rd", and s p a c e d - o u t letters). The red-flag cards still quote your original text.
- **Caps:** each group has a maximum (identity/auth 40, links 35, content 45), so one kind of signal cannot take over the score.
- **Floors:** dangerous combinations get a minimum score. For example, a look-alike domain plus a password request always scores at least 70, and so does a prize or inheritance story combined with a request for card details or gift-card payment. A request for card or bank details, or a request to pass on a one-time code, scores at least 50 on its own. A gift-card or crypto payment scores at least 40 only when it comes with pressure (urgency, secrecy, a prize or a fee) or an instruction to send it somewhere, so "Buy a gift card for your mom" stays low. The scam families have floors too: a wallet recovery-phrase request scores at least 70, a fine demand 60, an investment "guarantee" 55 (70 with pressure), a job that asks for an upfront fee 60, and a failed-delivery link, a task job, a recruiter's document link, a utility disconnection threat, a "payment failed" lure, a sign-in alert on a lure address or an unfamiliar link with pressure 50, and a tech-support scam 60. Each of these needs several clues together, so no single weak clue lifts a message above 50.
- The score maps to the ghost: 0–30 Pookie, 31–69 Skeptical, 70–100 Poltergeist.

Weights, caps, floors and word lists are all in [backend/engine/src/config.js](backend/engine/src/config.js).

### Layers 2 and 3: the optional server

The server ([backend/server](backend/server)) adds three endpoints:

| Endpoint | Purpose |
|---|---|
| `POST /api/unwrap` | Follows redirects to find a link's real destination |
| `POST /api/safebrowsing` | Checks up to 10 links with the Google Safe Browsing Lookup API v4 |
| `POST /api/analyze` | Gets the AI score |

The engine combines these results with its own score. The AI can raise or lower the score, but the result never drops below 80% of the engine's score. Every layer fails quietly. If a key is missing, a call times out or the daily AI budget is used up, the app falls back to the engine-only result. The result then says "Heuristics only. No AI check was run."

The live demo currently runs with Safe Browsing and AI both off. The current UI always sends `useAI: false`, so the AI layer is ready on the server, but users cannot turn it on yet.

## How well does it work?

We measured the rules engine alone (no AI, no Safe Browsing) on two labelled sets of messages in [backend/engine/benchmark](backend/engine/benchmark). We tuned the rules on the 60-message dev set. Then we ran the separate 40-message held-out set once, without tuning on it afterwards. Its numbers are the honest ones:

| Held-out set (20 scams, 20 normal messages) | Before tuning | After tuning |
|---|---|---|
| Scams flagged (score 31 or more) | 30% (6/20) | **65% (13/20)** |
| Scams scored high risk (70 or more) | 10% (2/20) | 15% (3/20) |
| Normal messages wrongly flagged | 5% (1/20) | **0% (0/20)** |

On the dev set the rules flag 93% of scams with no false alarms. That number is higher because the rules were tuned on it. The held-out set shows how the rules do on wording they were not tuned on. The held-out misses include both advance-fee scams, and the card-detail, job-offer and tech-support scams, all worded in ways the rules had not seen. Most scams that are caught land in Skeptical, not Poltergeist.

The numbers above were measured on 23 November 2026.

### Update, 25 November 2026: direct password and OTP requests

"Send us your password and otp" used to score 20 (Pookie). We added rules for a request to hand over a one-time code, PIN or password, and a new floor: a direct instruction to send a password scores at least 45 (Skeptical). Before changing any rule we wrote a second held-out set of 30 new messages (15 scams, mostly asking for passwords or codes, and 15 normal messages, including real one-time-code and password-reset mails). We ran it once before and once after the change, and tuned only on 10 new messages added to the dev set:

| Held-out set 2 (15 scams, 15 normal messages) | Before | After |
|---|---|---|
| Scams flagged (score 31 or more) | 27% (4/15) | **47% (7/15)** |
| Scams scored high risk (70 or more) | 7% (1/15) | 7% (1/15) |
| Normal messages wrongly flagged | 7% (1/15) | 7% (1/15) |

The first held-out set did not change (65% flagged, 15% high risk, 0% false alarms), and neither did any of its 40 scores. The dev set is now 70 messages: 94% of scams flagged, no false alarms. Held-out set 2 still misses 8 scams, among them code requests without a code word ("the 6 digit number on your screen", "a code is coming, can u text it to me"), a request sent to "all customers", and non-credential scams (romance, delivery fee, job offer). Its one false alarm is a real delivery mail that tells you to give the courier your 4-digit delivery code.

### Update, 25 November 2026: scam families and disguised links

Six reported messages scored 0 to 15: a recruiter with a "job brief" on `docs-share-view[.]com`, a VIP crypto signals group, a wallet "re-sync" asking for the 12-word recovery phrase, a traffic-fine demand, a paid video-liker job and a failed-delivery text with a `bit.ly` link. Disguised links (`[.]`, `dot`, `hxxp`) were not seen as links at all. We added link "refanging" and six scam-family signals with their own floors. The six messages now score 50, 70, 70, 60, 50 and 50. The rules were written from these six messages and their paraphrases, not from the benchmark sets. Each set was run before and after the change:

| Set | Scams flagged before | After | High risk (70+) before | After | False alarms before | After |
|---|---|---|---|---|---|---|
| dev (35 + 35) | 94% (33/35) | 94% (33/35) | 23% (8/35) | 23% (8/35) | 0% (0/35) | 0% (0/35) |
| heldout (20 + 20) | 65% (13/20) | **70% (14/20)** | 15% (3/20) | 15% (3/20) | 0% (0/20) | 0% (0/20) |
| heldout2 (15 + 15) | 47% (7/15) | **53% (8/15)** | 7% (1/15) | 7% (1/15) | 7% (1/15) | 7% (1/15) |

No false alarm was added. The newly caught held-out scams are a "like videos" job offer and a parcel held for an incomplete address. The held-out sets are no longer fully unseen: their miss lists were printed while we measured the "before" numbers. A third held-out set, [`heldout3.json`](backend/engine/benchmark/heldout3.json), has 30 messages (15 scams, 15 normal) written by a third party (Gemini) and not seen while these rules were written (it was seen later, in round 2, see below). These rules flagged 60% of its scams (9/15; 8 score 50 or more), score 2 of them 70 or more, and flag none of its normal messages. It is English-only (3 romanized-Bengali messages in the draft were replaced by English versions), and it contains a scam and a normal "send me BDT on bKash" request that read almost the same; the rules cannot separate them. See the [engine README](backend/engine/README.md#benchmark) for details.

### Update, 26 November 2026: round 2 (lure addresses, utility, payment and sign-in lures, job fees)

heldout3 caught 60% of its scams. Its misses were a utility disconnection threat, a "payment failed, update your payment method" phish, a fake sign-in alert, a remote data-entry job with a Telegram contact, a recruiter asking for an onboarding fee and a friend asking for money from a "new number". We wrote general rules for all of them except the last one, which a rule engine cannot separate from a real friend: the new signals `lookalike-lure-domain`, `utility-disconnection-threat`, `payment-failed-lure` and `account-security-lure`, a job-fee floor of 60, a remote-work path for task jobs, and the endings `.support`, `.online`, `.info`, `.site` and `.icu` on the risky list. No sentence from heldout3 is in a rule or a test. Each set was run before and after:

| Set | Scams flagged before | After | High risk (70+) before | After | False alarms before | After |
|---|---|---|---|---|---|---|
| dev (35 + 35) | 94% (33/35) | 94% (33/35) | 23% (8/35) | 23% (8/35) | 0% (0/35) | 0% (0/35) |
| heldout (20 + 20) | 70% (14/20) | 70% (14/20) | 15% (3/20) | 15% (3/20) | 0% (0/20) | 0% (0/20) |
| heldout2 (15 + 15) | 53% (8/15) | 53% (8/15) | 7% (1/15) | 7% (1/15) | 7% (1/15) | 7% (1/15) |
| heldout3 (15 + 15), **seen, used for rule tuning in round 2** | 60% (9/15) | 93% (14/15) | 13% (2/15) | 47% (7/15) | 0% (0/15) | 0% (0/15) |

No normal message in any set changed score. **heldout3 is now seen, used for rule tuning in round 2**, so its "after" numbers are optimistic and are not a held-out result. A fourth set, [`heldout4.json`](backend/engine/benchmark/heldout4.json), has 30 messages (15 scams, 15 normal) written by a third party (Gemini), with scam types none of the earlier sets had: bank e-KYC and SIM re-registration deadlines, scholarship, visa, loan and appointment fees, a rental deposit, a fake charity, a marketplace QR code, an invoice with changed bank details, a page appeal, a government grant and a verification badge. Its **first contact, before round 3**, was the only fully unseen measure of the round 2 rules, run once with no rule change. It went badly: the rules caught only the scholarship fee and the page appeal, and they wrongly flagged a real "your password was changed" bank alert. The rules knew the scam families they were written for, not scams in general.

### Round 3: fixing the heldout4 false alarm and one general gap

We made two general changes, guided by heldout4. First, `credential-request` now needs a real request: a verb such as send, enter, share, confirm, verify, reply or "read out" before the password, PIN or code in the same sentence, or "log in" used as an instruction. Notices ("your password was changed", "your OTP is 123456", "a login from a new device") no longer fire. Second, a new signal, `unfamiliar-link-pressure`, fires when a link to an unfamiliar website comes with pressure language, and sets the score to at least 50. It works the same whether the link is written normally or disguised. No sentence from heldout4 is in a rule or a test; the tests use made-up messages and check every scam both with normal dots and disguised.

| Set | Scams flagged (31+) before → after | Scored 50+ | High risk (70+) | Normal messages flagged |
|---|---|---|---|---|
| dev (35 + 35) | 94% (33/35) → 91% (32/35) | 22 → 22 | 8 → 8 | 0% → 0% |
| heldout (20 + 20) | 70% (14/20) → 75% (15/20) | 9 → 10 | 3 → 3 | 0% → 0% |
| heldout2 (15 + 15) | 53% (8/15) → 53% (8/15) | 5 → 5 | 1 → 1 | 7% (1/15) → 7% (1/15) |
| heldout3 (15 + 15), seen in round 2 | 93% (14/15) → 93% (14/15) | 13 → 13 | 7 → 9 | 0% → 0% |
| heldout4 (15 + 15), **first contact, before round 3** → **seen after round 3 (used for tuning)** | 13% (2/15) → 53% (8/15) | 2 → 8 | 0 → 3 | 7% (1/15) → 0% (0/15) |

No normal message in any set scored higher; ten scored lower (the old `credential-request` fired on notices). One dev scam got worse: a fake virus alert that only says "your banking passwords are at risk" and asks you to call a number dropped from 55 to 15, because it does not ask for the password itself. heldout4's "after" numbers are optimistic, because its misses guided this round; the 7 heldout4 scams without a link (a rental deposit, a wrong-number investor, a charity, a fake antivirus call, a marketplace QR code, an invoice with new bank details and a visa bond) were still missed.

We then added one more general signal, `tech-support-scam` (floor 60): a security scare about your device or account plus an order to call support or install a remote-control app. Real security notices ("scan completed, no threats found", "virus definitions updated", "we detected a sign-in from a new device", "never install remote access software for strangers") do not fire it. `remote-access-request` now also fires when a remote-control app is named with "install", "open" or "allow". Only two messages changed on all five sets, both fake virus alerts:

| Set | Scams flagged (31+) before → after | Scored 50+ | High risk (70+) | Normal messages flagged |
|---|---|---|---|---|
| dev (35 + 35) | 91% (32/35) → 94% (33/35) | 22 → 23 | 8 → 8 | 0% → 0% |
| heldout (20 + 20) | 75% (15/20) → 75% (15/20) | 10 → 10 | 3 → 3 | 0% → 0% |
| heldout2 (15 + 15) | 53% (8/15) → 53% (8/15) | 5 → 5 | 1 → 1 | 7% (1/15) → 7% (1/15) |
| heldout3 (15 + 15), seen in round 2 | 93% (14/15) → 93% (14/15) | 13 → 13 | 9 → 9 | 0% → 0% |
| heldout4 (15 + 15), seen after round 3 (used for tuning) | 53% (8/15) → 60% (9/15) | 8 → 9 | 3 → 3 | 0% → 0% |

The dev fake virus alert is back (15 → 60), and so is the heldout4 fake Defender alert that asks you to install AnyDesk (0 → 60). heldout4 stays marked "seen after round 3"; its first-contact result (13% flagged, 1 false alarm) is the only unseen measure it gave. The 6 heldout4 scams without a link that remain (a rental deposit, a wrong-number investor, a charity, a marketplace QR code, an invoice with new bank details and a visa bond) are still missed. **heldout4 is now seen after round 3 (used for tuning).** 

### heldout5: the only set fully unseen at the time of final tuning

[`heldout5.json`](backend/engine/benchmark/heldout5.json) has 30 messages (15 scams, 15 normal) written by a third party (Gemini) after round 3 and the tech-support signal were finished, with scam types none of the earlier sets had (a corporate SSO password expiry, a court summons, a crypto withdrawal alert, a fake-check job, a voicemail link, ticket and puppy deposits, a survey gift card...). Links are written normally, not disguised. We ran it once and changed no rule:

| Set | Scams flagged (31+) | Scored 50+ | High risk (70+) | Normal messages flagged |
|---|---|---|---|---|
| heldout5 (15 + 15), **only set fully unseen at the time of final tuning** | 40% (6/15) | 40% (6/15) | 0% (0/15) | 0% (0/15) |

Every caught scam scored exactly 50, and five of the six were caught only through `unfamiliar-link-pressure`; none reached Poltergeist. The 9 misses are a wrong-number opener with no ask yet (0), a fake Kraken "withdrawal initiated, cancel it" alert (0), a concert-ticket resale paid by Zelle (0), a fake-check job via WhatsApp (0), an "encrypted voicemail" link (0), a puppy deposit by CashApp (0), a health-relief stipend registration (25), a university admission-result link (20) and a $100 gift-card survey (0). No normal message was flagged; the highest scored 20 (a Microsoft sign-in alert and a benefits reminder that say "update your password" / "log in"). Caveat: a third-party generator tends to write hyphenated look-alike domains such as `corp-sso-auth-desk.com`, which is exactly what `unfamiliar-link-pressure` looks for, so real scams with plainer domains may do worse. This is the most honest number in this README for scam types the rules were not built for. It is small, synthetic and English-only, so it is not a guarantee.

All of these are small, synthetic, English-only test sets (dev, heldout and heldout2 written by the same author with fictional brands, heldout3, heldout4 and heldout5 by a third party). They are not a guarantee of how ThreatPeek does on real messages. Run `npm run benchmark -- --set=heldout` (or `--set=heldout2`, `--set=heldout3`, `--set=heldout4`, `--set=heldout5`, `--set=dev`) in `backend/engine` to reproduce; full results are in [RESULTS.md](backend/engine/benchmark/RESULTS.md).

## Safety and honesty

- **An estimate, never a promise.** ThreatPeek never calls a message "safe". Every result says "This is an estimate, not a guarantee."
- **No API keys in the browser.** All keys live in server environment variables. The frontend only calls our own `/api/...` paths.
- **SSRF guard on link unwrapping:**
  - Only http/https on ports 80 and 443.
  - Every address that DNS returns must be public. Private, loopback, link-local (including cloud metadata) and other reserved ranges are blocked.
  - The check runs again on every redirect, with at most 5 hops in 10 seconds.
  - A pinned DNS lookup stops rebinding tricks.
  - Only headers are read, never the page body.
- **Rate limits:**
  - 30 requests per minute per IP on the API.
  - 10 per minute on `/api/analyze`.
  - A daily AI budget (40 calls by default).
  - JSON bodies are capped at 16 kB, and text at 4000 characters.
- **Prompt-injection defense:**
  - The pasted text goes inside a `<message>` block, and any `<message>` tags in it are escaped.
  - The system prompt says the text is data to rate, not instructions.
  - The model must answer with exactly `{"score": <0-100>}`. Anything else is thrown away, and model text never reaches the user.
- **User text is shown as plain text.** No `innerHTML`, no `dangerouslySetInnerHTML`.
- **Strict security headers:** a same-origin Content-Security-Policy, no framing, and HSTS in production.
- **Privacy:** the server never logs pasted text or keys.
- **Only fictional brands** (such as Galactibank, Orbitins, Nexamail) and reserved domains (`.example`, `.test`, `.invalid`) appear in examples and tests.

### Google Safe Browsing

When Safe Browsing is turned on, Google's terms require warnings to say **"Advisory provided by Google"** with a link to <https://developers.google.com/safe-browsing/v4/advisory>. They also require warnings to say "possibly" or "suspected", never "certainly". The v4 Lookup API is for non-commercial use only. The live demo does not use Safe Browsing right now, and the current UI does not show this advisory yet. It must be added before a key is set.

## Tech stack

- **Frontend:** React 19, Vite 8 and plain CSS. The ghost and backdrop are inline SVG, and the sounds are made with the Web Audio API (no audio files). The page respects `prefers-reduced-motion` and has a mute button.
- **Server:** Node.js 20+, Express 5, zod (input and env validation), express-rate-limit and undici.
- **Engine:** plain ES modules with no dependencies.
- **Tests:** Vitest, fast-check (property tests) and supertest.

## Project layout

```
backend/engine/    Layer 1 rules engine (pure JS, shared by browser and server)
backend/server/    Express API: /api/unwrap, /api/safebrowsing, /api/analyze, /api/health;
                   also serves the built frontend in production
frontend/          React + Vite app (src/api.js is the single entry point to the engine and API)
docs/              deploy.md (build, start, env vars), server-spec.md
.kiro/             Kiro spec for the engine (requirements, design, tasks) and steering files
```

## Run locally

You need Node.js 20 or newer. All commands below are run from the repository root unless noted.

**Production-style run** (one service: server plus built frontend):

```sh
npm run build    # installs packages and builds frontend/dist
npm start        # production mode on http://localhost:3001
```

**Development** (two terminals):

```sh
# Terminal 1: API server on port 3001, restarts on file changes
npm install
npm run dev -w @threatpeek/server

# Terminal 2: frontend on http://localhost:5173 (forwards /api to port 3001)
cd frontend
npm install
npm run dev
```

To build the UI without the server, copy `frontend/.env.example` to `frontend/.env`. It sets `VITE_USE_MOCK=true`, which returns sample results. The production build always uses the real engine and API.

**Environment variables:**
- The server reads them from `backend/server/.env` (copy `backend/server/.env.example`) or from the host's settings.
- None are required. Safe Browsing needs `GOOGLE_SAFE_BROWSING_KEY`. The AI layer needs `AI_ENABLED=true`, `OPENROUTER_API_KEY` and `OPENROUTER_MODEL`.
- Behind a hosting proxy, set `TRUST_PROXY=1` so rate limits see real visitor IPs.
- See [docs/deploy.md](docs/deploy.md) for the full table.

**Windows notes:**
- Run the tests from a path with an uppercase drive letter (`D:\...`). With `/d/...` from Git Bash, Vitest loads twice and every suite fails.
- Stop `npm run dev` before running `npm run build`. The build reinstalls `frontend/node_modules`, and Windows blocks that while the dev server holds a file open.

## Tests

```sh
npm test    # engine, server and frontend
```

| Package | Test files | Tests | What they cover |
|---|---|---|---|
| `backend/engine` | 18 | 315 | Unit tests per module, 13 golden tests, fast-check property tests, normalization and defanged-link tests, scam-family tests, a dev-set benchmark check |
| `backend/server` | 8 | 208 | Endpoints, SSRF guard and IP ranges, env loading, cache; no network needed |
| `frontend` | 2 | 14 | The `api.js` adapter in mock mode and the recorded voice clips (`voice.js`) |
| **Total** | **28** | **537** | |

## How we built it

- **Kiro:** we wrote the engine spec in Kiro, made up of requirements, design and a task list ([.kiro/specs/threat-scoring](.kiro/specs/threat-scoring)). We also wrote short steering files there for the product, security and tech rules ([.kiro/steering](.kiro/steering)). Those files set the rules the rest of the project follows: for example, never say "safe", keep keys on the server, and use only fictional brands.
- **Claude Code:** we used it to write the implementation (the engine, the server, the frontend and the tests). For the engine, it worked through the Kiro task list. We also used it to review changes and to write this README.
- **Our own decisions:** we made the key choices ourselves and wrote them into the spec and steering files: the three-layer design with the engine as the always-on base, the scoring weights, caps, floors and ghost thresholds, the security rules, and the free-tier limits.

The Kiro spec covers only the engine. The server was planned in [docs/server-spec.md](docs/server-spec.md), not in `.kiro/`. No Kiro hooks are used.

## Credits

Built by a team of two for Kiroween 2026.

Chithi's voice was recorded by the author and pitch-shifted. No third-party audio is used.

Released under the [MIT License](LICENSE).
