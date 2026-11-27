# @threatpeek/engine

Pure-JavaScript threat-scoring engine for ThreatPeek. You give it a pasted link, email or SMS and it returns an estimated 0–100 risk score, a ghost verdict, red-flag cards and highlighted "cursed phrases".

It is plain ES modules with no dependencies, no I/O and no browser or Node.js APIs, so the client and the server share the same code.

## Usage

```js
import { score } from "@threatpeek/engine";

const result = score("Enter your OTP at http://203.0.113.5/verify");
// {
//   riskScore: 70,
//   verdict: "poltergeist",          // "pookie" (0-30) | "skeptical" (31-69) | "poltergeist" (70-100)
//   redFlags: [{ id: "raw-ip-url", weight: 35, evidence: "...", explanation: "..." }, ...],
//   cursedPhrases: [{ text: "OTP", reason: "..." }],
//   confidence: "limited"            // "full" only when an AI score (l3Score) was supplied
// }
```

`score(input, options?)`

| option    | type                          | default            | meaning                                                   |
|-----------|-------------------------------|--------------------|-----------------------------------------------------------|
| `l2Hit`   | `boolean`                     | `false`            | The caller's blacklist lookup matched. The engine never does the lookup itself. |
| `l3Score` | integer 0–100 or `null`       | `null`             | An AI score from the caller. The engine never calls an AI itself. |
| `brands`  | `{ name, domains[] }[]`       | `DEFAULT_BRANDS`   | Brands to protect from typosquatting and display-name spoofing. |

Errors: `TypeError` when the input is not a string. `RangeError` when the input is longer than 4000 characters, or when `l3Score` is not an integer 0–100.

The package also exports `blend(l1Score, l2Hit, l3Score, flags, context?)` and `verdictFor(riskScore)`. `context.paymentInstruction`, `context.secretRequest` and `context.jobFee` are facts from the content detector, not signals (`jobFee` lifts `advance-fee-scheme` to 60 when a job message asks for an upfront fee): the first lets a gift-card or crypto payment reach its floor when the message says where to send it; the second lifts a direct instruction to hand over a password, PIN, passcode, login or security answer ("Send us your password") to at least 45.

## How it scores

1. **L1 heuristics.** Four detectors run in order: identity, auth headers, links, content. Together they check 33 signals (English text only). The content detector first normalizes the text (NFKC, lowercase, no zero-width characters, collapsed whitespace, leetspeak and spaced-out letters undone) and maps every match back, so evidence always quotes the original text. Defanged links ("evil[.]com", "evil dot com", "hxxps://") are turned back into real links before every link check, and the disguise itself is a signal (`defanged-link`, 10). `lookalike-lure-domain` (20, or 30 on a risky ending or a defanged link) fires when the registrable part of a link is 2 or more hyphen-joined lure words such as `secure-login-help` (subdomains and the brands' own domains are skipped). Six scam-family signals (`delivery-scam`, `seed-phrase-request`, `investment-guarantee`, `task-job-scam`, `official-fine-threat`, `recruiter-bait`) each need several cues in the same message, and so do the round 2 families `utility-disconnection-threat`, `payment-failed-lure` and `account-security-lure`. `payment-failed-lure` needs a suspicious link (lure address, risky ending, shortener or raw IP) or an hours-level deadline or deletion threat; `account-security-lure` needs a suspicious link. Round 3: `credential-request` (20) needs a real request, a request verb (enter, send, share, confirm, verify, reply, read out...) before the password, PIN, OTP or code in the same sentence (80 characters), the word followed by "please", or "log in" / "sign in" as an instruction rather than a noun ("a login from a new device"); notices such as "your password was changed" do not fire. `unfamiliar-link-pressure` (25) fires on a link, normal or defanged, whose registrable domain is unfamiliar (URL shortener, raw IP, risky ending, a label with 2 or more hyphens, or a hyphenated label with a lure word) together with pressure in the text (a deadline, a threat to an account or service, a fee or payment ask, or a verify/claim ask); pressure words inside the domain do not count, and `UNFAMILIAR_SAFE_DOMAINS` (google.com, paypal.com, bkash.com, nagad.com.bd...) never count. `tech-support-scam` (30) needs a security scare about the reader's device or account (malware "detected"/"alert", "infected with", "detected on your PC", passwords/device "at risk", "5 viruses", an error code like `0x8007002`; not inside an "if..." clause) AND a hook: call/contact + support/helpdesk/technician, or install/open/allow + a named remote tool or "remote session". `remote-access-request` also fires on a named remote-control tool (AnyDesk, TeamViewer, UltraViewer, Quick Assist...) with an install/open/download/allow instruction. Each signal's weight counts once, and each category has a cap: identity/auth 40, link 35, content 45.
2. **Blend.** The L1 score is combined with `l2Hit` and `l3Score`. The result never drops below 0.8 × L1. Hard floors then apply to dangerous combinations, for example a look-alike domain plus a password request scores at least 70, and a prize or inheritance story plus a request for card details or gift-card payment also scores at least 70. The scam families have their own floors: a wallet recovery-phrase request 70, a fine or tax demand with a link and a threat 60, an investment "guarantee" 55 (70 with pressure), a job or hiring message with an upfront onboarding, registration or training fee 60 (`context.jobFee`), and a failed-delivery link, a paid task job (including remote data-entry work with daily pay, "no experience" and a chat-app contact), a recruiter's document link, a utility disconnection threat, a "payment failed" lure, a sign-in alert on a lure address or an unfamiliar link with pressure (4.27) 50, and a tech-support scam (4.28) 60. No floor rests on a single weak cue.
3. **Verdict.** The blended score maps to `verdictFor`.

All weights, caps, floors, word lists and explanation texts live in [`src/config.js`](src/config.js). The fictional default brands live in [`src/brands.js`](src/brands.js).

## Notes for the UI

- Every string taken from the input (`evidence`, `cursedPhrases[].text`, and explanations that quote evidence) is untrusted. Render it as plain text, never as HTML.
- Scores are estimates. The engine never says a message is safe, and `confidence: "limited"` means only heuristics were used.

## Tests

```sh
npm install
npm test
```

The suite has unit tests per module, 13 golden tests, fast-check property tests (P1–P21 from the design), and a regression check on the benchmark dev set. Fixtures use only fictional brands and reserved TLDs (`.example`, `.test`, `.invalid`).

## Benchmark

```sh
npm run benchmark                     # dev set (70 messages, used to tune the rules)
npm run benchmark -- --set=heldout    # held-out set (40 different messages, never tuned on)
npm run benchmark -- --set=heldout2   # second held-out set (30 messages, credential/OTP focus, never tuned on)
npm run benchmark -- --set=heldout3   # third set (30 messages, seen, used for rule tuning in round 2)
npm run benchmark -- --set=heldout4   # fourth set (30 messages, seen after round 3, used for tuning)
npm run benchmark -- --set=heldout5   # reserved fifth set (empty: the next fully unseen set)
```

**heldout3** ([`benchmark/heldout3.json`](benchmark/heldout3.json), 30 messages: 15 scam, 15 benign) was written by a third party (Gemini) and was not seen while the round 1 rules were written. **It is now seen, used for rule tuning in round 2**, so it is no longer a held-out measure. Unlike the other sets it uses real Bangladeshi service names (bKash, Nagad, DESCO, RedX...) with defanged throwaway domains, and its file is `{ note, messages }`. Results with `score(text)` only, round 1 (measured once on 25 November 2026, before it was seen) and round 2 (26 November 2026, after tuning on its misses):

| heldout3 | Round 1 (unseen) | Round 2 (seen) |
|---|---|---|
| Scams flagged (score 31 or more) | 60% (9/15) | 93% (14/15) |
| Scams scored 50 or more | 53% (8/15) | 87% (13/15) |
| Scams scored high risk (70 or more) | 13% (2/15) | 47% (7/15) |
| Normal messages wrongly flagged (31 or more) | 0% (0/15) | 0% (0/15) |

Known limitations:

- The original draft contained 3 romanized-Bengali messages. They were replaced by English versions because the engine is English-only, so this set says nothing about mixed-language messages, which real Bangladeshi scams often are.
- `h3-s06` (scam: "my main number got blocked... I need an urgent 3,000 BDT bKash transfer") and `h3-b13` (normal: "my card got declined... can you send me 600 BDT on bKash right now?") are near-twins. A rule engine cannot reliably tell them apart: the scam scored 15 (only `urgency-en`), the normal one 0. Both stay Pookie.
- Round 1 misses (all but the friend-impersonation are caught in round 2): a task-job offer that asks you to message HR on Telegram (25), a utility disconnection threat (25), the friend-impersonation money request (15), a fake Gmail sign-in alert (10), a recruiter asking for an onboarding fee (0), and a subscription "update your payment method" phish (25).

Like the other sets, heldout3 is small and synthetic; the numbers are not a guarantee.

**heldout4** ([`benchmark/heldout4.json`](benchmark/heldout4.json), 30 messages: 15 scam, 15 benign) was written by a third party (Gemini) and covers different scam types than all earlier sets. Its **first contact, before round 3** (27 November 2026), was measured once without changing any rule, when no rule had been written with it in view. **It is now seen after round 3 (used for tuning)**: its misses and false alarm guided the `credential-request` fix and `unfamiliar-link-pressure`, so the round 3 column is optimistic and not a held-out measure. Results with `score(text)` only:

| heldout4 | First contact, before round 3 (unseen) | After round 3 (seen) | + tech-support-scam (seen) |
|---|---|---|---|
| Scams flagged (score 31 or more) | 13% (2/15) | 53% (8/15) | 60% (9/15) |
| Scams scored 50 or more | 13% (2/15) | 53% (8/15) | 60% (9/15) |
| Scams scored high risk (70 or more) | 0% (0/15) | 20% (3/15) | 20% (3/15) |
| Normal messages wrongly flagged (31 or more) | 7% (1/15) | 0% (0/15) | 0% (0/15) |

At first contact the rules caught only a scholarship "processing fee" (`h4-s03`, 55) and a Facebook page appeal that asks you to verify your identity (`h4-s11`, 55), and flagged a real "your password was changed, call us if it wasn't you" bank alert (`h4-b14`, 55: `urgency-en`, `credential-request`). After round 3 the alert scores 15, and the 8 scams with a link score 50 to 75 (50 to 60 with the brackets removed, so the result does not depend on `defanged-link`). The 7 scams without a link are still missed: a visa "clearance bond" by wire transfer (20), a rental deposit from a landlord abroad (0), a wrong-number "angel investor" opener (0), a fake flood-relief donation (0), a fake Microsoft Defender alert asking you to call and install AnyDesk (0, was 20 when `credential-request` fired on "passwords are at risk"), a marketplace buyer's QR code (0) and an invoice with changed bank details (0). Round 3 also changed the other sets: no normal message scored higher anywhere, and one dev scam dropped (`dev-s19`, a fake virus alert that only says your passwords are at risk, 55 to 15), see the [root README](../../README.md#round-3-fixing-the-heldout4-false-alarm-and-one-general-gap). The later `tech-support-scam` signal brings both fake virus alerts back: `h4-s08` (fake Microsoft Defender alert, call and install AnyDesk) 0 → 60 and `dev-s19` 15 → 60; no other message on any set changed. The remaining 6 heldout4 misses are the scams without a link listed above, except the Defender alert.

**heldout5** ([`benchmark/heldout5.json`](benchmark/heldout5.json)) is reserved and empty (`{ note, messages: [] }`), kept for 30 fresh messages (15 scam, 15 benign) that nobody has seen. It is the next fully unseen set. `--set=heldout5` prints its note and leaves `RESULTS.md` untouched while it is empty. Do not invent messages for it. Like every set here, it will be small and synthetic; the numbers are not a guarantee.

Each run scores every message with `score(text)` only (no AI, no Safe Browsing). It prints counts by label and verdict, detection rate (scam scored 31 or more), strong detection rate (70 or more), false-alarm rate (normal message scored 31 or more), detection per scam category, and every miss and false alarm. It also updates that set's section of [`benchmark/RESULTS.md`](benchmark/RESULTS.md). The sets are small, synthetic and English-only, and all were written by the same author, so the numbers are not a guarantee.

On Windows, run the tests from a path whose drive letter is uppercase (`D:\...`). If Git Bash starts in `/d/...`, the working directory gets a lowercase drive letter, vitest loads two copies of itself, and every suite fails with "Cannot read properties of undefined (reading 'config')".
