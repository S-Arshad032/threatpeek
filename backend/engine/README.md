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

The package also exports `blend(l1Score, l2Hit, l3Score, flags, context?)` and `verdictFor(riskScore)`. `context.paymentInstruction` and `context.secretRequest` are facts from the content detector, not signals: the first lets a gift-card or crypto payment reach its floor when the message says where to send it; the second lifts a direct instruction to hand over a password, PIN, passcode, login or security answer ("Send us your password") to at least 45.

## How it scores

1. **L1 heuristics.** Four detectors run in order: identity, auth headers, links, content. Together they check 27 signals (English text only). The content detector first normalizes the text (NFKC, lowercase, no zero-width characters, collapsed whitespace, leetspeak and spaced-out letters undone) and maps every match back, so evidence always quotes the original text. Defanged links ("evil[.]com", "evil dot com", "hxxps://") are turned back into real links before every link check, and the disguise itself is a signal (`defanged-link`, 10). Six scam-family signals (`delivery-scam`, `seed-phrase-request`, `investment-guarantee`, `task-job-scam`, `official-fine-threat`, `recruiter-bait`) each need several cues in the same message. Each signal's weight counts once, and each category has a cap: identity/auth 40, link 35, content 45.
2. **Blend.** The L1 score is combined with `l2Hit` and `l3Score`. The result never drops below 0.8 × L1. Hard floors then apply to dangerous combinations, for example a look-alike domain plus a password request scores at least 70, and a prize or inheritance story plus a request for card details or gift-card payment also scores at least 70. The scam families have their own floors: a wallet recovery-phrase request 70, a fine or tax demand with a link and a threat 60, an investment "guarantee" 55 (70 with pressure), and a failed-delivery link, a paid "like videos" task job or a recruiter's document link 50. No floor rests on a single weak cue.
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
npm run benchmark -- --set=heldout3   # reserved third held-out set (empty for now, see below)
```

**heldout3 is reserved.** [`benchmark/heldout3.json`](benchmark/heldout3.json) has an empty `messages` array on purpose. It is kept for 30 fresh messages (15 scam, 15 benign) written by someone who has NOT seen the rules, or by the author before reading any engine output for them. Add them, run `--set=heldout3` once, and never tune rules on them afterwards. Until then the run prints this note and scores nothing.

Each run scores every message with `score(text)` only (no AI, no Safe Browsing). It prints counts by label and verdict, detection rate (scam scored 31 or more), strong detection rate (70 or more), false-alarm rate (normal message scored 31 or more), detection per scam category, and every miss and false alarm. It also updates that set's section of [`benchmark/RESULTS.md`](benchmark/RESULTS.md). The sets are small, synthetic and English-only, and all were written by the same author, so the numbers are not a guarantee.

On Windows, run the tests from a path whose drive letter is uppercase (`D:\...`). If Git Bash starts in `/d/...`, the working directory gets a lowercase drive letter, vitest loads two copies of itself, and every suite fails with "Cannot read properties of undefined (reading 'config')".
