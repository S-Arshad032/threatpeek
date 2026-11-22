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

The package also exports `blend(l1Score, l2Hit, l3Score, flags)` and `verdictFor(riskScore)`.

## How it scores

1. **L1 heuristics.** Four detectors run in order: identity, auth headers, links, content. Together they check 17 signals (English text only). Each signal's weight counts once, and each category has a cap: identity/auth 40, link 35, content 45.
2. **Blend.** The L1 score is combined with `l2Hit` and `l3Score`. The result never drops below 0.8 × L1. Hard floors then apply to dangerous combinations, for example a look-alike domain plus a password request scores at least 70, and a prize or inheritance story plus a request for card details or gift-card payment also scores at least 70.
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

The suite has unit tests per module, 10 golden tests, and fast-check property tests (P1–P20 from the design). Fixtures use only fictional brands and reserved TLDs (`.example`, `.test`, `.invalid`).

On Windows, run the tests from a path whose drive letter is uppercase (`D:\...`). If Git Bash starts in `/d/...`, the working directory gets a lowercase drive letter, vitest loads two copies of itself, and every suite fails with "Cannot read properties of undefined (reading 'config')".
