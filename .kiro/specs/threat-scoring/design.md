# Design Document: threat-scoring

## Overview

The threat-scoring engine is a pure-JavaScript ES-module library in `backend/engine`. It accepts a text message (email body, SMS or URL) and returns a structured risk assessment (`RiskResult`). It has no I/O, no browser APIs and no Node.js built-ins, so it runs unchanged in browsers, Node.js, Deno and edge runtimes. Content signals are English-only; Unicode is still handled for hostname checks.

Analysis happens in three layers:

- **L1 Heuristics**: four detector modules scan the input with bounded regular expressions and emit `RedFlag` and `CursedPhrase` objects.
- **L2 Blacklist**: a boolean (`options.l2Hit`) supplied by the caller. The engine never performs the lookup itself.
- **L3 AI**: an optional integer 0-100 (`options.l3Score`) supplied by the caller. The engine never calls an AI itself.

`blend()` combines the layers into one integer `riskScore` (0-100). `verdictFor()` maps it to `"pookie"`, `"skeptical"` or `"poltergeist"`. The whole pipeline is pure and deterministic.

**Design rules**

1. Every numeric value (weights, caps, thresholds, floors, coefficients, limits) is a named constant in `config.js`. Non-numeric word lists (risky TLDs, dangerous extensions, phrase lists, allowlists) also live in `config.js`. No other module uses an inline literal for these.
2. Pasted text is untrusted data. The engine never evaluates, fetches or follows anything in it. Every string derived from the input (`evidence`, `cursedPhrases[].text`, and text embedded in `explanation`) MUST be rendered by the UI as plain text, never as HTML.
3. Regexes are bounded and ReDoS-safe by construction. Regex objects with the `g` flag are never shared mutable state: use `String.prototype.matchAll` (which clones the regex) or create the regex inside the function. Never call `.exec()` or `.test()` on a module-level `g` regex.

---

## Architecture

```
input + options
       |
       v
  +-------------+
  |   score.js  |  validates input, assembles RiskResult
  +------+------+
         | runs all four detectors
    +----+--------------+-------------+-------------+
    v                   v             v             v
identity.js         link.js      content.js   auth-headers.js
    |                   |             |             |
    +-------------------+-------------+-------------+
                        | RedFlag[], CursedPhrase[]
                        v
                  +----------+
                  | blend.js |  computes riskScore
                  +----+-----+
                       v
                 +-----------+
                 | verdict.js|  computes verdict string
                 +-----------+
                       v
                   RiskResult
```

### File structure

```
backend/engine/
  src/
    config.js
    brands.js
    util/
      hostname.js        (hostname extractors, registrable-domain and brand-legitimacy helpers)
      levenshtein.js     (edit distance)
      normalize.js       (content-text normalization with an offset map back to the original; refang())
      links.js           (link finder for the content signals, URL-shortener check)
    detectors/
      identity.js
      link.js
      content.js
      auth-headers.js
    blend.js
    verdict.js
    score.js
    index.js
  test/
    golden.test.js
    property.test.js
    benchmark.test.js    (dev-set regression guard)
  benchmark/
    dev.json             (70 labelled messages, used for tuning)
    heldout.json         (40 different messages, never tuned on)
    heldout2.json        (30 different messages, credential/OTP focus, never tuned on)
    heldout3.json        ({ note, messages }, 30 third-party messages; seen, used for rule tuning in round 2)
    heldout4.json        ({ note, messages }, 30 third-party messages; first contact unseen, seen after round 3)
    heldout5.json        ({ note, messages }, 30 third-party messages; the only set fully unseen at the time of final tuning)
    lib.js, run.js       (`npm run benchmark [-- --set=dev|heldout|heldout2|heldout3|heldout4|heldout5]`)
    RESULTS.md           (generated)
```

### Layering rules

- `config.js` and `brands.js` import nothing from the package.
- `util/*` imports only `config.js`.
- Detector files import only `config.js`, `brands.js` and `util/*`.
- `blend.js` and `verdict.js` import only `config.js`.
- `score.js` imports all detectors, `blend.js`, `verdict.js`, `config.js` and `brands.js` (for `DEFAULT_BRANDS`).
- `index.js` re-exports `score`, `blend`, `verdictFor`; it contains no logic.
- No module imports from `score.js`.

---

## Components and Interfaces

```js
score(input: string, options?: ScoreOptions | null): RiskResult
detectIdentity(input: string, brands: BrandEntry[]): { flags: RedFlag[], cursedPhrases: CursedPhrase[] }
detectLinks(input: string):       { flags: RedFlag[], cursedPhrases: CursedPhrase[] }
detectContent(input: string):     { flags: RedFlag[], cursedPhrases: CursedPhrase[] }
detectAuthHeaders(input: string): { flags: RedFlag[], cursedPhrases: CursedPhrase[] }
blend(l1Score: number, l2Hit: boolean, l3Score: number | null, flags: string[] | Set<string>): number
verdictFor(riskScore: number): "pookie" | "skeptical" | "poltergeist"
```

Only `identity`, `link` and `auth-headers` return an empty `cursedPhrases`. Only `content.js` produces cursed phrases.

---

## Data Models

```js
RedFlag      { id: string, weight: number, evidence: string, explanation: string }
CursedPhrase { text: string, reason: string }
RiskResult   { riskScore: number /* int 0-100 */, verdict: string, redFlags: RedFlag[],
               cursedPhrases: CursedPhrase[], confidence: "limited" | "full" }
BrandEntry   { name: string /* e.g. "galactibank" */, domains: string[] /* legitimate domains */ }
ScoreOptions { l2Hit?: boolean, l3Score?: number | null, brands?: BrandEntry[] }
```

Internally `score.js` also needs each flag's category (identity-auth, link, content). Categories are derived from a signal-id-to-category map in `config.js` (`SIGNAL_CATEGORY`), so `RedFlag` keeps exactly the four fields above.

### config.js

```js
// Signal weights
export const W_TYPOSQUATTING         = 35;
export const W_HOMOGRAPH_PUNYCODE    = 35;
export const W_RAW_IP_URL            = 35;
export const W_RISKY_TLD             = 15;
export const W_DISPLAY_NAME_MISMATCH = 25;
export const W_LINK_TEXT_MISMATCH    = 35;
export const W_URGENCY_EN            = 15;
export const W_CREDENTIAL_REQUEST    = 20;
export const W_SUSPICIOUS_ATTACHMENT = 20;
export const W_SPF_FAIL              = 20;
export const W_DKIM_FAIL             = 20;
export const W_DMARC_FAIL            = 15;
export const W_PRIZE_LOTTERY          = 25;
export const W_ADVANCE_FEE_SCHEME     = 25;
export const W_FINANCIAL_INFO_REQUEST = 30;
export const W_UNUSUAL_PAYMENT_METHOD = 20;
export const W_SECRECY_PRESSURE       = 10;
export const W_CODE_SHARING_REQUEST   = 30;
export const W_MISTAKEN_PAYMENT       = 25;
export const W_REMOTE_ACCESS_REQUEST  = 25;

// Category caps
export const CAP_IDENTITY_AUTH = 40;
export const CAP_LINK          = 35;
export const CAP_CONTENT       = 45;

// Verdict thresholds (inclusive upper bounds)
export const VERDICT_POOKIE_MAX    = 30;
export const VERDICT_SKEPTICAL_MAX = 69;

// Hard floors
export const FLOOR_TYPOSQUAT_CRED = 70;
export const FLOOR_RAWIP_CRED     = 70;
export const FLOOR_AUTH_DISPLAY   = 60;
export const FLOOR_CRED_URGENCY   = 55;
export const FLOOR_ATTACHMENT     = 40;
export const FLOOR_PRIZE_PAYMENT  = 70;
export const FLOOR_FINANCIAL_INFO = 50;
export const FLOOR_UNUSUAL_PAYMENT = 40;   // only with a pressure signal or a hand-over instruction
export const FLOOR_CODE_SHARING   = 50;
export const FLOOR_MISTAKEN_PAYMENT = 40;
export const FLOOR_SECRET_REQUEST = 45; // 4.16, context.secretRequest
export const FLOOR_DELIVERY_SCAM = 50;        // 4.17
export const FLOOR_SEED_PHRASE = 70;          // 4.18
export const FLOOR_INVESTMENT = 55;           // 4.19
export const FLOOR_INVESTMENT_PRESSURE = 70;  // 4.19, with urgency-en or unusual-payment-method
export const FLOOR_TASK_JOB = 50;             // 4.20
export const FLOOR_OFFICIAL_FINE = 60;        // 4.21
export const FLOOR_RECRUITER_BAIT = 50;       // 4.22
export const FLOOR_UTILITY_DISCONNECTION = 50; // 4.23
export const FLOOR_PAYMENT_FAILED = 50;        // 4.24
export const FLOOR_ACCOUNT_SECURITY = 50;      // 4.25, only with a suspicious link
export const FLOOR_JOB_FEE = 60;               // 4.26, advance-fee-scheme + context.jobFee
export const FLOOR_UNFAMILIAR_LINK_PRESSURE = 50; // 4.27, round 3
export const FLOOR_TECH_SUPPORT = 60;          // 4.28

// Content proximity windows (characters)
export const REQUEST_PROXIMITY_CHARS = 60;
export const PRIZE_PROXIMITY_CHARS   = 60;
export const NEGATION_GOVERNED_MAX_WORDS = 4;   // helper words between a negation and the verb it governs
export const MONEY_DIGITS_MAX        = 15;
export const MONEY_SPACE_MAX         = 3;

// Blend coefficients
export const BLEND_L1_WEIGHT       = 0.55;
export const BLEND_L3_WEIGHT       = 0.45;
export const BLEND_L1_FLOOR_FACTOR = 0.8;
export const BLEND_L2_FLOOR        = 90;

// Limits
export const MAX_INPUT_LENGTH     = 4000;
export const MAX_HOSTNAMES_SCANNED = 50;
export const MAX_CURSED_PHRASES    = 20;

// Typosquatting tuning
export const TYPO_SHORT_NAME_MAX_LEN = 6;  // brand names this long or shorter use the short distance
export const TYPO_MAX_DISTANCE_SHORT = 1;
export const TYPO_MAX_DISTANCE_LONG  = 2;
export const TYPO_MIN_FUZZY_LEN      = 4;  // brand names shorter than this are matched exactly only
export const TYPO_CONTAINS_MIN_LEN   = 6;  // "label contains brand name" rule needs a name this long

// Word lists (non-numeric)
export const SIGNAL_CATEGORY = {
  "typosquatting": "identity-auth", "homograph-punycode": "identity-auth",
  "display-name-mismatch": "identity-auth", "spf-fail": "identity-auth",
  "dkim-fail": "identity-auth", "dmarc-fail": "identity-auth",
  "raw-ip-url": "link", "risky-tld": "link", "link-text-mismatch": "link",
  "urgency-en": "content", "credential-request": "content", "suspicious-attachment": "content",
  "prize-lottery": "content", "advance-fee-scheme": "content", "financial-info-request": "content",
  "unusual-payment-method": "content", "secrecy-pressure": "content", "code-sharing-request": "content",
  "mistaken-payment": "content", "remote-access-request": "content",
  "defanged-link": "link", "delivery-scam": "content", "seed-phrase-request": "content",
  "investment-guarantee": "content", "task-job-scam": "content", "official-fine-threat": "content",
  "recruiter-bait": "content", "lookalike-lure-domain": "link", "utility-disconnection-threat": "content",
  "payment-failed-lure": "content", "account-security-lure": "content", "unfamiliar-link-pressure": "content", "tech-support-scam": "content",
};
export const RISKY_TLDS = ["xyz", "top", "click", "tk", "ml", "ga", "cf",
                           "support", "online", "info", "site", "icu"]; // Requirement 2.6 (round 2 endings added)
export const DANGEROUS_EXTENSIONS = ["exe", "scr", "vbs", "bat", "cmd", "js", "lnk", "iso", "img"];
export const JS_LIBRARY_ALLOWLIST = ["node", "react", "vue", "next", "nuxt", "express", "angular", "d3", "three"];
export const SECOND_LEVEL_LABELS = ["com", "co", "org", "net", "gov", "edu", "ac"]; // used with 2-letter country TLDs, e.g. com.bd, co.uk
export const URGENCY_EN_PHRASES = [ /* see content.js section */ ];
// Also (see content.js section): PRIZE_PHRASES, CONGRATS_WORDS, PRIZE_WORDS, CURRENCY_SYMBOLS,
// CURRENCY_CODES, CURRENCY_WORDS, LARGE_AMOUNT_WORDS, ADVANCE_FEE_PHRASES, FINANCIAL_REQUEST_VERBS,
// FINANCIAL_INFO_TERMS, NEGATION_WORDS, PAYMENT_VERBS, PAYMENT_METHODS, MOBILE_WALLET_TERMS,
// FEE_WORDS, SECRECY_PHRASES, and the phrase families added with the benchmark (URGENCY_EXTRA_PHRASES,
// ADVANCE_FEE_TERMS, CODE_TERMS, RETURN_REQUESTS, LEET_MAP, ...). See src/config.js for the full lists.
```

### brands.js

Exports `DEFAULT_BRANDS`, a `BrandEntry[]` with only fictional brands and reserved TLDs:

```js
export const DEFAULT_BRANDS = [
  { name: "galactibank", domains: ["galactibank.example"] },
  { name: "orbitins",    domains: ["orbitins.test"] },
  { name: "nexamail",    domains: ["nexamail.example"] },
  { name: "vaultpay",    domains: ["vaultpay.example"] },
  { name: "trustledger", domains: ["trustledger.test"] },
];
```

This list is used by the tests. A real deployment passes its own list through `options.brands`; `score.js` uses `options.brands` when it is an array, otherwise `DEFAULT_BRANDS`. Brand names are stored lowercase with only `a-z0-9`.

---

## score.js

```
function score(input, options):
  if typeof input !== "string": throw TypeError("input must be a string")
  if input.length > MAX_INPUT_LENGTH: throw RangeError("input exceeds 4000 characters")

  const opts   = options ?? {}                 // score(input, null) behaves like no options
  const l2Hit  = opts.l2Hit === true           // only boolean true activates L2
  const l3Score = opts.l3Score === undefined ? null : opts.l3Score
  if l3Score !== null:
    if typeof l3Score !== "number" || !Number.isInteger(l3Score) || l3Score < 0 || l3Score > 100:
      throw RangeError("l3Score must be an integer 0-100 or null")
  const brands = Array.isArray(opts.brands) ? opts.brands : DEFAULT_BRANDS
```

`Number.isInteger` is already false for NaN, Infinity and non-integers.

**L1 pipeline**

1. Run `detectIdentity`, `detectAuthHeaders`, `detectLinks`, `detectContent` in that fixed order.
2. Concatenate the flags in that order (deterministic output order).
3. Group flags by `SIGNAL_CATEGORY[flag.id]`.
4. Sum weights per category and cap at `CAP_IDENTITY_AUTH` (40), `CAP_LINK` (35), `CAP_CONTENT` (45).
5. `l1Score = min(100, sum of the three capped totals)`.
6. `flagIds = redFlags.map(f => f.id)`.
7. `riskScore = blend(l1Score, l2Hit, l3Score, flagIds)`.
8. `verdict = verdictFor(riskScore)`.
9. `confidence = l3Score !== null ? "full" : "limited"`.
10. `cursedPhrases` = the phrases returned by `detectContent`.
11. Return `{ riskScore, verdict, redFlags, cursedPhrases, confidence }`.

**One-flag-per-signal rule.** Each signal id produces at most ONE `RedFlag` per message, and its weight is counted once, however many matches there are. `evidence` records the first match. Extra matches only add entries to `cursedPhrases` (content signals only).

**Safety floor.** The smallest single flag weight is 10 (`secrecy-pressure`), so any message with a flag has `l1Score >= 10`, and the `0.8 x l1Score` floor gives `riskScore >= 8 > 0` (Requirement 8.1).

**Content cap.** The twenty Content signals add up to 480 points before the cap (with `delivery-scam` at its shortener weight 30), and `CAP_CONTENT` stays at 45. Two strong content signals already reach the cap; the dangerous combinations are lifted further by the hard floors (4.8, 4.10-4.12, 4.14, 4.15, 4.17-4.26), not by raising the cap. The Link cap stays at 35: `defanged-link` (10) plus `risky-tld` (15) is 25, and with `lookalike-lure-domain` (30 on a risky or defanged link) the Link total is capped at 35. The engine never produces any wording that says a message is safe; `confidence: "limited"` tells the UI the result is a heuristics-only estimate (Requirement 8.3).

---

## blend.js

```
function blend(l1Score, l2Hit, l3Score, flags, context = {}):
  const flagSet = new Set(flags)          // accepts Array or Set

  if l2Hit:                    risk = max(BLEND_L2_FLOOR, l1Score)                      // Rule 4.1
  else if l3Score !== null:    risk = BLEND_L1_WEIGHT * l1Score + BLEND_L3_WEIGHT * l3Score  // Rule 4.2
  else:                        risk = l1Score                                           // Rule 4.3

  risk = max(risk, BLEND_L1_FLOOR_FACTOR * l1Score)                                     // Rule 4.4

  if has("typosquatting") && has("credential-request"):   risk = max(risk, FLOOR_TYPOSQUAT_CRED)  // 4.5
  if has("raw-ip-url")    && has("credential-request"):   risk = max(risk, FLOOR_RAWIP_CRED)      // 4.6
  if (has("spf-fail") || has("dkim-fail")) && has("display-name-mismatch"):
                                                          risk = max(risk, FLOOR_AUTH_DISPLAY)    // 4.7
  if has("credential-request") && has("urgency-en"):     risk = max(risk, FLOOR_CRED_URGENCY)    // 4.8
  if has("suspicious-attachment"):                        risk = max(risk, FLOOR_ATTACHMENT)      // 4.9
  if (has("prize-lottery") || has("advance-fee-scheme")) &&
     (has("financial-info-request") || has("unusual-payment-method")):
                                                          risk = max(risk, FLOOR_PRIZE_PAYMENT)   // 4.10
  if has("financial-info-request"):                       risk = max(risk, FLOOR_FINANCIAL_INFO)  // 4.11
  if has("unusual-payment-method") &&
     (has("urgency-en") || has("secrecy-pressure") || has("prize-lottery") ||
      has("advance-fee-scheme") || context.paymentInstruction):
                                                          risk = max(risk, FLOOR_UNUSUAL_PAYMENT) // 4.12
  if has("code-sharing-request"):                         risk = max(risk, FLOOR_CODE_SHARING)    // 4.14
  if has("mistaken-payment"):                             risk = max(risk, FLOOR_MISTAKEN_PAYMENT) // 4.15
  if context.secretRequest:                               risk = max(risk, FLOOR_SECRET_REQUEST)  // 4.16
  if has("delivery-scam"):                                risk = max(risk, FLOOR_DELIVERY_SCAM)   // 4.17
  if has("seed-phrase-request"):                          risk = max(risk, FLOOR_SEED_PHRASE)     // 4.18
  if has("investment-guarantee"):
    risk = max(risk, has("urgency-en") || has("unusual-payment-method")
                     ? FLOOR_INVESTMENT_PRESSURE : FLOOR_INVESTMENT)                           // 4.19
  if has("task-job-scam"):                                risk = max(risk, FLOOR_TASK_JOB)        // 4.20
  if has("official-fine-threat"):                         risk = max(risk, FLOOR_OFFICIAL_FINE)   // 4.21
  if has("recruiter-bait"):                               risk = max(risk, FLOOR_RECRUITER_BAIT)  // 4.22
  if has("utility-disconnection-threat"):                 risk = max(risk, FLOOR_UTILITY_DISCONNECTION) // 4.23
  if has("payment-failed-lure"):                          risk = max(risk, FLOOR_PAYMENT_FAILED)  // 4.24
  if has("account-security-lure"):                        risk = max(risk, FLOOR_ACCOUNT_SECURITY) // 4.25
  if has("advance-fee-scheme") && context?.jobFee === true: risk = max(risk, FLOOR_JOB_FEE)       // 4.26
  if has("unfamiliar-link-pressure"):                     risk = max(risk, FLOOR_UNFAMILIAR_LINK_PRESSURE) // 4.27
  if has("tech-support-scam"):                            risk = max(risk, FLOOR_TECH_SUPPORT)     // 4.28

  return Math.round(Math.min(100, Math.max(0, risk)))                                   // 4.13
```

The 0.8 x L1 floor is applied before the hard floors; hard floors can only raise the score. Clamp and round are always last.

Floors 4.17-4.22 rest only on the compound family signals (Requirement 2.26-2.31), each of which needs several cues in one message. The weak signals around them (`defanged-link` 10, `urgency-en` 15) have no floor, so one weak cue alone never lifts a message above 50. The levels follow how direct the harm is: a wallet recovery phrase is total, immediate loss (70); a fine with a legal threat and a payment link is a strong payment lure (60); delivery, task-job and recruiter lures are Skeptical (50), because real couriers and recruiters do send similar messages; investment promises sit at 55 and reach 70 only with pressure or a hard-to-trace payment.

Round 2 floors 4.23-4.25 (utility disconnection, payment-failed lure, sign-in alert on a lure link) are 50 for the same reason as delivery: real utilities, shops and mail providers send similar notices, and only the compound of cues plus an odd link or a pay-now order separates them. A job that asks for an upfront fee (4.26) is 60: legitimate employers do not charge to hire, so the fee itself is the harm. `lookalike-lure-domain` has no floor; it is a Link signal that adds weight and feeds the "suspicious link" condition of 2.34 and 2.35. Round 3 floor 4.27 (`unfamiliar-link-pressure`) is 50: the signal already needs an unfamiliar domain and pressure in the text, and it works on links written with normal dots, so it does not rest on `defanged-link`. It is capped at 50 so this signal alone never makes a message Poltergeist. Floor 4.28 (`tech-support-scam`) is 60: a device scare plus "call support" or "install a remote tool" is the full tech-support script, and the remote session it leads to gives the caller the device and the bank login, so it sits with the fine demand and the job fee.

`context.paymentInstruction` comes from the content detector (`score()` passes it through). It is not a signal and has no weight: it only says the message names where to send the payment ("send it to me", "pay to this account", "send me the codes"). A gift card or crypto mentioned with no pressure and no instruction ("Buy a gift card for your mom") gets no floor and stays at 20.

`context.secretRequest` also comes from the content detector. It says the message tells the reader to hand over a password, PIN, passcode, login or security answer ("Send us your password", "You need to email us your login details"). A credential word alone keeps weight 20 and no floor, because reset mails and security tips use the same words; only the instruction lifts the score to 45 (Skeptical). 45 sits below floor 4.14 (50): a stolen one-time code is the more direct account takeover, and below 4.8 (55) so urgency plus a credential word still ranks higher.

## verdict.js

```
function verdictFor(riskScore):
  if riskScore <= VERDICT_POOKIE_MAX:    return "pookie"       // 0-30
  if riskScore <= VERDICT_SKEPTICAL_MAX: return "skeptical"    // 31-69
  return "poltergeist"                                         // 70-100
```

---

## util/hostname.js

Two shared hostname extractors. Both use the `u` flag and Unicode-aware lookarounds so a hostname is never extracted from the middle of a word (for example, the tail of a Cyrillic-spoofed hostname).

**ASCII hostname extractor**

```js
/(?<![\p{L}\p{N}\p{M}_.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,10}[a-z]{2,24})(?![\p{L}\p{N}\p{M}_@-])/giu
```

- The lookbehind (not a leading character set) lets it extract the hostname from `https://host/...`, `user@host` and plain text.
- The trailing lookahead rejects a hostname followed by `@` (so `user.name@host` does not yield `user.name`) and ends cleanly before `/`, `:`, `?`, `.`, `,` and spaces.
- All repetitions are bounded and labels are separated by a literal dot, so matching is linear.

**Unicode hostname extractor** (for homograph checks)

```js
/(?<![\p{L}\p{N}\p{M}_.-])((?:[\p{L}\p{N}](?:[\p{L}\p{N}\p{M}-]{0,61}[\p{L}\p{N}\p{M}])?\.){1,10}[\p{L}\p{M}]{2,24})(?![\p{L}\p{N}\p{M}_@-])/gu
```

`\p{M}` (combining marks) is included so labels written with combining marks still form valid hostnames.

Both extractors are applied with `matchAll`, lowercase the result, de-duplicate, and stop after `MAX_HOSTNAMES_SCANNED` hostnames.

**Helpers**

- `registrableLabel(host)`: the label just before the public suffix. Default: the second-to-last label. If the last label has 2 letters and the second-to-last is in `SECOND_LEVEL_LABELS` (for example `shop.example.com.bd`), use the third-to-last.
- `registrableDomain(host)`: `registrableLabel + "." + suffix`, used by link-text-mismatch.
- `isLegitimate(host, brand)`: true when `host` equals, or is a subdomain of, any entry in `brand.domains`.

## util/levenshtein.js

Standard iterative edit distance over strings of at most 63 characters.

---

## Detector Design

### identity.js

Signals: `typosquatting`, `homograph-punycode`, `display-name-mismatch`. All Identity/Auth. Returns an empty `cursedPhrases`.

#### typosquatting (weight `W_TYPOSQUATTING` = 35)

1. Extract hostnames with the ASCII extractor.
2. Skip any hostname for which `isLegitimate(host, brand)` is true for any brand.
3. For each remaining hostname take `label = registrableLabel(host)`.
4. For each brand, let `name` be the normalized brand name and fire the signal when ANY of these holds:
   - **Exact label on a wrong domain**: `label === name`. Example: `galactibank.xyz`, because the hostname is not one of the brand's legitimate domains.
   - **Lookalike**: `canon(label)` is within edit distance of `canon(name)`: at most `TYPO_MAX_DISTANCE_SHORT` (1) when `name.length <= TYPO_SHORT_NAME_MAX_LEN` (6), otherwise at most `TYPO_MAX_DISTANCE_LONG` (2). Only for names with `name.length >= TYPO_MIN_FUZZY_LEN`.
   - **Brand inside label**: `name.length >= TYPO_CONTAINS_MIN_LEN` and `label.includes(name)` (for example `galactibank-verify.example`).
5. `canon(s)` lowercases, then replaces `rn` with `m` and `vv` with `w`, maps `0` to `o`, `3` to `e`, `4` to `a`, `5` to `s`, and maps each of `1`, `i`, `l` to `l`. It is applied to both sides, so `galact1bank` and `galactibank` become identical.
6. Emit at most one `RedFlag`. `evidence` is the first matching hostname.

Regex safety: only the bounded extractor above is used; the comparison is plain string code.

#### homograph-punycode (weight `W_HOMOGRAPH_PUNYCODE` = 35)

1. Extract hostnames with the Unicode extractor.
2. Split each hostname into labels. The signal fires when any label:
   - starts with `xn--` (case-insensitive), OR
   - mixes Latin letters (`[A-Za-z]`) with Cyrillic or Greek letters (`[Ͱ-ϿЀ-ӿ]`) within the same label.
3. It does NOT fire for a hostname written entirely in one script (for example pure Cyrillic), because legitimate internationalized domains exist.
4. Emit at most one `RedFlag`. `evidence` is the first suspicious hostname.

#### display-name-mismatch (weight `W_DISPLAY_NAME_MISMATCH` = 25)

```js
/(?:^|\n)[ \t]*From:[ \t]*(?:"([^"\n]{1,100})"|([^<\n]{1,100}?))[ \t]*<[^@<>\s]{1,64}@([a-z0-9.-]{1,253})>/gi
```

1. Take the display name (group 1 or 2) and the sending domain (group 3).
2. Normalize the display name (lowercase, keep only `a-z0-9`).
3. If it contains a brand's normalized `name` and the sending domain is neither equal to nor a subdomain of any of that brand's `domains`, fire.
4. Emit at most one `RedFlag`. `evidence` is the trimmed `From:` line (max 200 characters).

All repetitions are bounded; negated classes stop at line ends and `<`.

---

### Defanged links (`util/normalize.js`, Requirement 2.25)

`DEFANG_RE` has four fixed alternatives: `[\[({]\s?(?:\.|dot)\s?[\])}]`; `(?<=[a-z0-9])(?<!\b(the|a|an|of|...))\s{1,3}dot\s{1,3}(?=SPACED_DOT_TLD\b)`; `\bhxxp(?=s?(:|\[:\])//)`; `(?<=\bhttps?|\bhxxps?)\[:\](?=//)`. `refang(input)` replaces them ("hxxp" -> "http" keeping case and length, "[:]" -> ":", the rest -> "."). `normalize()` runs the same regex as step 4 on its character array: a same-length replacement rewrites characters in place; a shorter one emits characters that all span the whole original piece, so `toOriginal` still points at "[.]". The link and identity detectors call `refang` first. `findDefang` returns the first piece for the `defanged-link` evidence, which is widened to the surrounding whitespace-free token (at most `MAX_DEFANG_EVIDENCE_CHARS` = 100 characters each side).

`util/links.js` `findLinks(input)` refangs, then returns `{ text, host, shortener }` for each URL with a scheme, "www." host, or bare hostname whose ending is in `LINK_TLDS` (at most `MAX_HOSTNAMES_SCANNED`). `shortener` is true when the host is in `SHORTENER_DOMAINS`.

### link.js

Signals: `raw-ip-url`, `risky-tld`, `link-text-mismatch`, `defanged-link`, `lookalike-lure-domain`. All Link. Returns an empty `cursedPhrases`. Every check except `defanged-link` reads `refang(input)`. `detectLinks(input, brands)` takes the same brand list as `score()`.

#### lookalike-lure-domain (weight `W_LOOKALIKE_LURE_DOMAIN` = 20, `W_LOOKALIKE_LURE_DOMAIN_STRONG` = 30)

`util/lure.js` `isLureDomain(host, brands)`: split `registrableLabel(host)` on "-" and count parts in `LURE_WORDS`; fire at `LURE_WORDS_MIN` (2) or more, unless `registrableDomain(host)` is a brand domain or in `LOOKALIKE_SAFE_DOMAINS`. The first such link from `findLinks(input)` is the evidence (its host). Weight 30 when `hasRiskyTld(host)` or `findDefang(input)` finds a defanged piece, else 20. The same helper feeds the content detector's "suspicious link" test (lure domain, risky TLD, shortener or raw IP) for 2.34 and 2.35.

#### defanged-link (weight `W_DEFANGED_LINK` = 10)

Fires when `findDefang(input)` finds a piece; evidence is the disguised token from the original input. No floor.

#### raw-ip-url (weight `W_RAW_IP_URL` = 35)

IPv4:

```js
/https?:\/\/((?:\d{1,3}\.){3}\d{1,3})(?=\.?(?:[\s"'<>)\],;:\/?#]|$))/gi
```

- The terminator accepts whitespace, quotes, brackets, punctuation, `/`, `?`, `#`, `:` (port) or end of text. A trailing sentence period is allowed, but a dot followed by more hostname characters is not, so `http://1.2.3.4.evil.example` does not match.
- After matching, split on `.` and require each octet to be 0-255; otherwise discard the match.

IPv6 (always in brackets in a URL):

```js
/https?:\/\/\[([0-9a-f:.]{2,45})\]/gi
```

- Validate in code: at least two `:`, at most one `::`, each group at most 4 hex digits, at most 8 groups.
- Emit at most one `RedFlag`. `evidence` is the first matched URL.

#### risky-tld (weight `W_RISKY_TLD` = 15)

Built from `RISKY_TLDS` (exactly `xyz top click tk ml ga cf`):

```js
/(?<![\p{L}\p{N}\p{M}_.-])(?:[a-z0-9-]{1,63}\.){1,10}(?:xyz|top|click|tk|ml|ga|cf)(?![\p{L}\p{N}\p{M}_-]|\.[a-z0-9-])/giu
```

- The final lookahead means the TLD must be the last label. It may be followed by `/`, `?`, `#`, `:`, quotes, `)`, `>`, whitespace, end of text, or sentence punctuation. It may not be followed by another label, so `bad.xyz.example` does not fire.
- Emit at most one `RedFlag`. `evidence` is the first matched hostname.

#### link-text-mismatch (weight `W_LINK_TEXT_MISMATCH` = 35)

```js
// HTML anchor
/<a\s[^>]{0,500}?href\s*=\s*["']([^"']{1,2048})["'][^>]{0,500}>([^<]{1,500})<\/a>/gi
// Markdown link
/\[([^\]\n]{1,500})\]\((https?:\/\/[^)\s]{1,2048})\)/gi
```

1. For each link take the host of the `href`, and look at the visible text.
2. The visible text counts only if, trimmed, it looks like a URL or hostname: `/^(?:https?:\/\/)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:[\/:?#]\S*)?$/i`.
3. Compare `registrableDomain` of the text host and the `href` host (ignoring `www.`). If they differ, fire. A visible hostname that is a subdomain of the same registrable domain as the `href` is not a mismatch.
4. Emit at most one `RedFlag`. `evidence` is `"text: X -> href: Y"` for the first mismatch.

All inner groups are negated classes with explicit length caps; the HTML pattern uses a lazy bounded `[^>]{0,500}?` before `href`.

---

### content.js

Signals: `urgency-en`, `credential-request`, `suspicious-attachment`, `prize-lottery`, `advance-fee-scheme`, `financial-info-request`, `unusual-payment-method`, `secrecy-pressure`, `code-sharing-request`, `mistaken-payment`, `remote-access-request`, `delivery-scam`, `seed-phrase-request`, `investment-guarantee`, `task-job-scam`, `official-fine-threat`, `recruiter-bait`, `utility-disconnection-threat`, `payment-failed-lure`, `account-security-lure`, `unfamiliar-link-pressure`, `tech-support-scam`. All Content, English text only. `detectContent(input, brands)` also returns `jobFee` (Requirement 2.36a). Every signal except `suspicious-attachment` produces `cursedPhrases`. Flags are emitted in that order. Cursed phrases are collected in the same order (urgency, credential, then the scam signals), de-duplicated by lowercase text and limited to `MAX_CURSED_PHRASES` (20).

**Normalization (`util/normalize.js`, Requirement 2.21).** All phrase signals match a normalized copy of the input: NFKC per base character plus its combining marks, lowercase, zero-width and control characters dropped, each whitespace run collapsed to one `" "` (or `"\n"` if it held a line break, so sentence boundaries survive), leetspeak mapped inside tokens of letters/digits/`@`/`$` that contain a letter (`LEET_MAP`: @→a, 0→o, 1→i, $→s, 3→e, 5→s; tokens with a currency symbol next to a digit, number-first tokens such as "10am" or "$1million" and letters+number codes such as "mp3" are left alone), and `SPACED_LETTERS_MIN` (4) or more single letters separated by single spaces joined. Every normalized character keeps the [start, end) span of the original characters it came from, so `toOriginal(start, end)` maps a match back and evidence/cursed phrases are slices of the original input. A second string, `cased`, has the same length and offsets but keeps letter case and leet symbols; the case-sensitive PIN/OTP regex runs on it. The attachment check, like the link and identity detectors, reads the raw input. Every step is one linear pass.

Phrase lists are compiled the same way everywhere: each phrase is regex-escaped, single spaces become `\s+`, an apostrophe also accepts the typographic `’`, and the phrases are joined with `|` inside `\b(?:...)\b` with the `gi` flags.

#### urgency-en (weight `W_URGENCY_EN` = 15)

```js
/\b(?:act\s+now|verify\s+immediately|account\s+(?:will\s+be\s+|has\s+been\s+)?suspended|confirm\s+your\s+details|limited\s+time|expires\s+today|click\s+here\s+immediately|immediate\s+action\s+required)\b/gi
```

Each match becomes a `CursedPhrase` with a reason such as "Scammers rush you so you do not stop to check." One `RedFlag` per message; `evidence` is the first match. (`\s+` sits between fixed words only, so there is no nested quantifier.)

#### credential-request (weight `W_CREDENTIAL_REQUEST` = 20)

**Round 3 (replaces the single keyword pass below).** Three kinds of match: (1) `CREDENTIAL_ACTION_RE` (`(re-)verify/validate your account|identity|mailbox|login`, `confirm your identity|login`); (2) `CREDENTIAL_LOGIN_RE`, "log in" / "sign in" not preceded by a `LOGIN_NOUN_BEFORE` word and not followed by a `LOGIN_NOUN_AFTER` word; (3) a bare credential word (`passwords?|passcode|username|one-time code|password`, or uppercase `PIN|OTP`) that counts only when `CREDENTIAL_REQUEST_VERBS` appears in the same sentence within `CREDENTIAL_REQUEST_PROXIMITY_CHARS` (80) before it (a sentence ends at `!`, `?`, a newline or a `.` followed by whitespace, so "4.99" and "secure.example" do not end it), or when it is directly followed by please/pls/plz. Negated-request and delivered-code spans still remove matches. The original passes, kept for reference:

Case-insensitive pass:

```js
/\b(?:password|passcode|log\s*in|sign\s+in|username|one[- ]time\s+(?:code|password)|verify\s+your\s+(?:account|identity)|confirm\s+your\s+identity)\b/gi
```

Case-sensitive pass (uppercase only, so the ordinary word "pin" never fires):

```js
/\b(?:PIN|OTP)\b/g
```

Each match becomes a `CursedPhrase`. One `RedFlag` per message.

#### suspicious-attachment (weight `W_SUSPICIOUS_ATTACHMENT` = 20)

```js
/(?<![\/\w@.-])(\w[\w.-]{0,100})\.(exe|scr|vbs|bat|cmd|js|lnk|iso|img)(?=["'\s),;!?]|\.(?:\s|$)|$)/gi
```

- The lookbehind blocks matches inside URL paths (`/app.js`) and mid-word starts.
- The terminator requires whitespace, a quote, `)`, `,`, `;`, `!`, `?`, a sentence-ending dot, or end of text. A following `.` plus another label does not match, so `blog.bat.example` does not fire.
- **Allowlist**: when the extension is `js` and the base name (lowercased) is in `JS_LIBRARY_ALLOWLIST` (`node`, `react`, `vue`, `next`, `nuxt`, `express`, `angular`, `d3`, `three`), skip it. "I work with Node.js" does not fire.
- One `RedFlag` per message; `evidence` is the first matched filename. This signal produces no cursed phrase.

#### Shared building blocks for the scam signals

```js
NEAR         = `(?:[^.!?\n]|(?<=\d)\.(?=\d)){0,60}?`  // REQUEST_PROXIMITY_CHARS: same sentence, bounded; "$4.99" is not a sentence end
NOT_GOVERNED = `(?<!\b(?:never|not|don['’]t|won['’]t|can['’]t|cannot)\b(?:\s+(?:ever|ask|you|to|will|...)){0,4}\s+)`
               // NEGATION_WORDS + NEGATION_HELPER_WORDS, at most NEGATION_GOVERNED_MAX_WORDS helpers
MONEY       = `(?:(?:\$|£|€|\b(?:us\$|usd|gbp|eur)\s{0,3})\d[\d,.]{0,15}\s{0,3}(?:million|billion)\b`
            + `|\b\d[\d,.]{0,15}\s{0,3}(?:million|billion)\s+(?:dollars|pounds|euros)\b)`
```

Every gap is a negated class with an explicit upper bound, so each start position does a bounded amount of work and matching is linear in the input length. Stopping at `.`, `!`, `?` and line breaks keeps the verb and the term in the same sentence, so "Please confirm your appointment. We accept every credit card." does not fire. The two NEAR alternatives never match the same character, so it stays linear. The negation lookbehind is bounded too, and only matches when the negation directly governs the verb: "We will never ask you to share your card number" is skipped, "Do not delay, enter your card number" is not (the comma and "delay" break the chain).

**Negated request spans.** `NEGATION + helpers{0,4} + (request or share verb) + up to 60 characters of the same sentence` marks a warning clause. Credential words that start inside such a clause ("Do not share your PIN", "never ask you to share your card number, PIN or password") do not count for `credential-request`.

**Word gaps.** The secret-code and secret-request rules count the verb -> object gap in words, not characters: `(?:,?\s(?!STOP\b)[a-z0-9'’-]{1,20}){0,N}?,?\s`, where `STOP` is `GAP_STOP_WORDS` (if, whether, when, how, why, what, where, about, after, before, once, unless, because). Word characters, commas and spaces are disjoint classes and N is a constant (8 for code sharing, 5 for secret requests), so each start position does bounded work. Commas are allowed so a list ("your password, PIN and OTP") stays one gap; a clause-opening word ends it ("Tell us if you did not get your OTP").

**Delivered codes.** `(DELIVERED_CODE_TERMS)(\s+is\s*:?|\s*:)\s*\d{4,10}\b` ("Your OTP is 482913") marks a notice. Credential words that start inside it do not count for `credential-request`, the same way as negated request spans.

**Pairing across sentences.** `code-sharing-request` (code mention, then "forward it to us" within 100 characters) and `mistaken-payment` (claim, then return request within 200 characters) match the two parts separately and pair them in one forward pass over the two sorted match lists, so no regex spans more than one bounded gap.

#### prize-lottery (weight `W_PRIZE_LOTTERY` = 25)

Three patterns; the earliest match is the evidence and every match is a `CursedPhrase`:

1. `PRIZE_PHRASES`: "you have won", "you've won", "you are the winner", "you're the winner", "lucky winner", "claim your prize", "lottery", "jackpot", "free gift".
2. `\b(?:congratulations|congrats)\b(?=[\s\S]{0,60}?\b(?:won|winner|selected|prize|lottery|jackpot)\b)`. The lookahead keeps the cursed phrase to the greeting itself. "Congratulations on your new job!" does not fire.
3. `MONEY`: a large amount with a currency marker ("$1 million", "USD 2.5 billion", "5 million dollars"), or the same written in digits with at least two ",000" groups ("$1,000,000", "USD 15,500,000"). "2 million residents" and "1,000,000 reasons" do not fire.
4. Easy-money promises (also in `PRIZE_PHRASES`): "claim your free/reward", "you have been chosen", "guaranteed returns/profit/income/loan/approval", "zero risk", "risk-free", "double your money", "no experience needed/required", and `\b\d{2,4}\s?%\s+(?:returns?|profits?|gains)\b` ("400% returns"; "4% interest" does not fire).

#### advance-fee-scheme (weight `W_ADVANCE_FEE_SCHEME` = 25)

1. `ADVANCE_FEE_PHRASES`: "inheritance", "unclaimed funds", "unclaimed fund", "unclaimed money", "beneficiary", "processing fee", "release fee", "clearance fee", "pay a small fee to receive".
2. `\btransfer\s+of\s+(?:the\s+sum\s+of\s+)?` + `MONEY` ("transfer of $4.5 million").
3. More phrases: "next of kin", "dormant account", "unclaimed deposit/estate/assets", "release the funds", "funds are/will be released", "redelivery fee", "customs fee/charge", "clearance/release charge", "activation fee", "upfront fee".
4. A fee as a condition (`ADVANCE_FEE_TERMS` = fee, charge, cost, deposit, duty): "unpaid/outstanding/overdue ... FEE", "FEE ... is/are required/outstanding/pending/unpaid", "just/only/simply pay/cover/send/settle ... FEE", "small ... FEE", "FEE ... to receive/release/redeliver/reschedule/unlock/activate/claim/process/dispatch", "FEE ... before ... released/delivered/dispatched/processed/activated/transferred", "FEE ... upfront/up front/in advance". Each gap is bounded (30-40 characters, same sentence). A bare fee ("Delivery fee: $3.99", "Send the delivery fee through your mobile wallet") does not fire.

#### financial-info-request (weight `W_FINANCIAL_INFO_REQUEST` = 30)

```js
NOT_NEGATED + \b(?:enter|provide|send|share|confirm|verify|update|reply\s+with|give|submit|type)\b + NEAR +
\b(?:credit\s+card|debit\s+card|card\s+number|card\s+details|cvv|cvc|expiry\s+date|expiration\s+date|
     bank\s+account|bank\s+details|account\s+number|routing\s+number|ssn|social\s+security)\b
```

The same regex also accepts the reverse order, `TERM + NEAR + NOT_GOVERNED + VERB` ("Card number and CVV: send them now"), still within one sentence and 60 characters. A term alone ("Thanks for paying by credit card") never fires. A verb directly governed by a negation is skipped, so a bank's warning "We will never ask you to share your card number" does not fire. The evidence is the whole span, e.g. `Enter your credit card`.

#### unusual-payment-method (weight `W_UNUSUAL_PAYMENT_METHOD` = 20)

```js
NOT_GOVERNED + \b(?:pay|paying|payment|send|sending|transfer|buy|buying|purchase|pick\s+up|get|deposit|settle|return)\b + NEAR +
\b(?:gift\s+card|giftcard|itunes\s+card|itunes\s+gift\s+card|google\s+play\s+card|google\s+play\s+gift\s+card|
     bitcoin|btc|crypto|cryptocurrency|usdt|usdc|ethereum|wire\s+transfer|western\s+union|moneygram)s?\b
```

A mobile wallet is an ordinary way to pay, so it only counts when a fee is part of the request: `PAYMENT_VERB + NEAR + (WALLET + NEAR + FEE | FEE + NEAR + WALLET)`, where `WALLET` is `mobile wallet|mobile money|e-wallet|ewallet` and `FEE` is `fees?`. "wire the money/funds/payment/amount" also fires.

The detector also returns `paymentInstruction` (not a signal): `NOT_GOVERNED + (send|pay|transfer|wire|deposit) + up to 40 chars + to (me|us|my|our|this|the following|the name|the account|the wallet|the address)`, or `(send|give|read|text) (me|us) [the|a] [word] (code|number|pin|picture|photo)s?`. `blend` uses it for floor 4.12.

#### secrecy-pressure (weight `W_SECRECY_PRESSURE` = 10)

`SECRECY_PHRASES`: "do not tell anyone", "don't tell anyone", "do not tell anybody", "don't tell anybody", "keep this confidential", "keep this secret", "keep this between us", "keep it confidential", "keep it secret", "do not share this with anyone", "don't share this with anyone", "do not discuss this with anyone". Also `(do not|don't|please don't|please do not) (tell|discuss this with|discuss it with|mention this to|mention it to) (your family|your kids|your children|your parents|your bank|your husband|your wife|your partner|your friends|family|mom|dad|mum)`.

#### code-sharing-request (weight `W_CODE_SHARING_REQUEST` = 30)

1. `NOT_GOVERNED + (reply with|send|share|forward|tell|give|read|text) + NEAR + CODE`, where `CODE` is `CODE_TERMS` (verification/security/confirmation/login/sign-in/access/SMS code, one-time code/password/passcode, passcode) or `\d{1,2}[- ]digit [word] code`.
2. A `CODE` mention followed within `CODE_PRONOUN_PROXIMITY_CHARS` (100, may cross a sentence end) by `NOT_GOVERNED + share verb + (it|this|that|them) [back] to (us|me)`. The evidence is the hand-over phrase.

"Enter the code" never fires (that is how real one-time codes are used). "OTP" is left to `credential-request` so "Send the OTP" is not counted twice. `CODE` also includes `code (that)? (we|i) (just)? (texted|sent|messaged|emailed)` ("the code we texted you").

3. Secret-code family (`SECRET_CODE` = `SECRET_CODE_TERMS` (otp, otp code, 2fa code, 2-step code, two-factor code, authentication/authenticator code, plus `CODE_TERMS`) | `PIN` | `CODE`), with an explicit hand-over:
   - `NOT_GOVERNED + HAND_OVER_VERB + \s+ RECIPIENT + WORD_GAP(8) + SECRET_CODE` ("Send us your password and otp")
   - `NOT_GOVERNED + HAND_OVER_VERB + WORD_GAP(8) + SECRET_CODE + up to 30 chars + to RECIPIENT` ("send your OTP to this number")
   - `NOT_GOVERNED + (reply with|respond with) + WORD_GAP(8) + SECRET_CODE` ("Reply with your PIN")
   `PIN` = `(,\s?|\b(your|account|card|banking|atm|and|or)\s+)pin\b | \bpin\s+(code|number)\b`, so "pin this post" and "send us the pin for the map" do not fire. The pronoun hand-over (rule 2) also accepts a `SECRET_CODE` mention ("Your OTP is 4821. Please send it to us").

The detector also returns `secretRequest` (not a signal, floor 4.16): `(CLAUSE_START | INSTRUCTION_MODAL\s+) + LEAD_INS{0,2} + SECRET_REQUEST_VERB + [\s+RECIPIENT] + WORD_GAP(5) + SECRET_TERM`, where `CLAUSE_START` is a lookbehind for the text start or `[.!?:;,("“\n]` plus an optional space, `LEAD_INS` are please/kindly/just/simply/now/so/then/and/also/quickly, and `SECRET_TERM` is a password/passcode/login details/security answer/memorable word term (not after new/temporary/strong, not before reset/hint/manager/...) or `PIN`. A negation cannot sit between the clause start and the verb, so "Never share your password" and "You must not send us your password" do not match.

#### mistaken-payment (weight `W_MISTAKEN_PAYMENT` = 25)

A claim (`(accidentally|mistakenly|wrongly) (sent|transferred|paid|credited|deposited)`, `(sent|...) + NEAR + (by mistake|by accident|in error|accidentally|mistakenly)`, `duplicate payment`, `overpaid`, `overpayment`) followed within `MISTAKE_PROXIMITY_CHARS` (200) by a governed-negation-free return request (`RETURN_REQUESTS`: "send it back", "send the money back", "return the excess/amount/difference/money", "refund it", "refund the", "pay it back", "transfer it back", "transfer it to"). Both parts become cursed phrases; the claim is the evidence.

#### remote-access-request (weight `W_REMOTE_ACCESS_REQUEST` = 25)

Also: `NOT_GOVERNED` + `REMOTE_NAMED_VERBS` + `NEAR` + `REMOTE_TOOL_NAMES` ("install AnyDesk", "open TeamViewer"), so a named tool needs no "remote" or "access" word.

`NOT_GOVERNED + (install|download|run|open) + NEAR + (remote|screen-sharing) + up to 30 chars + (tool|app|application|software|program)`, or `(give|grant|allow) + NEAR + [remote] (access|control) (to|of) your (computer|pc|device|laptop|phone|screen)`, or `remote (access|control) (to|of) your (...)`. No floor: with a virus alarm (`urgency-en`) it reaches 40.

#### Scam families (Requirement 2.26-2.31)

Each family collects cue matches on the normalized text with bounded patterns and fires only when the required cues are all present; links come from `findLinks(input)`. Evidence is the first lead cue; every cue becomes a cursed phrase with the family's reason. Money uses `NUM = (?<![\d,.])\d[\d,.]{0,12}k?` with a currency marker (`MONEY_SYMBOLS` $ £ € ₹ before, or `MONEY_CODES` usd/usdt/bdt/tk/taka/... after; the taka sign is in the Bengali block, so the engine stays English-only and uses the codes).

| Signal | Weight | Fires when |
|---|---|---|
| `delivery-scam` | 25 (30 with a shortener) | `DELIVERY_FAILURE_RE` (not-delivered phrase, item + failed state, bad-address phrase, or `NOT_GOVERNED` update verb + delivery details) AND a `DELIVERY_CONTEXT_WORDS` word AND a link |
| `seed-phrase-request` | 35 | `NOT_GOVERNED` + not after can/could/will/able to + `SEED_REQUEST_VERBS` + NEAR + seed term or "N-word"; OR (with a link) `WALLET_FIX_VERBS` + [your] [word] + wallet word |
| `investment-guarantee` | 25 | a promise (not after `PROMISE_NEGATIONS`): promise phrase, guaranteed/assured + [word] + result word, "turn/grow $X into $Y", "N% daily/weekly"; AND an `INVESTMENT_CONTEXT_PHRASES` match outside the promise |
| `task-job-scam` | 25 | WORK + one of PAY/EASY/REPLY, or PAY + EASY + REPLY |
| `official-fine-threat` | 25 | `FINE_TERMS` AND a `NOT_GOVERNED` pay verb AND pressure (deadline, "today/immediately...", legal threat, "to avoid ...") AND a link |
| `recruiter-bait` | 20 | recruiter intro or title AND `JOB_WORDS` AND a document (`JOB_DOC_WORDS` or a doc part in the link) AND a link outside `RECRUITER_TRUSTED_DOMAINS` |
| `utility-disconnection-threat` | 25 | `DISCONNECT_RE` AND `UTILITY_WORDS` AND `UNPAID_RE` AND (a link OR `PAY_NOW_RE`) |
| `payment-failed-lure` | 25 | `PAYMENT_FAILED_RE` AND `PAYMENT_UPDATE_RE` AND a link AND (a suspicious link OR `URGENCY_DEADLINE_RE` OR `ACCOUNT_THREAT_RE`) |
| `account-security-lure` | 25 | a suspicious link AND `LOGIN_ALERT_RE` AND `SECURE_ACTION_RE` |
| `unfamiliar-link-pressure` | 25 | a link with `isUnfamiliarDomain` (util/lure.js) AND `PRESSURE_RE` outside hostnames and paths |
| `tech-support-scam` | 30 | `TECH_SCARE_RE` (not after if/whether/in case in the same clause) AND `TECH_HOOK_RE` (call + support word, or install/open/allow + a named remote tool or remote session) |
| `advance-fee-scheme` (job fee) | 25 | job context (`JOB_RE`, `RECRUITER_RE`, `JOB_CONTEXT_EXTRA`) AND (`JOB_FEE_RE` OR (`JOB_SLOT_RE` AND an amount)); sets `jobFee` |
| `task-job-scam` (remote path) | 25 | `REMOTE_WORK_RE` AND `REMOTE_PAY_RE` AND `NO_EXPERIENCE_RE` AND (`CHAT_APP_RE` OR the REPLY cue) |

#### urgency-en phrase families

Besides `URGENCY_EN_PHRASES` (10 phrases, unchanged): `URGENCY_EXTRA_PHRASES` ("urgent", "urgently", "final notice", "final warning", "pay now", "security breach", "virus(es) detected", "infected with", "or it will be returned/deleted/closed"); "to avoid" + `URGENCY_AVOID_THREATS`; `LOCKABLE_THINGS` [one word] `LOCK_STATE_VERBS` `LOCKED_WORDS` and `LOCKED_WORDS your LOCKABLE_THINGS`; `DEVICE_WORDS (has been|have been|is|was|may be) (infected|hacked|compromised)`; `within [the next] \d{1,3} (hours|hour|hrs|minutes|mins)`; and, not right after a `DEADLINE_NOT_AFTER` word (expires, arrives, processed, shipped, ready, back to you...), `within [the next] \d{1,3} (hr|days|day)` and `in [the next] \d{1,3} (hours|hour|hrs|hr)`; "limited spots/slots", "spots/slots left"; `only \d{1,3} (spots|places|slots|seats) (left|remaining)`; `IMMEDIACY_VERBS + up to 40 chars (same sentence) + (immediately|right away|asap)`.

`credential-request` now also matches "passwords".

---

### auth-headers.js

Signals: `spf-fail`, `dkim-fail`, `dmarc-fail`. All Identity/Auth. Returns an empty `cursedPhrases`.

1. **Unfold** header lines first: `text = input.replace(/\r?\n[ \t]+/g, " ")`, so a header folded over several lines is one line.
2. **Authentication-Results**: find lines with `/^Authentication-Results[ \t]*:[^\n]{1,2000}/gim`. Inside each, search `/\b(spf|dkim|dmarc)\s*=\s*(fail|softfail|permerror)\b/gi`. Map `spf` to `spf-fail`, `dkim` to `dkim-fail`, `dmarc` to `dmarc-fail`.
3. **Received-SPF fallback**: `/^Received-SPF[ \t]*:[ \t]*(fail|softfail)\b/gim` also fires `spf-fail`.
4. **DKIM-Signature must never fire**: that header carries a signature, not a result.
5. Each of the three signals emits at most one `RedFlag`. `evidence` is the matched fragment, for example `dkim=fail`.

All patterns use bounded negated classes and line anchors, so matching is linear.

---

## Plain-English Explanations

Every `RedFlag.explanation` is non-empty, jargon-free, and says what was found and why it is suspicious. `{e}` is the evidence. None of them claims anything is safe.

| id | explanation template |
|---|---|
| typosquatting | The web address "{e}" looks almost like a well-known company's address but is spelled slightly differently. Scammers use look-alike addresses to make a fake site look real. |
| homograph-punycode | The web address "{e}" uses unusual characters that imitate normal letters. Scammers use them to make a fake address look genuine. |
| display-name-mismatch | The sender's name claims to be a company, but the email address it came from belongs to someone else. Scammers pretend to be companies this way. |
| spf-fail | The email failed the check that confirms the sender is allowed to use that address. This often means the sender is faking who they are. |
| dkim-fail | The email's tamper-proof stamp did not check out, so the message may have been faked or changed on the way to you. |
| dmarc-fail | The sender's own safety rules say this message should not be trusted, which suggests it is not really from them. |
| raw-ip-url | The link "{e}" goes to a string of numbers instead of a normal website name. Real companies almost never do this, and scammers use it to hide where the link leads. |
| risky-tld | The link "{e}" ends in an address ending that is often used by throwaway scam websites. This alone is not proof, but be careful. |
| link-text-mismatch | The link shows one website but actually opens a different one ({e}). Scammers do this to hide the real destination. |
| urgency-en | The message pressures you to act quickly ("{e}"). Scammers rush people so they do not stop to check. |
| credential-request | The message asks for a password, PIN or one-time code ("{e}"). Real companies do not ask for these in messages. |
| suspicious-attachment | The message mentions a file called "{e}", a type of file that can install harmful programs. Do not open it unless you are sure who sent it. |
| prize-lottery | The message says you have won a prize or a large sum of money, or promises guaranteed or easy money ("{e}"). Scammers promise prizes and big returns so you hand over money or personal details. You cannot win a draw you never entered. |
| advance-fee-scheme | The message talks about an inheritance, unclaimed money, or a fee you must pay first to receive money, a parcel, a loan or a job ("{e}"). This is a well-known scam: you pay the fee and the promised thing never arrives. |
| financial-info-request | The message asks you to give your card or bank details ("{e}"). Real banks and shops do not ask for these in a message, and anyone who has them can take your money. |
| unusual-payment-method | The message asks you to pay with gift cards, cryptocurrency or a money-transfer service ("{e}"). Scammers ask for these because the money is hard to trace and almost never comes back. |
| secrecy-pressure | The message tells you to keep it secret ("{e}"). Scammers do this so nobody you trust can warn you. |
| code-sharing-request | The message asks you to pass on a code that was sent to you ("{e}"). That code is the key to your account: whoever has it can sign in as you or approve payments. |
| mistaken-payment | The message says money was sent to you by mistake and asks you to send it back ("{e}"). This is a common trick: the first payment is fake or gets reversed, and the money you send is lost. |
| remote-access-request | The message asks you to install a remote-control program or give someone access to your device ("{e}"). Whoever controls your device can see your screen, your passwords and your bank. |
| defanged-link | The link "{e}" is written in a disguised way (for example "[.]" or "dot" instead of a dot). Scammers do this to slip links past spam filters. Treat it like a real link and do not open it. |
| delivery-scam, seed-phrase-request, investment-guarantee, task-job-scam, official-fine-threat, recruiter-bait, lookalike-lure-domain, utility-disconnection-threat, payment-failed-lure, account-security-lure, unfamiliar-link-pressure, tech-support-scam | See `EXPLANATION_TEMPLATES` in `config.js`: each says what the message does, quotes the evidence, and says why it is a known scam pattern. |

Cursed-phrase reasons (`CURSED_PHRASE_REASONS`):

| id | reason |
|---|---|
| urgency-en | This phrase tries to rush you. Scammers rush people so they do not stop to check. |
| credential-request | This asks for a password, PIN or one-time code. Real companies do not ask for these in messages. |
| prize-lottery | This promises a prize, a big sum of money or guaranteed income. Scammers use these as bait. |
| advance-fee-scheme | This talks about money or goods waiting for you, or a fee to release them. The fee is the scam. |
| financial-info-request | This asks for card or bank details. Real companies do not ask for these in messages. |
| unusual-payment-method | This asks for payment that is hard to trace or get back, such as gift cards or cryptocurrency. |
| secrecy-pressure | This asks you to keep a secret, so nobody can warn you it is a scam. |
| code-sharing-request | This asks you to pass on a code sent to you. Never give these codes to anyone. |
| mistaken-payment | This claims money was sent to you by mistake and asks for it back. The first payment is usually fake. |
| remote-access-request | This asks for control of your device. Never let a stranger connect to it. |
| delivery-scam | This is the classic fake delivery problem. Check the parcel in the courier's own app, not through a link. |
| seed-phrase-request | This asks for your wallet recovery words. Whoever has them owns your crypto. |
| investment-guarantee | This promises certain or multiplied profit. Real investments never guarantee returns. |
| task-job-scam | This offers easy money for simple online tasks. These jobs end with you paying them. |
| official-fine-threat | This demands a fine or tax through a link, with a threat. Officials do not collect fines this way. |
| recruiter-bait | This is an unsolicited job offer with a link to a document. Check the recruiter before opening it. |
| utility-disconnection-threat | This threatens to cut off a utility unless you pay now. Check your bill in the official app. |
| payment-failed-lure | This claims a payment failed and asks for your card details again. Use the official app instead. |
| account-security-lure | This is a sign-in alert that sends you to a fake page. Check your account in the official app. |
| unfamiliar-link-pressure | Pressure to act through a link to an unfamiliar website. Go to the official site yourself. |
| tech-support-scam | A fake virus or security scare that tells you to call support or install a remote app. |

---

## Correctness Properties

*A property is a characteristic that should hold across all valid executions. Properties bridge the human-readable requirements and machine-checked guarantees.*

**P1: Non-string input rejection.** For any non-string value (number, boolean, null, undefined, object, array, symbol), `score(value)` throws `TypeError`. *Validates 1.3.*

**P2: Input length boundary.** For any string longer than 4000 characters, `score` throws `RangeError`; for any string of length <= 4000 it does not throw because of length. *Validates 1.4.*

**P3: Invalid l3Score rejection.** For any `l3Score` that is not null/undefined and not an integer in [0, 100] (NaN, Infinity, floats, negatives, > 100, strings), `score("hi", { l3Score })` throws `RangeError`. *Validates 1.5.*

**P4: Options default equivalence.** For any valid input, `score(input)`, `score(input, undefined)`, `score(input, null)`, `score(input, {})` and `score(input, { l2Hit: false, l3Score: null })` return deeply equal results. *Validates 1.2.*

**P5: Determinism.** For any valid `(input, options)`, two calls return deeply equal results, and repeated calls never change later results (no shared state). *Validates 1.6, 1.7.*

**P6: RiskResult shape.** For any valid call the result has exactly the fields `riskScore` (integer 0-100), `verdict`, `redFlags` (array), `cursedPhrases` (array), `confidence`. *Validates 1.8, 3.1.*

**P7: RedFlag shape.** Every `redFlags` entry has a non-empty string `id`, a positive numeric `weight`, a non-empty string `evidence`, and a non-empty string `explanation` that contains no claim of safety. *Validates 2.2, 7.1, 7.2, 7.3, 8.2.*

**P8: CursedPhrase shape and population.** Every entry has non-empty `text` and `reason`, and `text` occurs in the input. `cursedPhrases` is non-empty exactly when a phrase-producing signal fired (every Content signal except `suspicious-attachment`). *Validates 3.2, 3.3, 3.4.*

**P9: One flag per signal.** The `id`s in `redFlags` are pairwise distinct. *Validates the one-flag-per-signal rule.*

**P10: Safety floor.** If `redFlags` is non-empty then `riskScore > 0`. *Validates 8.1.*

**P11: Verdict consistency.** `result.verdict === verdictFor(result.riskScore)`. *Validates 5.5.*

**P12: Confidence.** `confidence` is `"limited"` when `l3Score` is null or absent and `"full"` when it is a valid integer; never any other value. *Validates 6.1, 6.2, 11.7.*

**P13: blend range.** For any valid `blend` inputs (l1 integer 0-100, l2Hit boolean, l3 integer 0-100 or null, flags Array or Set of strings), the result is an integer in [0, 100]. *Validates 4.13, 11.1.*

**P14: Pure-L1 floor.** With `l2Hit = false` and `l3Score = null`, `blend(...) >= l1Score`. *Validates 4.3, 11.2.*

**P15: 0.8 x L1 floor.** For all valid inputs, `blend(...) >= Math.round(0.8 * l1Score)`. *Validates 4.4, 11.3.*

**P16: L2 floor.** With `l2Hit = true`, `blend(...) >= 90`. *Validates 4.1, 11.4.*

**P17: blend determinism and representation independence.** Two identical calls return the same value, and passing flags as an Array or as a Set returns the same value. *Validates 11.5.*

**P18: Hard floors.** For any valid blend inputs: `typosquatting` + `credential-request` gives >= 70; `raw-ip-url` + `credential-request` gives >= 70; (`spf-fail` or `dkim-fail`) + `display-name-mismatch` gives >= 60; `credential-request` + `urgency-en` gives >= 55; `suspicious-attachment` gives >= 40; (`prize-lottery` or `advance-fee-scheme`) + (`financial-info-request` or `unusual-payment-method`) gives >= 70; `financial-info-request` gives >= 50; `unusual-payment-method` + (`urgency-en` or `secrecy-pressure`) gives >= 40; `code-sharing-request` gives >= 50; `mistaken-payment` gives >= 40; `context.secretRequest` gives >= 45. *Validates 4.5-4.12, 4.14-4.16.* Floors 4.17-4.22 (and "defanged-link / urgency-en alone have no floor") are unit tests in `blend.test.js`. (The 4.12 case with `context.paymentInstruction` and the "alone has no floor" case are unit tests in `blend.test.js`.)

**P19: verdictFor exhaustiveness.** For every integer 0-100 the result is exactly one of the three strings, with 0-30 `pookie`, 31-69 `skeptical`, 70-100 `poltergeist`. *Validates 5.1-5.4, 11.6.*

**P20: Robustness (ReDoS).** For arbitrary strings of length <= 4000, and for adversarial strings built from repeated fragments (`"a."`, `"<a "`, `"["`, `"http://"`, `"From: "`, `"-"`, long runs of one character, and repeated request verbs, payment verbs, negations, money fragments and "congratulations" for the content proximity patterns), `score` does not throw and returns within a generous time bound (500 ms per call; measured worst case is about 2 ms at 4000 characters). A fixed list of hand-built worst cases for every bounded-gap regex runs in the same test. *Validates 2.20.*

**P21: Scam signals.** For text built from scam and near-miss fragments (prize claims, card-detail requests, warnings that say "never share", gift-card and wallet payments, secrecy phrases), `score` returns an integer in [0, 100], is deterministic, and meets floors 4.10, 4.11, 4.14 and 4.15 whenever the matching flags fired, and 4.12 whenever `unusual-payment-method` fired together with a pressure signal. *Validates 2.15-2.19, 2.22, 2.23, 4.10-4.12, 4.14, 4.15.*

---

## Error Handling

| Condition | Error | Message |
|---|---|---|
| `input` is not a string | `TypeError` | `input must be a string` |
| `input.length > 4000` | `RangeError` | `input exceeds 4000 characters` |
| `l3Score` not null/undefined and not an integer 0-100 | `RangeError` | `l3Score must be an integer 0-100 or null` |

Nothing else throws. An empty string, a string with no signals, omitted or `null` options, and a non-boolean `l2Hit` (treated as false) all produce a valid `RiskResult`. Detectors do not perform I/O and never throw on odd text; a regex that does not match simply yields no flag.

---

## Testing Strategy

Vitest is the test runner and fast-check provides property-based testing (do not hand-roll property generators). Every property runs at least 100 iterations. All tests live in `backend/engine/test/`. Fixtures use only fictional brands and the reserved TLDs `.example`, `.test`, `.invalid`. Each property test carries a comment `// Feature: threat-scoring, Property N: <text>`.

### Golden tests (`golden.test.js`)

| # | Input (fixture) | Flags expected | L1 | Expected result |
|---|---|---|---|---|
| 1 | `Hi, lunch at 1pm tomorrow? Let me know.` | none | 0 | `pookie`, riskScore 0 |
| 2 | `Check your balance at http://bad.xyz/portal and enter your password.` | risky-tld, credential-request | 35 | `skeptical`, riskScore 35 (no floor applies) |
| 3 | `Your Galactibank account: log in at https://galact1bank.example/login to continue.` | typosquatting, credential-request | 55 | floor 4.5 gives `poltergeist`, riskScore 70 |
| 4 | `Enter your OTP at http://203.0.113.5/verify` | raw-ip-url, credential-request | 55 | floor 4.6 gives `poltergeist`, riskScore 70 |
| 5 | `From: Galactibank Support <noreply@mail-alerts.invalid>` + newline + `Authentication-Results: mx.example.test; spf=fail smtp.mailfrom=mail-alerts.invalid` + blank line + `Please review your statement.` | display-name-mismatch, spf-fail | 40 (capped from 45) | floor 4.7 gives riskScore 60, `skeptical` |
| 6 | `Meeting notes attached for review.` with `{ l2Hit: true }` | none | 0 | rule 4.1 gives `poltergeist`, riskScore 90 |
| 7 | `Please send your password.` with `{ l3Score: 80 }` | credential-request | 20 | rule 4.2: round(0.55 x 20 + 0.45 x 80) = 47, `skeptical`, confidence `full` |
| 8 | `Act now: please confirm your password.` | urgency-en, credential-request | 35 | floor 4.8 gives riskScore 55, `skeptical` |
| 9 | `Please open invoice.exe to see your order.` | suspicious-attachment | 20 | floor 4.9 gives riskScore 40, `skeptical` |
| 10 | `Click <a href="http://phish.invalid/offer">http://galactibank.example</a> to see it.` | link-text-mismatch | 35 | `skeptical`, riskScore 35 |
| 11 | `Congratulations! You have won $1 million. Enter your credit card details to get that money.` | prize-lottery, financial-info-request | 45 (capped from 55) | floor 4.10 gives `poltergeist`, riskScore 70 |
| 12 | `Hi, it's your manager. I need a quick favour: buy four Google Play gift cards of $100 each and send me the codes within the hour. Do not tell anyone, it's a surprise for the team.` | unusual-payment-method, secrecy-pressure | 30 | floor 4.12 gives riskScore 40, `skeptical` |
| 13 | `Dear friend, I am the lawyer of the late Mr Ostrander Vell, who left an inheritance with no heir. You are named as the beneficiary for the transfer of $4.5 million. To release the funds, pay the $300 clearance fee by wire transfer. Keep this confidential.` | prize-lottery, advance-fee-scheme, unusual-payment-method, secrecy-pressure | 45 (capped from 80) | floor 4.10 gives `poltergeist`, riskScore 70 |

Each golden test asserts the exact verdict, the riskScore (exact where the arithmetic above fixes it), the exact set of flag ids, that `cursedPhrases` is non-empty exactly when a content signal fired, and the expected `confidence`.

### Edge-case unit tests (same file or `unit.test.js`)

- `"I work with Node.js daily"` produces no `suspicious-attachment`.
- `"visit галактибанк.example"` (pure Cyrillic hostname) produces no `homograph-punycode`.
- `"http://bad.xyz/login"` produces `risky-tld` (trailing `/` accepted).
- `"bad.xyz.example"` does not produce `risky-tld`.
- `"http://203.0.113.5 click here"` produces `raw-ip-url` (space terminator).
- `"http://1.2.3.4.evil.example"` and `"http://999.1.1.1/"` do not produce `raw-ip-url`.
- `"http://[2001:db8::1]/"` produces `raw-ip-url`.
- `"visit xn--galctibnk-r8a.example"` produces `homograph-punycode`.
- `"visit gаlactibank.example"` (Cyrillic `а` U+0430) produces `homograph-punycode`.
- `"https://galact1bank.example/login"` produces `typosquatting`.
- `"http://galactibank.xyz"` produces `typosquatting` (exact label, wrong domain).
- `"https://galactibank-verify.example"` produces `typosquatting` (brand inside label).
- `"visit galactibank.example"` and `"https://login.galactibank.example"` (legitimate domain and subdomain) produce no flags.
- `"From: Galactibank Support <noreply@phish.invalid>"` produces `display-name-mismatch`.
- `Authentication-Results` folded over two lines with `dkim=fail` on the second line produces `dkim-fail`; a `DKIM-Signature:` header alone produces nothing; `Received-SPF: softfail` produces `spf-fail`.
- Input with several urgency phrases produces exactly one `urgency-en` flag (weight counted once) but several cursed phrases.
- `"please pin this post"` produces no `credential-request` (lowercase "pin").
- `score(123)` throws `TypeError`; `score("x".repeat(4001))` throws `RangeError`; `score("hi", { l3Score: 1.5 })` throws `RangeError`; `score("hi", null)` works.
- `l3Score` exactly 0 and exactly 100 are accepted; boundary scores 30/31 and 69/70 map to the right verdicts.
- Brand replacement: `score("http://zorbbank.example/x", { brands: [{ name: "zorbbank", domains: ["zorbbank.example"] }] })` produces no typosquatting, while a lookalike of that custom brand does.

### Scam-signal unit tests (`content.test.js`)

- Positives for every phrase in `PRIZE_PHRASES`, `ADVANCE_FEE_PHRASES` and `SECRECY_PHRASES`, plus the congratulations, money-amount, transfer-of, request-verb, payment-verb and wallet-fee patterns.
- Benign counterexamples that must stay `pookie` and never fire `financial-info-request`, `unusual-payment-method` or `advance-fee-scheme`: "Thanks for paying by credit card", "Your order has shipped and will arrive on Tuesday.", "Congratulations on your new job!", a Galactibank statement notice that says it will never ask for card or bank details, an appointment reminder asking to confirm attendance, a refund sent back to a debit card, "$2 billion for new parks", a gift card bought as a present, "Happy anniversary!", and a bank statement attachment notice.

### Scam-family tests (`scam-families.test.js`, `defang.test.js`)

- The six reference messages reach their targets (recruiter >= 50, investment >= 70, seed phrase >= 70, fine >= 60, task job >= 50, delivery >= 50) with their family signal; the ambiguous new-device sign-in notice has no flag.
- Three paraphrases per family fire the family signal and score >= 50.
- Negatives stay below 30: delivered/shipped notices, a due electricity bill, a full-time job ad, an OTP delivery, "Never share your 12-word recovery phrase", plus a near miss per family (warnings, "does not guarantee future returns", part-time cashier pay, a paid parking ticket receipt, a recruiter with no link, "arrives in 24 hours").
- Refang cases (brackets, "dot", hxxp, [:]), prose left alone, offsets mapped back, risky-tld/raw-ip/typosquatting on defanged links.

### Round 2 tests (`round2.test.js`)

- `lookalike-lure-domain`: weights 20/30, evidence is the host; one lure word, unhyphenated names, subdomains and brand domains do not fire; the round 2 TLDs fire `risky-tld`.
- Three paraphrases each for `utility-disconnection-threat`, `payment-failed-lure`, `account-security-lure`, the job fee (>= 60, `jobFee`) and the remote task-job path (>= 50), all written for the test file with fictional names.
- `account-security-lure` needs a suspicious link; utility needs a link or pay-now; the job-fee floor needs `advance-fee-scheme`.
- Negatives < 30: the six required ones (due electricity bill, subscription payment failed with an ordinary account link, new-device sign-in with no action, full-time job ad, OTP delivery, delivered parcel) plus near misses (planned maintenance, a 7-day grace period on the real domain, a sign-in alert with no link, "no registration fee", a monthly-salary remote role, one lure word, a declined card at a shop).

### Round 3 tests (`round3.test.js`)

- `credential-request`: notices (a password was changed/reset, a PIN was created, "Your OTP is 482913", "do not share", "if you did not make this change, contact us", "a login from a new device", "passwords are at risk") do not fire and stay < 30; urgency alone stays < 30; real requests (enter, reply with, read out/back, "Your PIN please", log in, re-validate) still fire, and "Send us your password and otp" is still 50.
- `unfamiliar-link-pressure`: four fictional scam paraphrases, each tested defanged and with normal dots (>= 50, the normal-dot versions without `defanged-link`); shortener, raw IP and risky TLD; the signal alone gives exactly 50; no fire without pressure, without a link, on a plain domain, or when the pressure word is only inside the domain; never on an allowlisted real domain; the five required negatives with normal links stay < 30.

### Tech-support tests (`tech-support.test.js`)

- Four fictional `tech-support-scam` paraphrases (with a phone number, with an error code, without a phone number via "download TeamViewer", and one with a link and a remote session) score >= 60.
- Legitimate security notices stay < 30: scan completed with no threats, virus definitions updated, a sign-in from a new device, "never install remote access software for strangers", "our support team is available at 16221", "if you think your account is at risk, contact our support team".
- The scare alone or the hook alone does not fire; `dev-s19` and `h4-s08` now score >= 50.
- `remote-access-request` fires on install/open/allow/download + a named tool and not on a mention or a negated instruction.

### Property tests (`property.test.js`)

P13-P19 drive `blend` and `verdictFor` directly. P1-P12 and P20 drive `score`.

Arbitraries:

- `l1Score`: `fc.integer({ min: 0, max: 100 })`
- `l2Hit`: `fc.boolean()`
- `l3Score`: `fc.oneof(fc.constant(null), fc.integer({ min: 0, max: 100 }))`
- `flags`: `fc.array(fc.constantFrom(...ALL_SIGNAL_IDS))` (27 ids), passed as an Array or wrapped in a `Set` (`fc.boolean()` chooses)
- invalid `l3Score`: `fc.oneof(fc.constant(NaN), fc.constant(Infinity), fc.constant(-Infinity), fc.double(), fc.integer({ max: -1 }), fc.integer({ min: 101 }), fc.string())`
- non-string input: `fc.oneof(fc.integer(), fc.boolean(), fc.constant(null), fc.constant(undefined), fc.array(fc.anything()), fc.object())`
- text input: `fc.string({ maxLength: 4000 })`, plus `fc.array(fc.constantFrom("a.", "<a ", "[", "http://", "From: ", "-", "xn--", " ")).map(a => a.join("")).filter(s => s.length <= 4000)` for P20

### Test isolation

Each test builds its data inline and shares no mutable state. Detector tests import detector functions directly. Property tests import `blend` and `verdictFor` from their own modules, bypassing `score.js`.
