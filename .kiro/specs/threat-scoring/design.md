# Design Document: threat-scoring

## Overview

The threat-scoring engine is a pure-JavaScript ES-module library in `packages/engine`. It accepts a text message (email body, SMS or URL) and returns a structured risk assessment (`RiskResult`). It has no I/O, no browser APIs and no Node.js built-ins, so it runs unchanged in browsers, Node.js, Deno and edge runtimes.

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
packages/engine/
  src/
    config.js
    brands.js
    util/
      hostname.js        (hostname extractors, registrable-domain and brand-legitimacy helpers)
      levenshtein.js     (edit distance)
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
export const W_URGENCY_BN            = 15;
export const W_CREDENTIAL_REQUEST    = 20;
export const W_SUSPICIOUS_ATTACHMENT = 20;
export const W_SPF_FAIL              = 20;
export const W_DKIM_FAIL             = 20;
export const W_DMARC_FAIL            = 15;

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
  "urgency-en": "content", "urgency-bn": "content",
  "credential-request": "content", "suspicious-attachment": "content",
};
export const RISKY_TLDS = ["xyz", "top", "click", "tk", "ml", "ga", "cf"]; // exactly Requirement 2.6
export const DANGEROUS_EXTENSIONS = ["exe", "scr", "vbs", "bat", "cmd", "js", "lnk", "iso", "img"];
export const JS_LIBRARY_ALLOWLIST = ["node", "react", "vue", "next", "nuxt", "express", "angular", "d3", "three"];
export const SECOND_LEVEL_LABELS = ["com", "co", "org", "net", "gov", "edu", "ac"]; // used with 2-letter country TLDs, e.g. com.bd, co.uk
export const URGENCY_EN_PHRASES = [ /* see content.js section */ ];
export const URGENCY_BN_PHRASES = [ /* see content.js section */ ];
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

**Safety floor.** The smallest single flag weight is 15, so any message with a flag has `l1Score >= 15`, and the `0.8 x l1Score` floor gives `riskScore >= 12 > 0` (Requirement 8.1). The engine never produces any wording that says a message is safe; `confidence: "limited"` tells the UI the result is a heuristics-only estimate (Requirement 8.3).

---

## blend.js

```
function blend(l1Score, l2Hit, l3Score, flags):
  const flagSet = new Set(flags)          // accepts Array or Set

  if l2Hit:                    risk = max(BLEND_L2_FLOOR, l1Score)                      // Rule 4.1
  else if l3Score !== null:    risk = BLEND_L1_WEIGHT * l1Score + BLEND_L3_WEIGHT * l3Score  // Rule 4.2
  else:                        risk = l1Score                                           // Rule 4.3

  risk = max(risk, BLEND_L1_FLOOR_FACTOR * l1Score)                                     // Rule 4.4

  if has("typosquatting") && has("credential-request"):   risk = max(risk, FLOOR_TYPOSQUAT_CRED)  // 4.5
  if has("raw-ip-url")    && has("credential-request"):   risk = max(risk, FLOOR_RAWIP_CRED)      // 4.6
  if (has("spf-fail") || has("dkim-fail")) && has("display-name-mismatch"):
                                                          risk = max(risk, FLOOR_AUTH_DISPLAY)    // 4.7
  if has("credential-request") && (has("urgency-en") || has("urgency-bn")):
                                                          risk = max(risk, FLOOR_CRED_URGENCY)    // 4.8
  if has("suspicious-attachment"):                        risk = max(risk, FLOOR_ATTACHMENT)      // 4.9

  return Math.round(Math.min(100, Math.max(0, risk)))                                   // 4.10
```

The 0.8 x L1 floor is applied before the hard floors; hard floors can only raise the score. Clamp and round are always last.

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

`\p{M}` (combining marks) is included so scripts with vowel signs, such as Bangla, form valid labels.

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
3. It does NOT fire for a hostname written entirely in one script (for example pure Bangla), because legitimate internationalized domains exist.
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

### link.js

Signals: `raw-ip-url`, `risky-tld`, `link-text-mismatch`. All Link. Returns an empty `cursedPhrases`.

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

Signals: `urgency-en`, `urgency-bn`, `credential-request`, `suspicious-attachment`. All Content. The first three produce `cursedPhrases`. Cursed phrases are de-duplicated by lowercase text and limited to `MAX_CURSED_PHRASES` (20).

#### urgency-en (weight `W_URGENCY_EN` = 15)

```js
/\b(?:act\s+now|verify\s+immediately|account\s+(?:will\s+be\s+|has\s+been\s+)?suspended|confirm\s+your\s+details|limited\s+time|expires\s+today|click\s+here\s+immediately|immediate\s+action\s+required)\b/gi
```

Each match becomes a `CursedPhrase` with a reason such as "Scammers rush you so you do not stop to check." One `RedFlag` per message; `evidence` is the first match. (`\s+` sits between fixed words only, so there is no nested quantifier.)

#### urgency-bn (weight `W_URGENCY_BN` = 15)

`URGENCY_BN_PHRASES` in `config.js` holds fixed Bangla phrases, for example:

- `আপনার অ্যাকাউন্ট স্থগিত হবে`
- `এখনই যাচাই করুন`
- `অবিলম্বে যাচাই`
- `এখনই সাড়া দিন`
- `অ্যাকাউন্ট বন্ধ হয়ে যাবে`

The regex is compiled from this list (regex-escaped, joined with `|`, single spaces replaced by `\s+`, `u` flag, no `\b` because it does not work for Bangla). Each match becomes a `CursedPhrase`. One `RedFlag` per message. Golden tests build their Bangla fixtures from these same constants, so a fixture and the pattern can never drift apart.

#### credential-request (weight `W_CREDENTIAL_REQUEST` = 20)

Case-insensitive pass:

```js
/\b(?:password|passcode|log\s*in|sign\s+in|username|one[- ]time\s+(?:code|password)|verify\s+your\s+(?:account|identity)|confirm\s+your\s+identity)\b/gi
```

Case-sensitive pass (uppercase only, so the ordinary word "pin" never fires):

```js
/\b(?:PIN|OTP)\b/g
```

Bangla terms (no `\b`): `পাসওয়ার্ড`, `ওটিপি`, `পিন নম্বর`.

Each match becomes a `CursedPhrase`. One `RedFlag` per message.

#### suspicious-attachment (weight `W_SUSPICIOUS_ATTACHMENT` = 20)

```js
/(?<![\/\w@.-])(\w[\w.-]{0,100})\.(exe|scr|vbs|bat|cmd|js|lnk|iso|img)(?=["'\s),;!?]|\.(?:\s|$)|$)/gi
```

- The lookbehind blocks matches inside URL paths (`/app.js`) and mid-word starts.
- The terminator requires whitespace, a quote, `)`, `,`, `;`, `!`, `?`, a sentence-ending dot, or end of text. A following `.` plus another label does not match, so `blog.bat.example` does not fire.
- **Allowlist**: when the extension is `js` and the base name (lowercased) is in `JS_LIBRARY_ALLOWLIST` (`node`, `react`, `vue`, `next`, `nuxt`, `express`, `angular`, `d3`, `three`), skip it. "I work with Node.js" does not fire.
- One `RedFlag` per message; `evidence` is the first matched filename. This signal produces no cursed phrase.

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
| urgency-en / urgency-bn | The message pressures you to act quickly ("{e}"). Scammers rush people so they do not stop to check. |
| credential-request | The message asks for a password, PIN or one-time code ("{e}"). Real companies do not ask for these in messages. |
| suspicious-attachment | The message mentions a file called "{e}", a type of file that can install harmful programs. Do not open it unless you are sure who sent it. |

---

## Correctness Properties

*A property is a characteristic that should hold across all valid executions. Properties bridge the human-readable requirements and machine-checked guarantees.*

**P1: Non-string input rejection.** For any non-string value (number, boolean, null, undefined, object, array, symbol), `score(value)` throws `TypeError`. *Validates 1.3.*

**P2: Input length boundary.** For any string longer than 4000 characters, `score` throws `RangeError`; for any string of length <= 4000 it does not throw because of length. *Validates 1.4.*

**P3: Invalid l3Score rejection.** For any `l3Score` that is not null/undefined and not an integer in [0, 100] (NaN, Infinity, floats, negatives, > 100, strings), `score("hi", { l3Score })` throws `RangeError`. *Validates 1.5.*

**P4: Options default equivalence.** For any valid input, `score(input)`, `score(input, undefined)`, `score(input, null)`, `score(input, {})` and `score(input, { l2Hit: false, l3Score: null })` return deeply equal results. *Validates 1.2.*

**P5: Determinism.** For any valid `(input, options)`, two calls return deeply equal results, and repeated calls never change later results (no shared state). *Validates 1.6, 1.7.*

**P6: RiskResult shape.** For any valid call the result has exactly the fields `riskScore` (integer 0-100), `verdict`, `redFlags` (array), `cursedPhrases` (array), `confidence`. *Validates 1.8, 3.1.*

**P7: RedFlag shape.** Every `redFlags` entry has a non-empty string `id`, a positive numeric `weight`, a non-empty string `evidence`, and a non-empty string `explanation` that contains no claim of safety. *Validates 2.17, 7.1, 7.2, 7.3, 8.2.*

**P8: CursedPhrase shape and population.** Every entry has non-empty `text` and `reason`, and `text` occurs in the input. When no credential-request, urgency-en or urgency-bn term occurs, `cursedPhrases` is empty. *Validates 3.2, 3.3, 3.4.*

**P9: One flag per signal.** The `id`s in `redFlags` are pairwise distinct. *Validates the one-flag-per-signal rule.*

**P10: Safety floor.** If `redFlags` is non-empty then `riskScore > 0`. *Validates 8.1.*

**P11: Verdict consistency.** `result.verdict === verdictFor(result.riskScore)`. *Validates 5.5.*

**P12: Confidence.** `confidence` is `"limited"` when `l3Score` is null or absent and `"full"` when it is a valid integer; never any other value. *Validates 6.1, 6.2, 11.7.*

**P13: blend range.** For any valid `blend` inputs (l1 integer 0-100, l2Hit boolean, l3 integer 0-100 or null, flags Array or Set of strings), the result is an integer in [0, 100]. *Validates 4.10, 11.1.*

**P14: Pure-L1 floor.** With `l2Hit = false` and `l3Score = null`, `blend(...) >= l1Score`. *Validates 4.3, 11.2.*

**P15: 0.8 x L1 floor.** For all valid inputs, `blend(...) >= Math.round(0.8 * l1Score)`. *Validates 4.4, 11.3.*

**P16: L2 floor.** With `l2Hit = true`, `blend(...) >= 90`. *Validates 4.1, 11.4.*

**P17: blend determinism and representation independence.** Two identical calls return the same value, and passing flags as an Array or as a Set returns the same value. *Validates 11.5.*

**P18: Hard floors.** For any valid blend inputs: `typosquatting` + `credential-request` gives >= 70; `raw-ip-url` + `credential-request` gives >= 70; (`spf-fail` or `dkim-fail`) + `display-name-mismatch` gives >= 60; `credential-request` + (`urgency-en` or `urgency-bn`) gives >= 55; `suspicious-attachment` gives >= 40. *Validates 4.5-4.9.*

**P19: verdictFor exhaustiveness.** For every integer 0-100 the result is exactly one of the three strings, with 0-30 `pookie`, 31-69 `skeptical`, 70-100 `poltergeist`. *Validates 5.1-5.4, 11.6.*

**P20: Robustness (ReDoS).** For arbitrary strings of length <= 4000, and for adversarial strings built from repeated fragments (`"a."`, `"<a "`, `"["`, `"http://"`, `"From: "`, `"-"`, long runs of one character), `score` does not throw and returns within a generous time bound (for example 500 ms per call). *Validates 2.16.*

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

Vitest is the test runner and fast-check provides property-based testing (do not hand-roll property generators). Every property runs at least 100 iterations. All tests live in `packages/engine/test/`. Fixtures use only fictional brands and the reserved TLDs `.example`, `.test`, `.invalid`. Each property test carries a comment `// Feature: threat-scoring, Property N: <text>`.

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
| 8 | Bangla phrase from `URGENCY_BN_PHRASES` (`আপনার অ্যাকাউন্ট স্থগিত হবে`) followed by ` OTP পাঠান।` | urgency-bn, credential-request | 35 | floor 4.8 gives riskScore 55, `skeptical` |
| 9 | `Please open invoice.exe to see your order.` | suspicious-attachment | 20 | floor 4.9 gives riskScore 40, `skeptical` |
| 10 | `Click <a href="http://phish.invalid/offer">http://galactibank.example</a> to see it.` | link-text-mismatch | 35 | `skeptical`, riskScore 35 |

Each golden test asserts the exact verdict, the riskScore (exact where the arithmetic above fixes it), the exact set of flag ids, that `cursedPhrases` is non-empty exactly when a content signal fired, and the expected `confidence`.

### Edge-case unit tests (same file or `unit.test.js`)

- `"I work with Node.js daily"` produces no `suspicious-attachment`.
- `"visit গালাক্তিব্যাংক.example"` (pure Bangla hostname) produces no `homograph-punycode`.
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

### Property tests (`property.test.js`)

P13-P19 drive `blend` and `verdictFor` directly. P1-P12 and P20 drive `score`.

Arbitraries:

- `l1Score`: `fc.integer({ min: 0, max: 100 })`
- `l2Hit`: `fc.boolean()`
- `l3Score`: `fc.oneof(fc.constant(null), fc.integer({ min: 0, max: 100 }))`
- `flags`: `fc.array(fc.constantFrom(...ALL_13_SIGNAL_IDS))`, passed as an Array or wrapped in a `Set` (`fc.boolean()` chooses)
- invalid `l3Score`: `fc.oneof(fc.constant(NaN), fc.constant(Infinity), fc.constant(-Infinity), fc.double(), fc.integer({ max: -1 }), fc.integer({ min: 101 }), fc.string())`
- non-string input: `fc.oneof(fc.integer(), fc.boolean(), fc.constant(null), fc.constant(undefined), fc.array(fc.anything()), fc.object())`
- text input: `fc.string({ maxLength: 4000 })`, plus `fc.array(fc.constantFrom("a.", "<a ", "[", "http://", "From: ", "-", "xn--", " ")).map(a => a.join("")).filter(s => s.length <= 4000)` for P20

### Test isolation

Each test builds its data inline and shares no mutable state. Detector tests import detector functions directly. Property tests import `blend` and `verdictFor` from their own modules, bypassing `score.js`.
