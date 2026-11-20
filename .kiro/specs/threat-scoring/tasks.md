# Implementation Plan: threat-scoring

## Overview

Build the `packages/engine` ES-module library in plain JavaScript. The library analyses a text message and returns a structured risk assessment via a pure, deterministic `score()` function. Implementation follows the layered architecture from the design: configuration constants, brand data, utility helpers, four detector modules, a blending function, verdict mapping, and the top-level orchestrator — then golden tests and property tests.

Each task creates or modifies exactly one source file or one test file. No task merges multiple source files. Order follows the dependency graph: constants first, then utilities, then detectors, then composition, then tests.

## Tasks

- [x] 0. Project scaffolding
  - Create directory tree: `packages/engine/src/`, `packages/engine/src/util/`, `packages/engine/src/detectors/`, `packages/engine/test/`
  - Create `packages/engine/package.json` with `"type": "module"`, `vitest` and `fast-check` as devDependencies, and a `test` script that runs `vitest --run`
  - Create `packages/engine/vitest.config.js` configured for ESM (set `environment` to `node`, no transform needed for plain JS ES modules)
  - No source files yet — just the project shell
  - _Requirements: 12.1_

- [x] 1. `packages/engine/src/config.js`
  - Export all named numeric and word-list constants; no imports from within the package
  - Signal weights: `W_TYPOSQUATTING=35`, `W_HOMOGRAPH_PUNYCODE=35`, `W_RAW_IP_URL=35`, `W_RISKY_TLD=15`, `W_DISPLAY_NAME_MISMATCH=25`, `W_LINK_TEXT_MISMATCH=35`, `W_URGENCY_EN=15`, `W_URGENCY_BN=15`, `W_CREDENTIAL_REQUEST=20`, `W_SUSPICIOUS_ATTACHMENT=20`, `W_SPF_FAIL=20`, `W_DKIM_FAIL=20`, `W_DMARC_FAIL=15`
  - Category caps: `CAP_IDENTITY_AUTH=40`, `CAP_LINK=35`, `CAP_CONTENT=45`
  - Verdict thresholds: `VERDICT_POOKIE_MAX=30`, `VERDICT_SKEPTICAL_MAX=69`
  - Hard floors: `FLOOR_TYPOSQUAT_CRED=70`, `FLOOR_RAWIP_CRED=70`, `FLOOR_AUTH_DISPLAY=60`, `FLOOR_CRED_URGENCY=55`, `FLOOR_ATTACHMENT=40`
  - Blend coefficients: `BLEND_L1_WEIGHT=0.55`, `BLEND_L3_WEIGHT=0.45`, `BLEND_L1_FLOOR_FACTOR=0.8`, `BLEND_L2_FLOOR=90`
  - Limits: `MAX_INPUT_LENGTH=4000`, `MAX_HOSTNAMES_SCANNED=50`, `MAX_CURSED_PHRASES=20`
  - Typosquatting tuning: `TYPO_SHORT_NAME_MAX_LEN=6`, `TYPO_MAX_DISTANCE_SHORT=1`, `TYPO_MAX_DISTANCE_LONG=2`, `TYPO_MIN_FUZZY_LEN=4`, `TYPO_CONTAINS_MIN_LEN=6`
  - `SIGNAL_CATEGORY` map: typosquatting→identity-auth, homograph-punycode→identity-auth, display-name-mismatch→identity-auth, spf-fail→identity-auth, dkim-fail→identity-auth, dmarc-fail→identity-auth, raw-ip-url→link, risky-tld→link, link-text-mismatch→link, urgency-en→content, urgency-bn→content, credential-request→content, suspicious-attachment→content
  - `RISKY_TLDS = ["xyz", "top", "click", "tk", "ml", "ga", "cf"]`
  - `DANGEROUS_EXTENSIONS = ["exe", "scr", "vbs", "bat", "cmd", "js", "lnk", "iso", "img"]`
  - `JS_LIBRARY_ALLOWLIST = ["node", "react", "vue", "next", "nuxt", "express", "angular", "d3", "three"]`
  - `SECOND_LEVEL_LABELS = ["com", "co", "org", "net", "gov", "edu", "ac"]`
  - `URGENCY_EN_PHRASES = ["act now", "verify immediately", "account will be suspended", "account has been suspended", "account suspended", "confirm your details", "limited time", "expires today", "click here immediately", "immediate action required"]`
  - `URGENCY_BN_PHRASES = ["আপনার অ্যাকাউন্ট স্থগিত হবে", "এখনই যাচাই করুন", "অবিলম্বে যাচাই", "এখনই সাড়া দিন", "অ্যাকাউন্ট বন্ধ হয়ে যাবে"]`
  - No other module may use an inline literal for any of these values
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10, 2.11, 2.12, 2.13, 2.14, 2.15, 4.1–4.10, 5.2–5.4, 6.1–6.2, 12.1_

- [x] 2. `packages/engine/src/brands.js`
  - Export `DEFAULT_BRANDS` as a `BrandEntry[]` with only fictional brands and reserved TLDs: galactibank / galactibank.example, orbitins / orbitins.test, nexamail / nexamail.example, vaultpay / vaultpay.example, trustledger / trustledger.test
  - Brand names are lowercase, a–z0–9 only; no imports from the package
  - _Requirements: 9.1, 9.2, 9.3_

- [x] 3. `packages/engine/src/util/levenshtein.js`
  - Export `levenshtein(a, b)` — standard iterative Wagner-Fischer edit distance
  - Returns the exact edit distance for strings of any length; accepts empty strings (distance equals the length of the other string)
  - Imports only `config.js`
  - _Requirements: 2.3, 2.4_

- [x] 4. `packages/engine/src/util/hostname.js`
  - Export `extractAsciiHostnames(text)` using the ASCII extractor regex from the design; apply with `matchAll`, lowercase, de-duplicate, cap at `MAX_HOSTNAMES_SCANNED`
  - Export `extractUnicodeHostnames(text)` using the Unicode extractor regex from the design; same post-processing
  - Regex objects with the `g` flag must never be shared mutable state; create inside the function or use `matchAll`
  - Export `registrableLabel(host)`: second-to-last label; if last label has 2 letters and second-to-last is in `SECOND_LEVEL_LABELS`, use third-to-last
  - Export `registrableDomain(host)`: `registrableLabel(host) + "." + lastLabel(host)`
  - Export `isLegitimate(host, brand)`: true when `host` equals or is a subdomain of any domain in `brand.domains`
  - Imports only `config.js`
  - _Requirements: 2.3, 2.4, 2.5, 2.7, 2.8_

- [x] 5. Identity detector
  - [x] 5.1 Implement `packages/engine/src/detectors/identity.js`
    - Implement `detectIdentity(input, brands)` returning `{ flags: RedFlag[], cursedPhrases: [] }`
    - Three signals: `typosquatting` (W_TYPOSQUATTING=35), `homograph-punycode` (W_HOMOGRAPH_PUNYCODE=35), `display-name-mismatch` (W_DISPLAY_NAME_MISMATCH=25)
    - One `RedFlag` per signal per message; evidence is the first match
    - Explanation templates with `{e}` replaced by evidence (exact strings from design Plain-English Explanations table)
    - Typosquatting: ASCII extractor → skip legitimate → `registrableLabel` → `canon()` substitution (rn→m, vv→w, 0→o, 3→e, 4→a, 5→s, 1/i/l→l) → fire on exact label match on wrong domain, canon distance ≤ threshold, or brand name (len≥6) substring of label
    - Homograph-punycode: Unicode extractor → split labels → fire on `xn--` prefix OR Latin/Cyrillic-Greek mix within same label; does NOT fire for pure single-script hostnames
    - Display-name-mismatch: pattern `/(?:^|\n)[ \t]*From:[ \t]*(?:"([^"\n]{1,100})"|([^<\n]{1,100}?))[ \t]*<[^@<>\s]{1,64}@([a-z0-9.-]{1,253})>/gi`; fire when display name contains a brand name and sending domain is not legitimate
    - Imports: `config.js`, `brands.js`, `util/hostname.js`, `util/levenshtein.js`
    - _Requirements: 2.2, 2.3, 2.4, 2.7, 7.1, 7.2, 7.3, 9.1_

  - [x]* 5.2 Unit tests for `identity.js`
    - "https://galact1bank.example/login" → `typosquatting` fires
    - "http://galactibank.xyz" → `typosquatting` fires (exact label, wrong domain)
    - "https://galactibank-verify.example" → `typosquatting` fires (brand inside label)
    - "https://login.galactibank.example" → no `typosquatting` (legitimate subdomain)
    - "visit galactibank.example" → no `typosquatting` (legitimate domain)
    - "visit gаlactibank.example" (Cyrillic а U+0430) → `homograph-punycode` fires
    - "visit গালাক্তিব্যাংক.example" (pure Bangla hostname) → no `homograph-punycode`
    - "visit xn--galctibnk-r8a.example" → `homograph-punycode` fires
    - "From: Galactibank Support <noreply@phish.invalid>" → `display-name-mismatch` fires
    - Every emitted `RedFlag` has a non-empty `explanation`
    - _Requirements: 2.3, 2.4, 2.7, 7.1, 7.2, 7.3_

- [x] 6. Link detector
  - [x] 6.1 Implement `packages/engine/src/detectors/link.js`
    - Implement `detectLinks(input)` returning `{ flags: RedFlag[], cursedPhrases: [] }`
    - Three signals: `raw-ip-url` (W_RAW_IP_URL=35), `risky-tld` (W_RISKY_TLD=15), `link-text-mismatch` (W_LINK_TEXT_MISMATCH=35)
    - One `RedFlag` per signal; evidence is the first match; explanations from design table
    - `raw-ip-url`: IPv4 pattern from design + octet validation (0–255) in code; IPv6 pattern from design + structural validation in code
    - `risky-tld`: built from `RISKY_TLDS` constant; pattern from design; last-label check via lookahead
    - `link-text-mismatch`: HTML anchor and Markdown patterns from design; compare `registrableDomain` of text host vs href host; fire only when both sides have a parseable domain
    - Imports: `config.js`, `util/hostname.js`
    - _Requirements: 2.5, 2.6, 2.8, 7.1, 7.2, 7.3_

  - [x]* 6.2 Unit tests for `link.js`
    - "http://203.0.113.5 click here" → `raw-ip-url` fires
    - "http://1.2.3.4.evil.example" → no `raw-ip-url`
    - "http://999.1.1.1/" → no `raw-ip-url` (invalid octet)
    - "http://[2001:db8::1]/" → `raw-ip-url` fires (IPv6)
    - "http://bad.xyz/login" → `risky-tld` fires (trailing `/` accepted)
    - "bad.xyz.example" → no `risky-tld` (not last label)
    - HTML anchor with text domain ≠ href domain → `link-text-mismatch` fires
    - Markdown link with text domain ≠ href domain → `link-text-mismatch` fires
    - Every emitted `RedFlag` has a non-empty `explanation`
    - _Requirements: 2.5, 2.6, 2.8, 7.1_

- [x] 7. Content detector
  - [x] 7.1 Implement `packages/engine/src/detectors/content.js`
    - Implement `detectContent(input)` returning `{ flags: RedFlag[], cursedPhrases: CursedPhrase[] }`
    - Four signals: `urgency-en` (15), `urgency-bn` (15), `credential-request` (20), `suspicious-attachment` (20)
    - One `RedFlag` per signal; evidence is the first match; explanations from design table
    - `urgency-en`: regex built from `URGENCY_EN_PHRASES` (regex-escaped, `|`-joined, single spaces → `\s+`, `gi` + `\b`); each match → `CursedPhrase`
    - `urgency-bn`: regex built from `URGENCY_BN_PHRASES` (regex-escaped, `|`-joined, `\s+`, `u` flag, no `\b`); each match → `CursedPhrase`
    - `credential-request`: case-insensitive pass + case-sensitive pass for PIN/OTP + Bangla terms; each match → `CursedPhrase`
    - `suspicious-attachment`: pattern from design; `JS_LIBRARY_ALLOWLIST` skips `.js` allowlisted names; evidence = first filename; no `CursedPhrase`
    - `CursedPhrase` entries de-duplicated by lowercase text; capped at `MAX_CURSED_PHRASES`
    - Imports: `config.js` only
    - _Requirements: 2.9, 2.10, 2.11, 2.12, 3.1, 3.2, 3.3, 3.4, 7.1, 7.2, 7.3_

  - [x]* 7.2 Unit tests for `content.js`
    - Input with 3 distinct urgency-en phrases → one `urgency-en` `RedFlag` + 3 `CursedPhrase` entries
    - "please pin this post" → no `credential-request`
    - "I work with Node.js daily" → no `suspicious-attachment`
    - "I use React.js and Vue.js" → no `suspicious-attachment`
    - "Please open invoice.exe to see your order." → `suspicious-attachment` fires
    - "blog.bat.example" → no `suspicious-attachment`
    - Every emitted `RedFlag` has a non-empty `explanation`
    - Every `CursedPhrase` has a non-empty `reason`
    - _Requirements: 2.9, 2.10, 2.11, 2.12, 3.2, 3.3, 7.1_

- [ ] 8. Auth-headers detector
  - [ ] 8.1 Implement `packages/engine/src/detectors/auth-headers.js`
    - Implement `detectAuthHeaders(input)` returning `{ flags: RedFlag[], cursedPhrases: [] }`
    - Three signals: `spf-fail` (W_SPF_FAIL=20), `dkim-fail` (W_DKIM_FAIL=20), `dmarc-fail` (W_DMARC_FAIL=15)
    - One `RedFlag` per signal; evidence is the matched fragment (e.g. `"dkim=fail"`); explanations from design table
    - Step 1: unfold folded headers with `input.replace(/\r?\n[ \t]+/g, " ")`
    - Step 2: scan `Authentication-Results` lines; within each, detect `spf=fail|softfail|permerror`, `dkim=fail|softfail|permerror`, `dmarc=fail|softfail|permerror`
    - Step 3: `Received-SPF: fail|softfail` → `spf-fail`
    - `DKIM-Signature` header must NEVER fire
    - Imports: `config.js` only
    - _Requirements: 2.13, 2.14, 2.15, 7.1, 7.2, 7.3_

  - [ ]* 8.2 Unit tests for `auth-headers.js`
    - `Authentication-Results` with `spf=fail` → `spf-fail` fires
    - `Authentication-Results` with `dkim=fail` on a folded second line → `dkim-fail` fires
    - `DKIM-Signature` header alone → no flags
    - `Received-SPF: softfail` → `spf-fail` fires
    - `Authentication-Results` with `dmarc=permerror` → `dmarc-fail` fires
    - Every emitted `RedFlag` has a non-empty `explanation`
    - _Requirements: 2.13, 2.14, 2.15, 7.1_

- [ ] 9. Blend function
  - [ ] 9.1 Implement `packages/engine/src/blend.js`
    - Implement `blend(l1Score, l2Hit, l3Score, flags)` → integer 0–100; accept flags as `Array<string>` or `Set<string>`; normalize with `new Set(flags)`
    - Rule 4.1: `l2Hit` → `risk = max(BLEND_L2_FLOOR, l1Score)`
    - Rule 4.2: `l3Score !== null` → `risk = BLEND_L1_WEIGHT * l1Score + BLEND_L3_WEIGHT * l3Score`
    - Rule 4.3: else → `risk = l1Score`
    - Rule 4.4: `risk = max(risk, BLEND_L1_FLOOR_FACTOR * l1Score)`
    - Rule 4.5: typosquatting + credential-request → `max(risk, FLOOR_TYPOSQUAT_CRED)`
    - Rule 4.6: raw-ip-url + credential-request → `max(risk, FLOOR_RAWIP_CRED)`
    - Rule 4.7: (spf-fail ∨ dkim-fail) + display-name-mismatch → `max(risk, FLOOR_AUTH_DISPLAY)`
    - Rule 4.8: credential-request + (urgency-en ∨ urgency-bn) → `max(risk, FLOOR_CRED_URGENCY)`
    - Rule 4.9: suspicious-attachment → `max(risk, FLOOR_ATTACHMENT)`
    - Rule 4.10: `Math.round(Math.min(100, Math.max(0, risk)))`
    - All constants imported from `config.js`; no inline literals
    - Imports: `config.js` only
    - _Requirements: 4.1–4.10_

  - [ ]* 9.2 Unit tests for `blend.js`
    - Each of rules 4.1–4.10 tested independently
    - Each hard floor (4.5–4.9) tested independently
    - Array and Set with same flags → same result
    - `l1=0, l2Hit=false, l3=null, flags=[]` → 0
    - `l1=50, l2Hit=true` → ≥ 90
    - `l1=20, l3=80` → `round(0.55×20 + 0.45×80) = 47`
    - `l1=35, flags=[typosquatting, credential-request]` → 70
    - `l1=0, flags=[suspicious-attachment]` → 40
    - _Requirements: 4.1–4.10, 11.1–11.5_

- [ ] 10. Verdict function
  - [ ] 10.1 Implement `packages/engine/src/verdict.js`
    - Implement `verdictFor(riskScore)` → `"pookie" | "skeptical" | "poltergeist"`
    - `≤ VERDICT_POOKIE_MAX (30)` → `"pookie"`; `≤ VERDICT_SKEPTICAL_MAX (69)` → `"skeptical"`; else → `"poltergeist"`
    - Imports: `config.js` only
    - _Requirements: 5.1–5.4_

  - [ ]* 10.2 Unit tests for `verdict.js`
    - 0 → `"pookie"`, 30 → `"pookie"`
    - 31 → `"skeptical"`, 69 → `"skeptical"`
    - 70 → `"poltergeist"`, 100 → `"poltergeist"`
    - _Requirements: 5.2–5.4_

- [ ] 11. Score orchestrator and public API
  - [ ] 11.1 Implement `packages/engine/src/score.js` and `packages/engine/src/index.js`
    - Implement `score(input, options)` → `RiskResult` per design `score.js` section
    - Input validation: `typeof input !== "string"` → `TypeError("input must be a string")`; `input.length > MAX_INPUT_LENGTH` → `RangeError("input exceeds 4000 characters")`; `const opts = options ?? {}`; `l2Hit = opts.l2Hit === true`; `l3Score` defaults to `null`; non-null non-integer-0–100 `l3Score` → `RangeError("l3Score must be an integer 0-100 or null")`; brands from `opts.brands` or `DEFAULT_BRANDS`
    - L1 pipeline: `detectIdentity` → `detectAuthHeaders` → `detectLinks` → `detectContent` (fixed order); group by `SIGNAL_CATEGORY`; cap per category; sum; clamp 0–100; one-flag-per-signal enforced
    - Compose: `blend(l1Score, l2Hit, l3Score, flagIds)` → `verdictFor(riskScore)` → confidence
    - `index.js` re-exports `score`, `blend`, `verdictFor`; no logic
    - Imports: `config.js`, `brands.js`, all four detectors, `blend.js`, `verdict.js`
    - _Requirements: 1.1–1.8, 4.1–4.10, 5.5, 6.1–6.2, 8.1–8.3, 9.1–9.2_

  - [ ]* 11.2 Unit tests for `score.js`
    - `score(123)` → `TypeError`; `score("x".repeat(4001))` → `RangeError`; `score("hi", { l3Score: 1.5 })` → `RangeError`; `score("hi", null)` → valid result
    - `score("hi")` and `score("hi", {})` → deeply equal results
    - `l3Score` 0 and 100 accepted without throwing
    - Boundary verdicts: riskScore 30 → `"pookie"`, 31 → `"skeptical"`, 69 → `"skeptical"`, 70 → `"poltergeist"`
    - Brand substitution: `score("http://zorbbank.example/x", { brands: [{ name: "zorbbank", domains: ["zorbbank.example"] }] })` → no `typosquatting`; a lookalike triggers it
    - Any message with ≥ 1 flag has `riskScore > 0`
    - `confidence` is `"limited"` without `l3Score`; `"full"` with valid `l3Score`
    - _Requirements: 1.1–1.8, 6.1–6.2, 8.1, 9.2_

- [ ] 12. Checkpoint — Ensure all unit tests pass
  - Run `vitest --run` from `packages/engine/` and confirm zero failures before proceeding to integration tests
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 13. `packages/engine/test/golden.test.js`
  - Implement all 10 golden test cases from the design Testing Strategy table; each asserts exact verdict, exact riskScore, exact set of flag ids, `cursedPhrases` non-empty iff a content signal fired, expected `confidence`
    1. `"Hi, lunch at 1pm tomorrow? Let me know."` → `pookie`, riskScore 0, no flags
    2. `"Check your balance at http://bad.xyz/portal and enter your password."` → `skeptical`, riskScore 35, flags `{risky-tld, credential-request}`
    3. `"Your Galactibank account: log in at https://galact1bank.example/login to continue."` → `poltergeist`, riskScore 70, flags `{typosquatting, credential-request}`
    4. `"Enter your OTP at http://203.0.113.5/verify"` → `poltergeist`, riskScore 70, flags `{raw-ip-url, credential-request}`
    5. `From: Galactibank Support <noreply@mail-alerts.invalid>` + `Authentication-Results` with `spf=fail` + body → `skeptical`, riskScore 60, flags `{display-name-mismatch, spf-fail}`
    6. `"Meeting notes attached for review."` with `{ l2Hit: true }` → `poltergeist`, riskScore 90, no flags
    7. `"Please send your password."` with `{ l3Score: 80 }` → `skeptical`, riskScore 47, flags `{credential-request}`, confidence `"full"`
    8. `URGENCY_BN_PHRASES[0] + " OTP পাঠান।"` (using the constant from config.js) → `skeptical`, riskScore 55, flags `{urgency-bn, credential-request}`
    9. `"Please open invoice.exe to see your order."` → `skeptical`, riskScore 40, flags `{suspicious-attachment}`
    10. `Click <a href="http://phish.invalid/offer">http://galactibank.example</a> to see it.` → `skeptical`, riskScore 35, flags `{link-text-mismatch}`
  - Also implement all edge-case unit tests from the design document
  - All fixtures use only fictional brands and reserved TLDs (`.example`, `.test`, `.invalid`)
  - Imports from `index.js` and `config.js`
  - _Requirements: 10.1–10.10_

- [ ] 14. `packages/engine/test/property.test.js`
  - Implement all 20 properties P1–P20 using fast-check; each tagged `// Feature: threat-scoring, Property N: <description>`; minimum 100 iterations each
  - P13–P19 drive `blend` and `verdictFor` directly; P1–P12 and P20 drive `score`
  - Arbitraries per design Testing Strategy section (l1Score, l2Hit, l3Score, flags as Array/Set, invalid l3Score, non-string input, text input ≤ 4000, adversarial input for P20)
  - P1: non-string → `TypeError`; P2: len > 4000 → `RangeError`, len ≤ 4000 → no length error; P3: invalid `l3Score` → `RangeError`; P4: options default equivalence; P5: determinism; P6: `RiskResult` shape; P7: `RedFlag` shape (non-empty fields; "no claim of safety" check with `/\b(safe|risk-free)\b/i`); P8: `CursedPhrase` shape; P9: flag id uniqueness; P10: safety floor; P11: verdict consistency; P12: confidence exhaustiveness
  - P13: `blend` range (integer in [0,100]); P14: pure-L1 floor; P15: 0.8×L1 floor; P16: L2 floor; P17: determinism + Array/Set representation independence; P18: all five hard floors; P19: `verdictFor` exhaustiveness (partition check); P20: robustness — arbitrary and adversarial strings ≤ 4000 → no throw and returns in reasonable time
  - Imports from `index.js` and `config.js`
  - _Requirements: 11.1–11.7_

- [ ] 15. Final verification checkpoint
  - Run `vitest --run` from `packages/engine/` and verify all tests pass with zero failures
  - Confirm no inline numeric literals in source files outside `config.js` (grep check)
  - Confirm no imports of browser or Node.js built-in APIs anywhere in `src/`
  - Ensure all tests pass, ask the user if questions arise.
  - _Requirements: 10.1–10.10, 11.1–11.7, 12.1–12.4_

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP (but all property tests are needed to satisfy Requirement 11)
- Each task references specific requirements for traceability
- Checkpoints (tasks 12 and 15) ensure incremental validation at the boundary between unit tests and integration/property tests
- Property tests validate universal correctness properties (P1–P20); golden tests validate specific examples from the spec
- All fixtures must use only fictional brands (galactibank, orbitins, nexamail, vaultpay, trustledger) and reserved TLDs (.example, .test, .invalid)
- `URGENCY_BN_PHRASES` constant from `config.js` must be used directly in golden test 8 — never a hardcoded Bangla string

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["0"] },
    { "id": 1, "tasks": ["1", "2"] },
    { "id": 2, "tasks": ["3", "4"] },
    { "id": 3, "tasks": ["5.1", "6.1", "7.1", "8.1", "9.1", "10.1"] },
    { "id": 4, "tasks": ["5.2", "6.2", "7.2", "8.2", "9.2", "10.2"] },
    { "id": 5, "tasks": ["11.1"] },
    { "id": 6, "tasks": ["11.2"] },
    { "id": 7, "tasks": ["12"] },
    { "id": 8, "tasks": ["13", "14"] },
    { "id": 9, "tasks": ["15"] }
  ]
}
```
