# Requirements Document

## Introduction

The threat-scoring engine is a pure-JavaScript, ES-module library that analyses a text message and returns a structured risk assessment. It runs entirely in-memory with no I/O, no browser APIs, and no Node.js built-ins, making it portable across any JavaScript runtime. The engine combines three scoring layers — L1 heuristics (pattern matching), L2 blacklist signals, and an optional L3 AI score — into a single integer risk score accompanied by a plain-language verdict, a list of detected red flags, highlighted cursed phrases, and a confidence level.

## Requirements

### Requirement 1: Structured Input / Typed Result

**User Story:** As a developer integrating the threat-scoring engine, I want a well-typed pure function that validates its inputs and returns a consistent result shape, so that I can safely call it without worrying about unexpected side effects or ambiguous outputs.

#### Acceptance Criteria

1. The module exports a pure function `score(input, options)` where `input` is a string and `options` is an optional object.
2. `options.l2Hit` is a boolean; it defaults to `false` when omitted.
3. `options.l3Score` is a number in [0, 100] or null; it defaults to `null` when omitted.
4. The function throws `TypeError` if `input` is not a string.
5. The function throws `RangeError` if `input` length exceeds 4000 characters.
6. The function throws `RangeError` if `options.l3Score` is supplied but is not an integer in [0, 100] — including NaN, Infinity, non-integer numbers, negative numbers, and numbers above 100.
7. The function is pure and deterministic: same inputs always produce the same output; no I/O, no randomness, no global state mutations.
8. The function returns a `RiskResult` object with shape `{ riskScore, verdict, redFlags, cursedPhrases, confidence }`.

---

### Requirement 2: L1 Heuristics Engine

**User Story:** As a user pasting a suspicious message, I want the engine to automatically detect known phishing signals in the text, so that I receive a risk score even when no external threat intelligence is available.

#### Acceptance Criteria

1. The engine computes an `L1_Score` by summing red-flag weights subject to per-category caps: Identity/Auth max 40 points, Link max 35 points, Content max 45 points. The total is clamped to 0–100.
2. Each detected red flag produces an entry in `redFlags` with fields `id`, `weight`, `evidence`, and `explanation`.
3. `typosquatting` (Identity/Auth, weight 35): fires when a domain is a visually similar misspelling of a known brand — e.g. "galact1bank.example" for the fictional brand "galactibank". On its own (weight 35, no other signals) this yields an L1_Score of 35, placing the result in the "skeptical" range.
4. `homograph-punycode` (Identity/Auth, weight 35): fires when a domain uses punycode encoding or Unicode homoglyphs (e.g. xn-- prefix, Cyrillic "а" substituted for Latin "a"). On its own (weight 35) this yields an L1_Score of 35, placing the result in the "skeptical" range.
5. `raw-ip-url` (Link, weight 35): fires when a URL hostname is a raw IPv4 or IPv6 address. On its own (weight 35, Link cap 35) this yields an L1_Score of 35.
6. `risky-tld` (Link, weight 15): fires when a domain uses a TLD on the risky list (e.g. .xyz, .top, .click, .tk, .ml, .ga, .cf).
7. `display-name-mismatch` (Identity/Auth, weight 25): fires when the email From display name claims to be a known brand but the actual sending domain does not match that brand.
8. `link-text-mismatch` (Link, weight 35): fires when the visible link text and the real href point to different domains. Supported link formats: HTML anchors (`<a href="...">text</a>`) and Markdown-style links (`[text](url)`). On its own (weight 35, Link cap 35) this yields an L1_Score of 35.
9. `urgency-en` (Content, weight 15): fires when the message contains English urgency language (e.g. "act now", "verify immediately", "your account will be suspended").
10. `urgency-bn` (Content, weight 15): fires when the message contains Bangla urgency language (equivalent Bangla phrases).
11. `credential-request` (Content, weight 20): fires when the message requests a login, password, PIN, or OTP.
12. `suspicious-attachment` (Content, weight 20): fires when the message mentions or contains a filename with a dangerous extension (.exe, .scr, .vbs, .bat, .cmd, .js, .lnk, .iso, .img).
13. `spf-fail` (Identity/Auth, weight 20): fires when an SPF header is present and reports a failure.
14. `dkim-fail` (Identity/Auth, weight 20): fires when a DKIM header is present and reports a failure.
15. `dmarc-fail` (Identity/Auth, weight 15): fires when a DMARC header is present and reports a failure.
16. All regular expressions used in the engine must be safe against catastrophic backtracking: no unbounded nested quantifiers, no exponential alternation on overlapping patterns.

---

### Requirement 3: Cursed Phrases

**User Story:** As a user reviewing results, I want the engine to highlight the specific words or phrases that triggered content signals, so that I can see exactly what looked suspicious.

#### Acceptance Criteria

1. The result includes a `cursedPhrases` array.
2. Each entry has: `text` (the matched span from the input) and `reason` (plain-English explanation of why that phrase is suspicious).
3. Phrases that trigger `credential-request`, `urgency-en`, or `urgency-bn` signals are candidates for cursed-phrase annotation.
4. When no such phrases are found, `cursedPhrases` is an empty array.

---

### Requirement 4: Layer Blending

**User Story:** As an integrator supplying external threat intelligence scores, I want the engine to combine heuristic, blacklist, and AI scores in a principled way, so that stronger signals always raise the final risk score.

#### Acceptance Criteria

The module exports a pure function `blend(l1Score, l2Hit, l3Score, flags)` that returns an integer riskScore in [0, 100]. Rules are applied in order:

1. If `l2Hit` is true: `risk = max(90, l1Score)`
2. Else if `l3Score` is not null: `risk = 0.55 * l1Score + 0.45 * l3Score`
3. Else: `risk = l1Score`
4. Then (always): `risk = max(risk, 0.8 * l1Score)`
5. Hard floor: if flags include `typosquatting` AND `credential-request`, then `risk = max(risk, 70)`
6. Hard floor: if flags include `raw-ip-url` AND `credential-request`, then `risk = max(risk, 70)`
7. Hard floor: if flags include (`spf-fail` OR `dkim-fail`) AND `display-name-mismatch`, then `risk = max(risk, 60)`
8. Hard floor: if flags include `credential-request` AND (`urgency-en` OR `urgency-bn`), then `risk = max(risk, 55)`
9. Hard floor: if flags include `suspicious-attachment`, then `risk = max(risk, 40)`
10. Clamp to 0–100 and round to nearest integer.

---

### Requirement 5: Verdict Thresholds

**User Story:** As a user reading the result, I want a plain-language verdict label, so that I understand the risk level without interpreting a number.

#### Acceptance Criteria

1. The module exports a pure function `verdictFor(riskScore)` that accepts an integer 0–100 and returns a verdict string.
2. Scores 0–30 return `"pookie"`.
3. Scores 31–69 return `"skeptical"`.
4. Scores 70–100 return `"poltergeist"`.
5. The `score` function uses `verdictFor` internally to populate the `verdict` field of the result.

---

### Requirement 6: Confidence

**User Story:** As a user reviewing the result, I want to know how complete the analysis was, so that I can judge how much to trust the score.

#### Acceptance Criteria

1. `confidence` is `"limited"` when `l3Score` is null.
2. `confidence` is `"full"` when `l3Score` is a number in [0, 100].

---

### Requirement 7: Plain-English Explanations

**User Story:** As a non-technical user, I want each red flag to be explained in plain language, so that I understand why the message was flagged without needing security expertise.

#### Acceptance Criteria

1. Every red flag in the result must have a non-empty `explanation` field.
2. The explanation must be written in plain English, free of technical jargon.
3. The explanation must describe both what was found and why it is suspicious to a non-technical reader.

---

### Requirement 8: Safety Floor and Estimate Disclosure

**User Story:** As a user, I want the engine to never falsely reassure me that a message is safe, so that I remain appropriately cautious even for borderline cases.

#### Acceptance Criteria

1. The engine must never return a `riskScore` of 0 when any red flags are present. A score of 0 with one or more active red flags is a defect.
2. The engine output must never contain any wording claiming a message is completely safe or risk-free.
3. The result object must include enough information for the UI to communicate to users that scores are estimates, not certainties. The `confidence` field serves this purpose: `"limited"` explicitly signals that the assessment is based on heuristics alone.

---

### Requirement 9: Pluggable Brand Data Module

**User Story:** As an operator, I want to supply my own brand list for typosquatting and display-name detection, so that I can tailor the engine to my users' most-targeted brands without modifying engine logic.

#### Acceptance Criteria

1. Brand names used for `typosquatting` detection (Requirement 2, criterion 3) and `display-name-mismatch` detection (Requirement 2, criterion 7) must come from a separate data module (e.g. `brands.js`) that is imported by the engine.
2. The data module must be replaceable without modifying the engine logic — callers can substitute their own brand list.
3. Test fixtures must use only fictional brand names (e.g. "Galactibank", "Orbitz Insurance") and must not reference real company names or real domains.

---

### Requirement 10: Golden Tests

**User Story:** As a developer, I want a suite of hand-written test cases that cover every scoring path, so that regressions are caught immediately.

#### Acceptance Criteria

At least 10 golden tests must be provided, each using reserved domains (.example, .test, .invalid) and fictional brand names only. The cases must cover:

1. **Clean message** — no signals fire → `pookie` (riskScore ≤ 30).
2. **Risky-TLD + credential-request** — `risky-tld` (weight 15) + `credential-request` (weight 20) = L1 35, no hard floor applies (no urgency phrase) → `skeptical`.
3. **Typosquatting + credential-request** — hard floor rule 4.5 applies → `poltergeist` (riskScore ≥ 70).
4. **Raw IP + credential-request** — hard floor rule 4.6 applies → `poltergeist` (riskScore ≥ 70).
5. **SPF/DKIM fail + display-name mismatch** — hard floor rule 4.7 applies (riskScore ≥ 60) → at least `skeptical`.
6. **L2 hit (blacklist)** — rule 4.1 applies → `poltergeist` (riskScore ≥ 90).
7. **L3 score supplied** — rule 4.2 weighted blend applies → riskScore = round(0.55 × L1 + 0.45 × L3).
8. **Bangla urgency + credential-request** — hard floor rule 4.8 applies (riskScore ≥ 55) → `skeptical` or higher. The input must contain both a Bangla urgency phrase and a credential request (e.g. OTP).
9. **Suspicious attachment only** — hard floor rule 4.9 applies (riskScore ≥ 40) → `skeptical` or higher. The input contains only a suspicious attachment filename with no other signals.
10. **Link-text mismatch only** — `link-text-mismatch` weight 35 (Link cap 35) → L1_Score 35 → `skeptical` or higher.

---

### Requirement 11: Property Tests

**User Story:** As a developer, I want automated property tests that verify mathematical invariants across arbitrary inputs, so that edge cases are caught beyond the hand-written golden tests.

#### Acceptance Criteria

Using the exported `blend(l1Score, l2Hit, l3Score, flags)` and `verdictFor(riskScore)` functions directly:

1. **Range invariant** — `blend` returns an integer riskScore. For all valid inputs, the returned value is an integer in [0, 100] (not an object, not NaN, not a float).
2. **Pure-L1 floor** — When `l2Hit` is false and `l3Score` is null, `riskScore >= l1Score`.
3. **0.8×L1 floor** — For all inputs, `riskScore >= Math.round(0.8 * l1Score)`.
4. **L2 floor** — When `l2Hit` is true, `riskScore >= 90`.
5. **Determinism** — `blend` is deterministic: calling it twice with the same arguments returns the same result.
6. **Verdict exhaustiveness** — `verdictFor(riskScore)` always returns one of `"pookie"`, `"skeptical"`, `"poltergeist"` for any integer input in [0, 100].
7. **Confidence exhaustiveness** — `confidence` from `score()` is always one of `"limited"`, `"full"`.

---

### Requirement 12: Module Purity

**User Story:** As a developer embedding the engine in any JavaScript environment, I want the module to have zero platform-specific dependencies, so that it works in browsers, Node.js, and edge runtimes alike.

#### Acceptance Criteria

1. The module uses ES module syntax (`import`/`export`).
2. No dependencies on browser APIs (`window`, `document`, `fetch`).
3. No dependencies on Node.js built-in APIs (`fs`, `net`, `http`, etc.).
4. No side effects at module load time.
