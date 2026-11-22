# Requirements Document

## Introduction

The threat-scoring engine is a pure-JavaScript, ES-module library that analyses a text message and returns a structured risk assessment. It runs entirely in-memory with no I/O, no browser APIs, and no Node.js built-ins, making it portable across any JavaScript runtime. The engine combines three scoring layers — L1 heuristics (pattern matching), L2 blacklist signals, and an optional L3 AI score — into a single integer risk score accompanied by a plain-language verdict, a list of detected red flags, highlighted cursed phrases, and a confidence level.

The engine analyses English text only. It has no language-specific signals for other languages; Unicode is still handled for hostname checks (for example Cyrillic or Greek look-alike letters).

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
9. `urgency-en` (Content, weight 15): fires when the message contains English urgency language (e.g. "act now", "verify immediately", "your account will be suspended"), including these phrase families: "urgent", "final notice", "pay now"; an account, card, access or mailbox that "is/has been (temporarily) locked/suspended/frozen/restricted/blocked/disabled" or "we have frozen your account"; "within N hours/minutes"; "to avoid arrest/legal action/a warrant/closure/..."; "or it will be returned/deleted/closed"; a device that "has been infected/hacked/compromised", "security breach", "virus detected"; "only N spots/places left"; and an action verb (call, contact, reply, verify, pay...) followed in the same sentence by "immediately", "right away" or "asap".
10. `credential-request` (Content, weight 20): fires when the message requests a login, password(s), PIN, or OTP. A credential word inside a warning whose negation directly governs a request verb ("Do not share your PIN", "We will never ask you to share your card number, PIN or password") does not fire.
11. `suspicious-attachment` (Content, weight 20): fires when the message mentions or contains a filename with a dangerous extension (.exe, .scr, .vbs, .bat, .cmd, .js, .lnk, .iso, .img).
12. `spf-fail` (Identity/Auth, weight 20): fires when an SPF header is present and reports a failure.
13. `dkim-fail` (Identity/Auth, weight 20): fires when a DKIM header is present and reports a failure.
14. `dmarc-fail` (Identity/Auth, weight 15): fires when a DMARC header is present and reports a failure.
15. `prize-lottery` (Content, weight 25): fires when the message claims the reader won something: "you have won", "you've won", "you are the winner", "lucky winner", "claim your prize", "lottery", "jackpot", "free gift", "congratulations" followed within 60 characters by won/winner/selected/prize/lottery/jackpot, a large money amount with a currency marker and million/billion (e.g. "$1 million") or written in digits of at least 1,000,000 (e.g. "USD 15,500,000"), and promises of guaranteed or easy money: "claim your free/reward", "guaranteed returns/profit/income/loan/approval", "zero risk", "risk-free", "double your money", "no experience needed", or a percentage of two or more digits followed by returns/profit/gains ("400% returns"). "Congratulations on your new job!" alone does not fire.
16. `advance-fee-scheme` (Content, weight 25): fires on inheritance or advance-fee wording: "inheritance", "unclaimed funds", "beneficiary", "processing fee", "release fee", "clearance fee", "pay a small fee to receive", "next of kin", "dormant account", "unclaimed deposit/estate/assets", "release the funds", "redelivery fee", "customs fee/charge", "activation fee", "upfront fee", or "transfer of" followed by a large money amount (e.g. "transfer of $4.5 million"). It also fires on a fee (fee, charge, cost, deposit, duty) presented as a condition: "unpaid/outstanding/overdue ... charge", "fee ... is required/outstanding/pending", "just/only/simply pay ... fee", "small ... fee", "fee ... to receive/release/redeliver/unlock/activate/claim/process/dispatch", "fee ... before ... released/delivered/dispatched", "fee ... upfront/in advance". An ordinary fee ("Delivery fee: $3.99", "Send the delivery fee through your mobile wallet") does not fire.
17. `financial-info-request` (Content, weight 30): fires when a request verb (enter, provide, send, share, confirm, verify, update, reply with, give, submit, type) is followed within 60 characters, in the same sentence, by a card or bank term (credit card, debit card, card number, card details, CVV, CVC, expiry date, bank account, account number, routing number, SSN, social security). The term may also come first, with the request verb after it within 60 characters in the same sentence ("Card number and CVV: send them now"). The proximity rule is mandatory: "Thanks for paying by credit card" does not fire. A request verb directly governed by a negation (never, not, don't, won't, can't, cannot, followed by at most 4 helper words such as "ask you to") does not fire: "We will never ask you to share your card number" and "Do not send your bank details" do not fire, but "Do not delay, enter your card number" does.
18. `unusual-payment-method` (Content, weight 20): fires when a payment verb (pay, send, transfer, buy, purchase, pick up, get, deposit, settle, return) is followed within 60 characters, in the same sentence, by a hard-to-trace method: gift cards, iTunes or Google Play cards, bitcoin, crypto, USDT, USDC, Ethereum, wire transfer, Western Union, MoneyGram; or on "wire the money/funds". A mobile wallet counts only when a fee is mentioned in the same sentence. A payment verb directly governed by a negation (as in 2.17) does not fire.
19. `secrecy-pressure` (Content, weight 10): fires on requests to keep the message secret: "do not tell anyone", "keep this confidential", "don't share this with anyone" and close variants, and "do not tell / discuss this with" a named group (your family, your kids, your bank, Mom, Dad...).
20. All regular expressions used in the engine must be safe against catastrophic backtracking: no unbounded nested quantifiers, no exponential alternation on overlapping patterns. Proximity rules use bounded, negated character classes. A dot between two digits ("$4.99") is a decimal point, not a sentence end.
21. **Text normalization.** The content detector matches a normalized copy of the input: Unicode NFKC, lowercase, zero-width and control characters removed (line breaks kept), whitespace runs collapsed, leetspeak mapped inside tokens that also contain letters (@→a, 0→o, 1→i, $→s, 3→e, 5→s; plain numbers, amounts such as "$1million", number+unit tokens such as "10am" and letters+number codes such as "mp3" are never changed), and 4 or more single letters separated by single spaces joined into one word ("p a s s w o r d" → "password"). Evidence and cursed phrases are always the matching span of the ORIGINAL input. The link and identity detectors and the attachment check read the raw input.
22. `code-sharing-request` (Content, weight 30): fires when a share verb (reply with, send, share, forward, tell, give, read, text) is followed within 60 characters, in the same sentence, by a code term (verification, security, confirmation, login, access or SMS code, one-time code/password/passcode, passcode, "N-digit code"), or when a code term is followed within 100 characters by "send/forward/give... it/this/that back to us/me". Governed negations do not fire ("Never share your verification code"). "Enter the code" does not fire, and "OTP" alone stays a `credential-request`.
23. `mistaken-payment` (Content, weight 25): fires when a claim that money was sent by mistake ("accidentally sent", "sent ... by mistake/in error", "duplicate payment", "overpaid") is followed within 200 characters by a request to return it ("send it back", "return the excess", "refund it", "transfer it to"...).
24. `remote-access-request` (Content, weight 25): fires on a request to install or open a remote/screen-sharing tool, app or software, or to give or grant (remote) access or control to "your computer/PC/device/laptop/phone/screen".

---

### Requirement 3: Cursed Phrases

**User Story:** As a user reviewing results, I want the engine to highlight the specific words or phrases that triggered content signals, so that I can see exactly what looked suspicious.

#### Acceptance Criteria

1. The result includes a `cursedPhrases` array.
2. Each entry has: `text` (the matched span from the input) and `reason` (plain-English explanation of why that phrase is suspicious).
3. Phrases that trigger `urgency-en`, `credential-request`, `prize-lottery`, `advance-fee-scheme`, `financial-info-request`, `unusual-payment-method`, `secrecy-pressure`, `code-sharing-request`, `mistaken-payment` or `remote-access-request` are candidates for cursed-phrase annotation. The cursed-phrase text is always a substring of the original input. `suspicious-attachment` produces no cursed phrase.
4. When no such phrases are found, `cursedPhrases` is an empty array.

---

### Requirement 4: Layer Blending

**User Story:** As an integrator supplying external threat intelligence scores, I want the engine to combine heuristic, blacklist, and AI scores in a principled way, so that stronger signals always raise the final risk score.

#### Acceptance Criteria

The module exports a pure function `blend(l1Score, l2Hit, l3Score, flags, context?)` that returns an integer riskScore in [0, 100]. `context.paymentInstruction` (optional boolean, set by `score()` from the content detector) is true when the message explicitly says where to send a payment: a send/pay/transfer/wire/deposit verb followed in the same sentence by "to me/us/my/our/this/the account/the wallet...", or "send/give/read/text me the codes/numbers/pictures". It is not a signal and adds no weight. Rules are applied in order:

1. If `l2Hit` is true: `risk = max(90, l1Score)`
2. Else if `l3Score` is not null: `risk = 0.55 * l1Score + 0.45 * l3Score`
3. Else: `risk = l1Score`
4. Then (always): `risk = max(risk, 0.8 * l1Score)`
5. Hard floor: if flags include `typosquatting` AND `credential-request`, then `risk = max(risk, 70)`
6. Hard floor: if flags include `raw-ip-url` AND `credential-request`, then `risk = max(risk, 70)`
7. Hard floor: if flags include (`spf-fail` OR `dkim-fail`) AND `display-name-mismatch`, then `risk = max(risk, 60)`
8. Hard floor: if flags include `credential-request` AND `urgency-en`, then `risk = max(risk, 55)`
9. Hard floor: if flags include `suspicious-attachment`, then `risk = max(risk, 40)`
10. Hard floor: if flags include (`prize-lottery` OR `advance-fee-scheme`) AND (`financial-info-request` OR `unusual-payment-method`), then `risk = max(risk, 70)`
11. Hard floor: if flags include `financial-info-request`, then `risk = max(risk, 50)`
12. Hard floor: if flags include `unusual-payment-method` AND (`urgency-en` OR `secrecy-pressure` OR `prize-lottery` OR `advance-fee-scheme` OR `context.paymentInstruction`), then `risk = max(risk, 40)`. `unusual-payment-method` alone has no floor ("Buy a gift card for your mom" stays at 20).
13. Clamp to 0–100 and round to nearest integer. This step runs last, after floors 14 and 15 (they were added later and keep their own numbers).
14. Hard floor: if flags include `code-sharing-request`, then `risk = max(risk, 50)`
15. Hard floor: if flags include `mistaken-payment`, then `risk = max(risk, 40)`

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

At least 13 golden tests must be provided, each using reserved domains (.example, .test, .invalid) and fictional brand names only. The cases must cover:

1. **Clean message** — no signals fire → `pookie` (riskScore ≤ 30).
2. **Risky-TLD + credential-request** — `risky-tld` (weight 15) + `credential-request` (weight 20) = L1 35, no hard floor applies (no urgency phrase) → `skeptical`.
3. **Typosquatting + credential-request** — hard floor rule 4.5 applies → `poltergeist` (riskScore ≥ 70).
4. **Raw IP + credential-request** — hard floor rule 4.6 applies → `poltergeist` (riskScore ≥ 70).
5. **SPF/DKIM fail + display-name mismatch** — hard floor rule 4.7 applies (riskScore ≥ 60) → at least `skeptical`.
6. **L2 hit (blacklist)** — rule 4.1 applies → `poltergeist` (riskScore ≥ 90).
7. **L3 score supplied** — rule 4.2 weighted blend applies → riskScore = round(0.55 × L1 + 0.45 × L3).
8. **Urgency + credential-request** — hard floor rule 4.8 applies (riskScore ≥ 55) → `skeptical` or higher. The input must contain both an English urgency phrase and a credential request (e.g. "Act now: please confirm your password.").
9. **Suspicious attachment only** — hard floor rule 4.9 applies (riskScore ≥ 40) → `skeptical` or higher. The input contains only a suspicious attachment filename with no other signals.
10. **Link-text mismatch only** — `link-text-mismatch` weight 35 (Link cap 35) → L1_Score 35 → `skeptical` or higher.
11. **Prize + card-details request** — "Congratulations! You have won $1 million. Enter your credit card details to get that money." → hard floor rule 4.10 applies → `poltergeist` (riskScore ≥ 70).
12. **Gift-card scam** — a payment request by gift card with secrecy pressure and no prize or inheritance story → hard floor rule 4.12 applies (riskScore ≥ 40) → `skeptical` or higher.
13. **Inheritance / advance-fee scam** — an inheritance story with a fee paid by wire transfer → hard floor rule 4.10 applies → `poltergeist` (riskScore ≥ 70).

Benign counterexamples (at least 8) must stay `pookie`, for example "Thanks for paying by credit card", "Your order has shipped", "Congratulations on your new job!", "Buy a gift card for your mom" and a bank notice that asks for no details.

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

---

### Requirement 13: Benchmark

**User Story:** As a developer tuning the rules, I want a labelled benchmark with a separate held-out set, so that I can measure detection and false alarms and catch regressions without fooling myself.

#### Acceptance Criteria

1. `backend/engine/benchmark/dev.json` has 60 messages (30 scam, 30 benign) and `heldout.json` has 40 different messages (20 scam, 20 benign), each `{ id, text, label: "scam" | "benign", category }`. All messages are synthetic English, use only fictional brands (Galactibank, Orbitins, Nexamail, VaultPay, TrustLedger) and reserved domains (`.example`, `.test`, `.invalid`) or documentation IP ranges, and name no real people, companies or phone numbers.
2. `npm run benchmark [-- --set=dev|heldout]` scores every message with `score(text)` only (no L2, no L3) and prints: counts by label and verdict, detection rate (scam scored >= 31), strong detection rate (scam scored >= 70), false-alarm rate (benign scored >= 31), detection per scam category, and every miss and false alarm with its score. It also writes that set's section of `benchmark/RESULTS.md`.
3. A test runs the dev set and asserts detection >= `BENCHMARK_MIN_DETECTION_RATE` (0.7) and false alarms <= `BENCHMARK_MAX_FALSE_ALARM_RATE` (0.1), both constants in `config.js`.
4. Rules are tuned on the dev set only. The held-out set is never asserted on in tests and its results are reported as measured.
