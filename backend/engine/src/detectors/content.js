// Content detector: urgency-en, credential-request, suspicious-attachment, prize-lottery,
// advance-fee-scheme, financial-info-request, unusual-payment-method, secrecy-pressure,
// code-sharing-request, mistaken-payment, remote-access-request.
// All Content category. Every signal except suspicious-attachment also produces cursed phrases.
//
// Phrase signals match the NORMALIZED text (util/normalize.js: lowercase, NFKC, no zero-width
// characters, collapsed whitespace, leetspeak and spaced-out letters undone). Every match is
// mapped back to the original input, so evidence and cursed phrases quote what the user pasted.

import {
  W_URGENCY_EN,
  W_CREDENTIAL_REQUEST,
  W_SUSPICIOUS_ATTACHMENT,
  W_PRIZE_LOTTERY,
  W_ADVANCE_FEE_SCHEME,
  W_FINANCIAL_INFO_REQUEST,
  W_UNUSUAL_PAYMENT_METHOD,
  W_SECRECY_PRESSURE,
  W_CODE_SHARING_REQUEST,
  W_MISTAKEN_PAYMENT,
  W_REMOTE_ACCESS_REQUEST,
  URGENCY_EN_PHRASES,
  URGENCY_EXTRA_PHRASES,
  URGENCY_AVOID_THREATS,
  LOCKABLE_THINGS,
  LOCKED_WORDS,
  LOCK_STATE_VERBS,
  DEVICE_WORDS,
  COMPROMISED_WORDS,
  DEADLINE_UNITS,
  DEADLINE_DIGITS_MAX,
  SCARCITY_UNITS,
  SCARCITY_DIGITS_MAX,
  IMMEDIACY_VERBS,
  IMMEDIACY_WORDS,
  IMMEDIACY_PROXIMITY_CHARS,
  DANGEROUS_EXTENSIONS,
  JS_LIBRARY_ALLOWLIST,
  PRIZE_PHRASES,
  CONGRATS_WORDS,
  PRIZE_WORDS,
  RETURN_WORDS,
  PERCENT_DIGITS_MIN,
  PERCENT_DIGITS_MAX,
  LARGE_AMOUNT_THOUSANDS_GROUPS,
  CURRENCY_SYMBOLS,
  CURRENCY_CODES,
  CURRENCY_WORDS,
  LARGE_AMOUNT_WORDS,
  ADVANCE_FEE_PHRASES,
  ADVANCE_FEE_TERMS,
  FEE_STATUS_BEFORE,
  FEE_STATUS_AFTER,
  FEE_MINIMIZERS,
  FEE_PAY_VERBS,
  FEE_PURPOSES,
  FEE_ADVANCE_WORDS,
  RELEASE_WORDS,
  FEE_PROXIMITY_CHARS,
  FEE_STATUS_PROXIMITY_CHARS,
  FINANCIAL_REQUEST_VERBS,
  FINANCIAL_INFO_TERMS,
  NEGATION_WORDS,
  NEGATION_HELPER_WORDS,
  NEGATION_GOVERNED_MAX_WORDS,
  PAYMENT_VERBS,
  PAYMENT_METHODS,
  WIRE_OBJECTS,
  MOBILE_WALLET_TERMS,
  FEE_WORDS,
  INSTRUCTION_VERBS,
  INSTRUCTION_TARGETS,
  INSTRUCTION_PROXIMITY_CHARS,
  HAND_OVER_VERBS,
  HAND_OVER_OBJECTS,
  SECRECY_PHRASES,
  SECRECY_NEGATIONS,
  SECRECY_VERBS,
  SECRECY_PEOPLE,
  CODE_SHARE_VERBS,
  CODE_TERMS,
  CODE_DIGIT_LENGTH_MAX,
  CODE_PRONOUNS,
  CODE_RECIPIENTS,
  CODE_PRONOUN_PROXIMITY_CHARS,
  CODE_SENDERS,
  CODE_SENT_VERBS,
  SECRET_CODE_TERMS,
  PIN_OWNERS,
  PIN_SUFFIXES,
  SECRET_HAND_OVER_VERBS,
  SELF_ADDRESSED_VERBS,
  SECRET_RECIPIENTS,
  SECRET_RECIPIENT_PROXIMITY_CHARS,
  SECRET_GAP_WORDS_MAX,
  GAP_STOP_WORDS,
  DELIVERED_CODE_TERMS,
  DELIVERED_CODE_DIGITS_MIN,
  DELIVERED_CODE_DIGITS_MAX,
  SECRET_REQUEST_VERBS,
  SECRET_REQUEST_TERMS,
  PASSWORD_NOT_SECRET_AFTER,
  PASSWORD_NOT_SECRET_BEFORE,
  INSTRUCTION_LEAD_INS,
  INSTRUCTION_LEAD_INS_MAX,
  INSTRUCTION_MODALS,
  SECRET_REQUEST_GAP_WORDS,
  MISTAKE_ADVERBS,
  MISTAKE_PHRASES,
  MONEY_MOVED_VERBS,
  MISTAKE_CLAIMS,
  RETURN_REQUESTS,
  MISTAKE_PROXIMITY_CHARS,
  INSTALL_VERBS,
  REMOTE_TOOL_WORDS,
  TOOL_WORDS,
  ACCESS_TARGETS,
  REQUEST_PROXIMITY_CHARS,
  PRIZE_PROXIMITY_CHARS,
  MONEY_DIGITS_MAX,
  MONEY_SPACE_MAX,
  MAX_CURSED_PHRASES,
  CURSED_PHRASE_REASONS,
} from "../config.js";
import { makeRedFlag } from "../util/flag.js";
import { normalize } from "../util/normalize.js";

// ---------------------------------------------------------------------------
// Regex builders. Phrases are fixed strings: escaped, joined with "|", single spaces become \s+
// and an apostrophe also accepts the typographic one. \s+ only ever sits between fixed words,
// and every gap between words is a bounded, negated character class, so there is no nesting
// and matching stays linear in the input length.
// ---------------------------------------------------------------------------
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function phrasePattern(phrase) {
  return escapeRegex(phrase).split(" ").join("\\s+").split("'").join("['’]");
}

/** Alternation of whole phrases: `(?:a|b|c)`. */
function anyOf(phrases) {
  return `(?:${phrases.map(phrasePattern).join("|")})`;
}

/** `\b(?:a|b|c)\b` */
function words(phrases) {
  return `\\b${anyOf(phrases)}\\b`;
}

function wordsRegex(phrases) {
  return new RegExp(words(phrases), "gi");
}

const re = (source) => new RegExp(source, "gi");

/**
 * Same sentence, bounded distance: no sentence end and no line break in between. A dot between
 * two digits ("$4.99") is a decimal point, not a sentence end. The two alternatives never match
 * the same character, so this stays linear.
 */
const near = (max) => `(?:[^.!?\\n]|(?<=\\d)\\.(?=\\d)){0,${max}}?`;
const NEAR = near(REQUEST_PROXIMITY_CHARS);

// "never share your card number", "do not pay with gift cards", "we will never ask you to send"
// are warnings, not requests. A negation only counts when it directly governs the verb: at most
// NEGATION_GOVERNED_MAX_WORDS helper words ("ask", "you", "to", "will"...) in between. So
// "Do not delay, enter your card number" is still a request.
const NOT_GOVERNED =
  `(?<!${words(NEGATION_WORDS)}(?:\\s+${anyOf(NEGATION_HELPER_WORDS)}){0,${NEGATION_GOVERNED_MAX_WORDS}}\\s+)`;

// A large money amount with a currency marker: "$1 million", "USD 2.5 billion", "5 million dollars".
const CURRENCY_MARKER =
  `(?:${CURRENCY_SYMBOLS.map(escapeRegex).join("|")}|\\b${anyOf(CURRENCY_CODES)}\\s{0,${MONEY_SPACE_MAX}})`;
const MONEY =
  `(?:${CURRENCY_MARKER}` +
  `\\d[\\d,.]{0,${MONEY_DIGITS_MAX}}\\s{0,${MONEY_SPACE_MAX}}${anyOf(LARGE_AMOUNT_WORDS)}\\b` +
  `|\\b\\d[\\d,.]{0,${MONEY_DIGITS_MAX}}\\s{0,${MONEY_SPACE_MAX}}${anyOf(LARGE_AMOUNT_WORDS)}\\s+${anyOf(CURRENCY_WORDS)}\\b)`;
// The same size written in digits: "$1,000,000", "USD 15,500,000".
const MONEY_DIGITS = `${CURRENCY_MARKER}\\d{1,3}(?:,\\d{3}){${LARGE_AMOUNT_THOUSANDS_GROUPS},${MONEY_DIGITS_MAX}}(?![\\d,])`;

// ---------------------------------------------------------------------------
// urgency-en
// ---------------------------------------------------------------------------
const URGENCY_EN_RE = wordsRegex(URGENCY_EN_PHRASES);
const URGENCY_EXTRA_RE = wordsRegex(URGENCY_EXTRA_PHRASES);
const URGENCY_AVOID_RE = re(`\\bto\\s+avoid\\s+${anyOf(URGENCY_AVOID_THREATS)}\\b`);
// "account is temporarily locked", "account limits have been restricted", "frozen your account".
const URGENCY_LOCKED_RE = re(
  `${words(LOCKABLE_THINGS)}(?:\\s+[a-z]{1,15})?\\s+${anyOf(LOCK_STATE_VERBS)}\\s+${anyOf(LOCKED_WORDS)}\\b` +
    `|${words(LOCKED_WORDS)}\\s+your\\s+${anyOf(LOCKABLE_THINGS)}\\b`,
);
const URGENCY_DEVICE_RE = re(
  `${words(DEVICE_WORDS)}\\s+(?:has\\s+been|have\\s+been|is|was|may\\s+be)\\s+${anyOf(COMPROMISED_WORDS)}\\b`,
);
const URGENCY_DEADLINE_RE = re(`\\bwithin\\s+(?:the\\s+next\\s+)?\\d{1,${DEADLINE_DIGITS_MAX}}\\s*${anyOf(DEADLINE_UNITS)}\\b`);
const URGENCY_SCARCITY_RE = re(
  `\\bonly\\s+\\d{1,${SCARCITY_DIGITS_MAX}}\\s+${anyOf(SCARCITY_UNITS)}\\s+(?:left|remaining)\\b`,
);
const URGENCY_IMMEDIACY_RE = re(
  `${words(IMMEDIACY_VERBS)}${near(IMMEDIACY_PROXIMITY_CHARS)}${words(IMMEDIACY_WORDS)}`,
);

// ---------------------------------------------------------------------------
// credential-request
// ---------------------------------------------------------------------------
// The lookarounds skip words that are part of a hostname, e.g. "login" in "login.galactibank.example".
const CREDENTIAL_EN_RE =
  /(?<![.-])\b(?:passwords?|passcode|log\s*in|sign\s+in|username|one[- ]time\s+(?:code|password)|verify\s+your\s+(?:account|identity)|confirm\s+your\s+identity)\b(?![.-][a-z0-9])/gi;
// Case-sensitive so the ordinary word "pin" never fires. Runs on the case-preserving text.
const CREDENTIAL_UPPER_RE = /\b(?:PIN|OTP)\b/g;
// A warning such as "Do not share your PIN" or "We will never ask you to share your card number,
// PIN or password": a negation that directly governs a request verb, plus the rest of that clause
// (bounded, same sentence). Credential words inside it are not requests.
const NEGATED_REQUEST_RE = re(
  `${words(NEGATION_WORDS)}(?:\\s+${anyOf(NEGATION_HELPER_WORDS)}){0,${NEGATION_GOVERNED_MAX_WORDS}}\\s+` +
    `${anyOf([...FINANCIAL_REQUEST_VERBS, ...CODE_SHARE_VERBS, ...SECRET_HAND_OVER_VERBS, ...SECRET_REQUEST_VERBS])}` +
    `\\b(?:[^.!?\\n]|(?<=\\d)\\.(?=\\d)){0,${REQUEST_PROXIMITY_CHARS}}`,
);
// A code being delivered, not requested: "Your OTP is 482913", "one-time password: 5590".
const DELIVERED_CODE_RE = re(
  `${words(DELIVERED_CODE_TERMS)}(?:\\s+is\\s*:?|\\s*:)\\s*\\d{${DELIVERED_CODE_DIGITS_MIN},${DELIVERED_CODE_DIGITS_MAX}}\\b`,
);

// ---------------------------------------------------------------------------
// suspicious-attachment (raw text, like the link detector)
// ---------------------------------------------------------------------------
const ATTACHMENT_RE = new RegExp(
  String.raw`(?<![\/\w@.-])(\w[\w.-]{0,100})\.(${DANGEROUS_EXTENSIONS.join("|")})(?=["'\s),;!?]|\.(?:\s|$)|$)`,
  "gi",
);
const JS_EXTENSION = "js";

// ---------------------------------------------------------------------------
// prize-lottery
// ---------------------------------------------------------------------------
const PRIZE_RE = wordsRegex(PRIZE_PHRASES);
// "Congratulations" alone is harmless ("Congratulations on your new job!"); it only counts when a
// prize word follows shortly after. The lookahead keeps the cursed phrase to the word itself.
const CONGRATS_RE = new RegExp(
  `\\b${anyOf(CONGRATS_WORDS)}\\b(?=[\\s\\S]{0,${PRIZE_PROXIMITY_CHARS}}?\\b${anyOf(PRIZE_WORDS)}\\b)`,
  "gi",
);
const MONEY_RE = re(`${MONEY}|${MONEY_DIGITS}`);
// "400% returns": a two-digit-or-more percentage promised as return or profit.
const PERCENT_RETURN_RE = re(`\\b\\d{${PERCENT_DIGITS_MIN},${PERCENT_DIGITS_MAX}}\\s?%\\s+${anyOf(RETURN_WORDS)}\\b`);

// ---------------------------------------------------------------------------
// advance-fee-scheme
// ---------------------------------------------------------------------------
const ADVANCE_FEE_RE = wordsRegex(ADVANCE_FEE_PHRASES);
const TRANSFER_OF_MONEY_RE = re(`\\btransfer\\s+of\\s+(?:the\\s+sum\\s+of\\s+)?${MONEY}`);
// A fee presented as the condition for getting something.
const FEE_TERM = words(ADVANCE_FEE_TERMS);
const FEE_CONDITION_RE = re(
  [
    `${words(FEE_STATUS_BEFORE)}${near(FEE_STATUS_PROXIMITY_CHARS)}${FEE_TERM}`, // "unpaid customs charge"
    `${FEE_TERM}${near(FEE_STATUS_PROXIMITY_CHARS)}\\b(?:is|are)\\s+(?:still\\s+)?${anyOf(FEE_STATUS_AFTER)}\\b`, // "fee is required"
    `${words(FEE_MINIMIZERS)}\\s+${anyOf(FEE_PAY_VERBS)}\\b${near(FEE_PROXIMITY_CHARS)}${FEE_TERM}`, // "just pay a $4.99 shipping fee"
    `\\bsmall\\b${near(FEE_STATUS_PROXIMITY_CHARS)}${FEE_TERM}`, // "a small handling fee"
    `${FEE_TERM}${near(FEE_PROXIMITY_CHARS)}\\bto\\s+${anyOf(FEE_PURPOSES)}\\b`, // "deposit upfront to activate"
    `${FEE_TERM}${near(FEE_PROXIMITY_CHARS)}\\bbefore\\b${near(FEE_PROXIMITY_CHARS)}${words(RELEASE_WORDS)}`, // "cost ... before the funds are released"
    `${FEE_TERM}${near(FEE_STATUS_PROXIMITY_CHARS)}${words(FEE_ADVANCE_WORDS)}`, // "deposit upfront"
  ].join("|"),
);

// ---------------------------------------------------------------------------
// financial-info-request
// ---------------------------------------------------------------------------
// Request verb then card or bank term ("Enter your credit card details"), or the term then the
// verb in the same sentence ("Card number and CVV: send them now"). A term with no request verb
// ("Thanks for paying by credit card") does not fire.
const FINANCIAL_VERB = `${NOT_GOVERNED}${words(FINANCIAL_REQUEST_VERBS)}`;
const FINANCIAL_TERM = words(FINANCIAL_INFO_TERMS);
const FINANCIAL_INFO_RE = re(`${FINANCIAL_VERB}${NEAR}${FINANCIAL_TERM}|${FINANCIAL_TERM}${NEAR}${FINANCIAL_VERB}`);

// ---------------------------------------------------------------------------
// unusual-payment-method
// ---------------------------------------------------------------------------
const PAYMENT_VERB = `${NOT_GOVERNED}${words(PAYMENT_VERBS)}`;
const PAYMENT_METHOD_RE = re(`${PAYMENT_VERB}${NEAR}\\b${anyOf(PAYMENT_METHODS)}s?\\b`);
// "wire the money to my agent"
const WIRE_MONEY_RE = re(`${NOT_GOVERNED}\\bwire\\s+(?:the\\s+|me\\s+|us\\s+|my\\s+|your\\s+)?${anyOf(WIRE_OBJECTS)}\\b`);
// A mobile wallet is ordinary; paying a "fee" through one is the scam pattern.
const WALLET = words(MOBILE_WALLET_TERMS);
const FEE = words(FEE_WORDS);
const WALLET_FEE_RE = re(`${PAYMENT_VERB}${NEAR}(?:${WALLET}${NEAR}${FEE}|${FEE}${NEAR}${WALLET})`);

// An explicit instruction to hand the payment over: "send it to me", "pay to this account",
// "send me the codes". Not a signal on its own; it feeds the unusual-payment-method floor.
const PAYMENT_INSTRUCTION_RE = re(
  `${NOT_GOVERNED}${words(INSTRUCTION_VERBS)}${near(INSTRUCTION_PROXIMITY_CHARS)}\\bto\\s+${anyOf(INSTRUCTION_TARGETS)}\\b` +
    `|${NOT_GOVERNED}${words(HAND_OVER_VERBS)}\\s+(?:me|us)\\s+(?:the\\s+|a\\s+)?(?:[a-z]{1,15}\\s+)?${anyOf(HAND_OVER_OBJECTS)}\\b`,
);

// ---------------------------------------------------------------------------
// secrecy-pressure
// ---------------------------------------------------------------------------
const SECRECY_RE = wordsRegex(SECRECY_PHRASES);
// "do not discuss this with your family", "don't tell your kids"
const SECRECY_PEOPLE_RE = re(`${words(SECRECY_NEGATIONS)}\\s+${anyOf(SECRECY_VERBS)}\\s+${anyOf(SECRECY_PEOPLE)}\\b`);

// ---------------------------------------------------------------------------
// code-sharing-request
// ---------------------------------------------------------------------------
// "the code we texted you", "the code I just sent to you"
const SENT_CODE = `\\bcode\\s+(?:that\\s+)?${anyOf(CODE_SENDERS)}\\s+(?:just\\s+)?${anyOf(CODE_SENT_VERBS)}\\b`;
const CODE =
  `(?:\\b\\d{1,${CODE_DIGIT_LENGTH_MAX}}[- ]digit\\s+(?:[a-z-]{1,20}\\s+)?code\\b|${words(CODE_TERMS)}|${SENT_CODE})`;
// "reply with the 6-digit code", "share the verification code"
const CODE_SHARE_RE = re(`${NOT_GOVERNED}${words(CODE_SHARE_VERBS)}${NEAR}${CODE}`);

// Secret-code family: OTP, PIN, 2FA code and the CODE terms above, but only with a hand-over
// context, so "Send the OTP" alone stays a plain credential-request.
// "pin" counts after an owner word or a list comma ("your PIN", "password, PIN") or before
// "code"/"number"; "pin this post" does not.
const PIN = `(?:(?:,\\s?|\\b${anyOf(PIN_OWNERS)}\\s+)pin\\b|\\bpin\\s+${anyOf(PIN_SUFFIXES)}\\b)`;
const SECRET_CODE = `(?:${words(SECRET_CODE_TERMS)}|${PIN}|${CODE})`;
/**
 * Verb -> object gap: at most `maxWords` words in the same sentence, commas allowed (lists),
 * and no word that opens a new clause ("tell us IF you did not get your OTP"). Word characters,
 * commas and spaces are disjoint classes, so the gap is unambiguous and matching stays linear.
 */
const wordGap = (maxWords) =>
  `(?:,?\\s(?!${anyOf(GAP_STOP_WORDS)}\\b)[a-z0-9'’-]{1,20}){0,${maxWords}}?,?\\s`;
const SECRET_GAP = wordGap(SECRET_GAP_WORDS_MAX);
const HAND_OVER = `${NOT_GOVERNED}${words(SECRET_HAND_OVER_VERBS)}`;
const SECRET_RECIPIENT = anyOf(SECRET_RECIPIENTS);
const SECRET_CODE_SHARE_RE = re(
  [
    // "Send us your password and otp", "give us your login password, PIN and the 2FA code"
    `${HAND_OVER}\\s+${SECRET_RECIPIENT}\\b${SECRET_GAP}${SECRET_CODE}`,
    // "Please send your OTP to this number"
    `${HAND_OVER}${SECRET_GAP}${SECRET_CODE}${near(SECRET_RECIPIENT_PROXIMITY_CHARS)}\\bto\\s+${SECRET_RECIPIENT}\\b`,
    // "Reply with your PIN" (the reply itself goes back to the sender)
    `${NOT_GOVERNED}${words(SELF_ADDRESSED_VERBS)}${SECRET_GAP}${SECRET_CODE}`,
  ].join("|"),
);

// "We sent you a verification code ... Please forward it to us": the code comes first, then a
// pronoun hand-over within CODE_PRONOUN_PROXIMITY_CHARS (may cross a sentence end).
const CODE_MENTION_RE = re(SECRET_CODE);
// Floor 4.16 (not a signal): an instruction to the reader to hand over a password, PIN,
// passcode, login or security answer. Instruction = the verb opens a sentence or clause
// (optionally after "please", "kindly"...) or follows "you must", "we need you to"...
// "We will never ask you to send your password" and "If you share your password" are not.
const LEAD_INS = `(?:${anyOf(INSTRUCTION_LEAD_INS)}\\s+){0,${INSTRUCTION_LEAD_INS_MAX}}`;
const CLAUSE_START = `(?<=^|[.!?:;,(\\n"“]\\s?)`;
const SECRET_TERM =
  `(?:(?<!\\b${anyOf(PASSWORD_NOT_SECRET_BEFORE)}\\s)${anyOf(SECRET_REQUEST_TERMS)}\\b` +
  `(?!\\s+${anyOf(PASSWORD_NOT_SECRET_AFTER)}\\b)|${PIN})`;
const SECRET_REQUEST_RE = re(
  `(?:${CLAUSE_START}|\\b${anyOf(INSTRUCTION_MODALS)}\\s+)${LEAD_INS}${words(SECRET_REQUEST_VERBS)}` +
    `(?:\\s+${SECRET_RECIPIENT}\\b)?${wordGap(SECRET_REQUEST_GAP_WORDS)}${SECRET_TERM}`,
);

const PRONOUN_HAND_OVER_RE = re(
  `${NOT_GOVERNED}${words(CODE_SHARE_VERBS)}\\s+${anyOf(CODE_PRONOUNS)}\\s+(?:back\\s+)?to\\s+${anyOf(CODE_RECIPIENTS)}\\b`,
);

// ---------------------------------------------------------------------------
// mistaken-payment
// ---------------------------------------------------------------------------
const MISTAKE_CLAIM_RE = re(
  `${words(MISTAKE_ADVERBS)}\\s+${anyOf(MONEY_MOVED_VERBS)}\\b` +
    `|${words(MONEY_MOVED_VERBS)}${NEAR}${words(MISTAKE_PHRASES)}` +
    `|${words(MISTAKE_CLAIMS)}`,
);
const RETURN_REQUEST_RE = re(`${NOT_GOVERNED}${words(RETURN_REQUESTS)}`);

// ---------------------------------------------------------------------------
// remote-access-request
// ---------------------------------------------------------------------------
const REMOTE_ACCESS_RE = re(
  `${NOT_GOVERNED}${words(INSTALL_VERBS)}${NEAR}${words(REMOTE_TOOL_WORDS)}${near(FEE_STATUS_PROXIMITY_CHARS)}${words(TOOL_WORDS)}` +
    `|\\b(?:give|grant|allow)\\b${NEAR}\\b(?:remote\\s+)?(?:access|control)\\s+(?:to|of)\\s+your\\s+${anyOf(ACCESS_TARGETS)}\\b` +
    `|\\bremote\\s+(?:access|control)\\s+(?:to|of)\\s+your\\s+${anyOf(ACCESS_TARGETS)}\\b`,
);

// ---------------------------------------------------------------------------
// Matching on the normalized text
// ---------------------------------------------------------------------------
/**
 * All matches of one regex on the normalized text, mapped back to the original input.
 * Case-sensitive regexes (no `i` flag, e.g. PIN/OTP) run on the case-preserving text.
 */
function findAll(norm, regex) {
  const haystack = regex.flags.includes("i") ? norm.text : norm.cased;
  const found = [];
  for (const m of haystack.matchAll(regex)) {
    const [start, end] = norm.toOriginal(m.index, m.index + m[0].length);
    found.push({ text: norm.input.slice(start, end), index: start, nStart: m.index, nEnd: m.index + m[0].length });
  }
  return found;
}

/** All matches of the given regexes, ordered by position in the original input. */
function matchesInOrder(norm, regexes) {
  return regexes.flatMap((r) => findAll(norm, r)).sort((a, b) => a.index - b.index);
}

function signalFrom(id, weight, matches) {
  if (matches.length === 0) return { flag: null, phrases: [] };
  const reason = CURSED_PHRASE_REASONS[id];
  return {
    flag: makeRedFlag(id, weight, matches[0].text),
    phrases: matches.map((m) => ({ text: m.text, reason })),
  };
}

function phraseSignal(norm, id, weight, regexes) {
  return signalFrom(id, weight, matchesInOrder(norm, regexes));
}

/** Drops matches that start inside one of the given normalized spans. */
function outside(matches, spans) {
  return matches.filter((m) => !spans.some((s) => m.nStart >= s.nStart && m.nStart < s.nEnd));
}

/**
 * Matches of `second` that start at most `maxGap` normalized characters after the end of a
 * match of `first`, each returned together with that first match. Linear: both lists are
 * already sorted, so one forward pass pairs them.
 */
function followedBy(firstMatches, secondMatches, maxGap) {
  const pairs = [];
  let i = 0;
  let lastFirst = null;
  for (const s of secondMatches) {
    while (i < firstMatches.length && firstMatches[i].nEnd <= s.nStart) lastFirst = firstMatches[i++];
    if (lastFirst !== null && s.nStart - lastFirst.nEnd <= maxGap) pairs.push([lastFirst, s]);
  }
  return pairs;
}

function detectAttachment(input) {
  for (const m of input.matchAll(ATTACHMENT_RE)) {
    const base = m[1].toLowerCase();
    const ext = m[2].toLowerCase();
    if (ext === JS_EXTENSION && JS_LIBRARY_ALLOWLIST.includes(base)) continue;
    return makeRedFlag("suspicious-attachment", W_SUSPICIOUS_ATTACHMENT, m[0]);
  }
  return null;
}

function detectCodeSharing(norm) {
  const direct = [...findAll(norm, CODE_SHARE_RE), ...findAll(norm, SECRET_CODE_SHARE_RE)];
  const pronoun = followedBy(
    findAll(norm, CODE_MENTION_RE),
    findAll(norm, PRONOUN_HAND_OVER_RE),
    CODE_PRONOUN_PROXIMITY_CHARS,
  ).map(([, handOver]) => handOver);
  const matches = [...direct, ...pronoun].sort((a, b) => a.index - b.index);
  return signalFrom("code-sharing-request", W_CODE_SHARING_REQUEST, matches);
}

function detectMistakenPayment(norm) {
  const pairs = followedBy(findAll(norm, MISTAKE_CLAIM_RE), findAll(norm, RETURN_REQUEST_RE), MISTAKE_PROXIMITY_CHARS);
  const matches = pairs.flatMap(([claim, request]) => [claim, request]);
  return signalFrom("mistaken-payment", W_MISTAKEN_PAYMENT, matches);
}

function dedupeAndCap(phrases) {
  const seen = new Set();
  const out = [];
  for (const p of phrases) {
    const key = p.text.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
    if (out.length >= MAX_CURSED_PHRASES) break;
  }
  return out;
}

/**
 * @param {string} input
 * @returns {{ flags: object[], cursedPhrases: object[], paymentInstruction: boolean }}
 */
export function detectContent(input) {
  const norm = normalize(input);
  const urgencyEn = phraseSignal(norm, "urgency-en", W_URGENCY_EN, [
    URGENCY_EN_RE,
    URGENCY_EXTRA_RE,
    URGENCY_AVOID_RE,
    URGENCY_LOCKED_RE,
    URGENCY_DEVICE_RE,
    URGENCY_DEADLINE_RE,
    URGENCY_SCARCITY_RE,
    URGENCY_IMMEDIACY_RE,
  ]);
  const notRequests = [...findAll(norm, NEGATED_REQUEST_RE), ...findAll(norm, DELIVERED_CODE_RE)];
  const credential = signalFrom(
    "credential-request",
    W_CREDENTIAL_REQUEST,
    outside(matchesInOrder(norm, [CREDENTIAL_EN_RE, CREDENTIAL_UPPER_RE]), notRequests),
  );
  const prize = phraseSignal(norm, "prize-lottery", W_PRIZE_LOTTERY, [PRIZE_RE, CONGRATS_RE, MONEY_RE, PERCENT_RETURN_RE]);
  const advanceFee = phraseSignal(norm, "advance-fee-scheme", W_ADVANCE_FEE_SCHEME, [
    ADVANCE_FEE_RE,
    TRANSFER_OF_MONEY_RE,
    FEE_CONDITION_RE,
  ]);
  const financialInfo = phraseSignal(norm, "financial-info-request", W_FINANCIAL_INFO_REQUEST, [FINANCIAL_INFO_RE]);
  const payment = phraseSignal(norm, "unusual-payment-method", W_UNUSUAL_PAYMENT_METHOD, [
    PAYMENT_METHOD_RE,
    WIRE_MONEY_RE,
    WALLET_FEE_RE,
  ]);
  const secrecy = phraseSignal(norm, "secrecy-pressure", W_SECRECY_PRESSURE, [SECRECY_RE, SECRECY_PEOPLE_RE]);
  const codeSharing = detectCodeSharing(norm);
  const mistakenPayment = detectMistakenPayment(norm);
  const remoteAccess = phraseSignal(norm, "remote-access-request", W_REMOTE_ACCESS_REQUEST, [REMOTE_ACCESS_RE]);

  // New signals come after the original ones so existing flag and phrase order is unchanged.
  const flags = [
    urgencyEn.flag,
    credential.flag,
    detectAttachment(input),
    prize.flag,
    advanceFee.flag,
    financialInfo.flag,
    payment.flag,
    secrecy.flag,
    codeSharing.flag,
    mistakenPayment.flag,
    remoteAccess.flag,
  ].filter(Boolean);
  const cursedPhrases = dedupeAndCap([
    ...urgencyEn.phrases,
    ...credential.phrases,
    ...prize.phrases,
    ...advanceFee.phrases,
    ...financialInfo.phrases,
    ...payment.phrases,
    ...secrecy.phrases,
    ...codeSharing.phrases,
    ...mistakenPayment.phrases,
    ...remoteAccess.phrases,
  ]);
  return {
    flags,
    cursedPhrases,
    paymentInstruction: findAll(norm, PAYMENT_INSTRUCTION_RE).length > 0,
    secretRequest: findAll(norm, SECRET_REQUEST_RE).length > 0,
  };
}
