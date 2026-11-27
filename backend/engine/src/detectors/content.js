// Content detector: urgency-en, credential-request, suspicious-attachment, prize-lottery,
// advance-fee-scheme, financial-info-request, unusual-payment-method, secrecy-pressure,
// code-sharing-request, mistaken-payment, remote-access-request, and the scam families
// delivery-scam, seed-phrase-request, investment-guarantee, task-job-scam, official-fine-threat,
// recruiter-bait, and from round 2 utility-disconnection-threat, payment-failed-lure,
// account-security-lure (each needs several cues together; some also need a link in the message).
// advance-fee-scheme also covers an upfront fee for a job (context.jobFee, floor 4.26).
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
  W_DELIVERY_SCAM,
  W_DELIVERY_SCAM_SHORTENER,
  W_SEED_PHRASE_REQUEST,
  W_INVESTMENT_GUARANTEE,
  W_TASK_JOB_SCAM,
  W_OFFICIAL_FINE_THREAT,
  W_RECRUITER_BAIT,
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
  DEADLINE_EXTRA_UNITS,
  IN_DEADLINE_UNITS,
  DEADLINE_NOT_AFTER,
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
  CREDENTIAL_REQUEST_VERBS,
  CREDENTIAL_REQUEST_PROXIMITY_CHARS,
  LOGIN_NOUN_BEFORE,
  LOGIN_NOUN_AFTER,
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
  REMOTE_TOOL_NAMES,
  REMOTE_NAMED_VERBS,
  MALWARE_WORDS,
  MALWARE_EVENT_WORDS,
  SCARE_DEVICE_WORDS,
  AT_RISK_SUBJECTS,
  SCARE_COUNT_WORDS,
  SUPPORT_CALL_VERBS,
  SUPPORT_WORDS,
  REMOTE_SESSION_PHRASES,
  TOOL_WORDS,
  ACCESS_TARGETS,
  REQUEST_PROXIMITY_CHARS,
  PRIZE_PROXIMITY_CHARS,
  MONEY_DIGITS_MAX,
  MONEY_SPACE_MAX,
  MAX_CURSED_PHRASES,
  CURSED_PHRASE_REASONS,
  DELIVERY_CONTEXT_WORDS,
  DELIVERY_ITEMS,
  DELIVERY_FAILED_STATES,
  DELIVERY_NOT_DELIVERED,
  DELIVERY_ADDRESS_PROBLEMS,
  DELIVERY_UPDATE_VERBS,
  DELIVERY_DETAILS,
  SEED_REQUEST_VERBS,
  SEED_NOT_AFTER,
  SEED_TERMS,
  SEED_WORD_COUNTS,
  WALLET_FIX_VERBS,
  WALLET_WORDS,
  INVESTMENT_PROMISE_PHRASES,
  GUARANTEE_WORDS,
  PROMISE_NEGATIONS,
  INVESTMENT_RESULT_WORDS,
  MULTIPLY_VERBS,
  RETURN_PERIODS,
  INVESTMENT_CONTEXT_PHRASES,
  MONEY_SYMBOLS,
  MONEY_CODES,
  AMOUNT_DIGITS_MAX,
  TASK_PAY_VERBS,
  TASK_PAY_PERIODS,
  TASK_EASY_PHRASES,
  TASK_TIME_UNITS,
  TASK_ACTIONS,
  TASK_OBJECTS,
  TASK_WORKER_PHRASES,
  TASK_REPLY_VERBS,
  TASK_REPLY_WORDS,
  TASK_CHAT_PHRASES,
  FINE_TERMS,
  FINE_PAY_VERBS,
  FINE_LEGAL_THREATS,
  FINE_DEADLINE_WORDS,
  RECRUITER_INTROS,
  RECRUITER_INTRO_LINKS,
  RECRUITER_TITLES,
  JOB_WORDS,
  JOB_DOC_WORDS,
  JOB_DOC_LINK_PARTS,
  RECRUITER_TRUSTED_DOMAINS,
  W_UTILITY_DISCONNECTION_THREAT,
  W_PAYMENT_FAILED_LURE,
  W_ACCOUNT_SECURITY_LURE,
  W_UNFAMILIAR_LINK_PRESSURE,
  W_TECH_SUPPORT_SCAM,
  PRESSURE_DEADLINE_PHRASES,
  PRESSURE_DEADLINE_UNITS,
  PRESSURE_THREAT_WORDS,
  PRESSURE_ASK_WORDS,
  UTILITY_WORDS,
  DISCONNECT_PHRASES,
  DISCONNECT_SOFT_WORDS,
  DISCONNECT_TIME_WORDS,
  UNPAID_WORDS,
  BILL_WORDS,
  PAY_NOW_VERBS,
  PAY_NOW_WORDS,
  PAY_NOW_GAP_WORDS,
  PAYMENT_SUBJECTS,
  PAYMENT_FAILED_STATES,
  CARD_FAILED_STATES,
  PAYMENT_UPDATE_VERBS,
  PAYMENT_DETAIL_WORDS,
  ACCOUNT_THREAT_THINGS,
  ACCOUNT_THREAT_STATES,
  LOGIN_ACTORS,
  LOGIN_VERBS,
  LOGIN_ODD_WORDS,
  LOGIN_EVENTS,
  SECURE_VERBS,
  SECURE_OBJECTS,
  JOB_FEE_KINDS,
  JOB_FEE_WORDS,
  JOB_SLOT_VERBS,
  JOB_SLOT_WORDS,
  JOB_FEE_NEGATIONS,
  JOB_CONTEXT_EXTRA,
  REMOTE_WORK_PHRASES,
  REMOTE_PAY_PERIODS,
  NO_EXPERIENCE_WORDS,
  NO_EXPERIENCE_FILLERS,
  CHAT_APPS,
  CHAT_CONTACT_VERBS,
  CHAT_PROXIMITY_CHARS,
} from "../config.js";
import { makeRedFlag } from "../util/flag.js";
import { normalize } from "../util/normalize.js";
import { findLinks } from "../util/links.js";
import { registrableDomain } from "../util/hostname.js";
import { isLureDomain, hasRiskyTld, isUnfamiliarDomain } from "../util/lure.js";
import { DEFAULT_BRANDS } from "../brands.js";

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
// "within 2 days", "within 12 hr", "in 24 hrs", but not "arrives in 24 hours" or "expires in 2 hours".
const DEADLINE_ALLOWED = `(?<!\\b${anyOf(DEADLINE_NOT_AFTER)}\\s)`;
const URGENCY_DEADLINE_EXTRA_RE = re(
  `${DEADLINE_ALLOWED}\\bwithin\\s+(?:the\\s+next\\s+)?\\d{1,${DEADLINE_DIGITS_MAX}}\\s*${anyOf(DEADLINE_EXTRA_UNITS)}\\b` +
    `|${DEADLINE_ALLOWED}\\bin\\s+(?:the\\s+next\\s+)?\\d{1,${DEADLINE_DIGITS_MAX}}\\s*${anyOf(IN_DEADLINE_UNITS)}\\b`,
);
const URGENCY_SCARCITY_RE = re(
  `\\bonly\\s+\\d{1,${SCARCITY_DIGITS_MAX}}\\s+${anyOf(SCARCITY_UNITS)}\\s+(?:left|remaining)\\b`,
);
const URGENCY_IMMEDIACY_RE = re(
  `${words(IMMEDIACY_VERBS)}${near(IMMEDIACY_PROXIMITY_CHARS)}${words(IMMEDIACY_WORDS)}`,
);

// ---------------------------------------------------------------------------
// credential-request
// ---------------------------------------------------------------------------
// Three kinds of match. The lookarounds skip words that are part of a hostname, e.g. "login" in
// "login.galactibank.example".
// 1. An instruction that is a request on its own: "verify your account", "confirm your identity",
// "re-validate your mailbox".
const CREDENTIAL_ACTION_RE =
  /\b(?:(?:re-?)?(?:verify|validate)\s+your\s+(?:account|identity|mailbox|login)|confirm\s+your\s+(?:identity|login))\b/gi;
// 2. "log in" / "sign in" used as an instruction, not as a noun ("a login from a new device").
const CREDENTIAL_LOGIN_RE = re(
  `(?<!\\b${anyOf(LOGIN_NOUN_BEFORE)}\\s+)(?<![.-])\\b(?:log\\s*in|sign\\s+in)\\b(?![.-][a-z0-9])` +
    `(?!\\s+${anyOf(LOGIN_NOUN_AFTER)}\\b)`,
);
// 3. A bare credential word. Only a request when CREDENTIAL_REQUEST_VERB_RE comes before it in the
// same sentence (see credentialRequests). PIN/OTP are case-sensitive so the word "pin" never fires.
const CREDENTIAL_NOUN_RE = /(?<![.-])\b(?:passwords?|passcode|username|one[- ]time\s+(?:code|password))\b(?![.-][a-z0-9])/gi;
const CREDENTIAL_UPPER_RE = /\b(?:PIN|OTP)\b/g;
const CREDENTIAL_REQUEST_VERB_RE = new RegExp(words(CREDENTIAL_REQUEST_VERBS), "i");
// "Your PIN please": the credential word directly followed by please.
const CREDENTIAL_PLEASE_RE = /^,?\s*(?:please|pls|plz)\b/i;
const CREDENTIAL_PLEASE_LOOKAHEAD = 10;

/** The same-sentence text up to CREDENTIAL_REQUEST_PROXIMITY_CHARS before position `end`. */
function sentenceBefore(text, end) {
  let start = Math.max(0, end - CREDENTIAL_REQUEST_PROXIMITY_CHARS);
  for (let i = end - 1; i >= start; i--) {
    const c = text[i];
    // "!", "?", a newline, or a "." that ends a sentence (followed by a space), not one in
    // "4.99" or "secure.example".
    if (c === "!" || c === "?" || c === "\n" || (c === "." && /\s/.test(text[i + 1] ?? " "))) {
      start = i + 1;
      break;
    }
  }
  return text.slice(start, end);
}

/** credential-request matches: actions, login instructions, and requested credential words. */
function credentialRequests(norm) {
  const nouns = matchesInOrder(norm, [CREDENTIAL_NOUN_RE, CREDENTIAL_UPPER_RE]).filter(
    (m) =>
      CREDENTIAL_REQUEST_VERB_RE.test(sentenceBefore(norm.text, m.nStart)) ||
      CREDENTIAL_PLEASE_RE.test(norm.text.slice(m.nEnd, m.nEnd + CREDENTIAL_PLEASE_LOOKAHEAD)),
  );
  return [...matchesInOrder(norm, [CREDENTIAL_ACTION_RE, CREDENTIAL_LOGIN_RE]), ...nouns].sort(
    (a, b) => a.index - b.index,
  );
}
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
    `|\\bremote\\s+(?:access|control)\\s+(?:to|of)\\s+your\\s+${anyOf(ACCESS_TARGETS)}\\b` +
    // a named remote-control tool with an instruction: "install AnyDesk", "open TeamViewer"
    `|${NOT_GOVERNED}${words(REMOTE_NAMED_VERBS)}${NEAR}${words(REMOTE_TOOL_NAMES)}`,
);

// ---------------------------------------------------------------------------
// Scam families. Every family needs several cues in the same message; links come from
// util/links.js (defanged links count).
// ---------------------------------------------------------------------------
const RANGE_SEP = `\\s?(?:-|–|—|to|and)\\s?`;
const NUM = `(?<![\\d,.])\\d[\\d,.]{0,${AMOUNT_DIGITS_MAX}}k?`;
const SYM = `(?:${MONEY_SYMBOLS.map(escapeRegex).join("|")})`;
const CODES = words(MONEY_CODES);
// One amount with a currency marker: "$200", "3,500 BDT", "38k usdt".
const CUR_AMOUNT = `(?:${SYM}\\s?${NUM}|${NUM}\\s?${CODES})`;
// An amount or a range with a currency marker: "$50-$200", "2,000–6,000 BDT".
const CUR_RANGE =
  `(?:${SYM}\\s?${NUM}(?:${RANGE_SEP}(?:${SYM}\\s?)?${NUM})?(?:\\s?${CODES})?` +
  `|${NUM}(?:${RANGE_SEP}${NUM})?\\s?${CODES})`;

// delivery-scam
const DELIVERY_CONTEXT_RE = wordsRegex(DELIVERY_CONTEXT_WORDS);
const DELIVERY_FAILURE_RE = re(
  [
    words(DELIVERY_NOT_DELIVERED), // "could not be delivered"
    // "Delivery failed", "your parcel is on hold"
    `${words(DELIVERY_ITEMS)}\\s+(?:(?:is|was|has\\s+been|is\\s+now|is\\s+currently|has)\\s+)?${anyOf(DELIVERY_FAILED_STATES)}\\b`,
    `${words(DELIVERY_ADDRESS_PROBLEMS)}\\s+(?:shipping\\s+|delivery\\s+|house\\s+)?address\\b`, // "incomplete address"
    `${NOT_GOVERNED}${words(DELIVERY_UPDATE_VERBS)}\\s+(?:your\\s+|the\\s+)?${anyOf(DELIVERY_DETAILS)}\\b`, // "update shipping details"
  ].join("|"),
);

// seed-phrase-request
const SEED_TERM =
  `(?:${words(SEED_TERMS)}` +
  `|\\b${anyOf(SEED_WORD_COUNTS)}[- ]words?\\b(?:\\s+(?:recovery\\s+|seed\\s+|secret\\s+|backup\\s+)?(?:phrase|key|code)\\b)?)`;
const SEED_VERB = `${NOT_GOVERNED}(?<!\\b${anyOf(SEED_NOT_AFTER)}\\s)${words(SEED_REQUEST_VERBS)}`;
const SEED_REQUEST_RE = re(`${SEED_VERB}${NEAR}${SEED_TERM}`);
// "Validate your wallet at <link>": counts only when the message has a link.
const WALLET_FIX_RE = re(
  `${NOT_GOVERNED}(?<!\\b${anyOf(SEED_NOT_AFTER)}\\s)${words(WALLET_FIX_VERBS)}\\s+(?:your\\s+|the\\s+)?(?:[a-z]{1,15}\\s+)?${anyOf(WALLET_WORDS)}\\b`,
);

// investment-guarantee
const NOT_PROMISED = `(?<!\\b${anyOf(PROMISE_NEGATIONS)}\\s)`;
const INVEST_PROMISE_RE = re(
  [
    `${NOT_PROMISED}${words(INVESTMENT_PROMISE_PHRASES)}`, // "guaranteed returns", "risk-free"
    `${NOT_PROMISED}${words(GUARANTEE_WORDS)}\\s+(?:[a-z]{1,15}\\s+)?${anyOf(INVESTMENT_RESULT_WORDS)}\\b`, // "guaranteed futures trades"
    `${words(MULTIPLY_VERBS)}\\s+(?:your\\s+|just\\s+|only\\s+)?${CUR_AMOUNT}\\s+(?:into|to)\\s+${CUR_AMOUNT}`, // "turn $200 into $3,500"
    `\\b\\d{1,3}(?:\\.\\d{1,2})?\\s?%\\s+${anyOf(RETURN_PERIODS)}\\b`, // "5% daily"
  ].join("|"),
);
const INVEST_CONTEXT_RE = wordsRegex(INVESTMENT_CONTEXT_PHRASES);

// task-job-scam
const TASK_PAY_RE = re(
  `${words(TASK_PAY_VERBS)}\\s+(?:up\\s+to\\s+|between\\s+|from\\s+)?${CUR_RANGE}\\s*` +
    `(?:${anyOf(TASK_PAY_PERIODS)}\\b|\\/\\s?(?:day|hour|hr|task)\\b)`,
);
const TASK_EASY_RE = re(
  `${words(TASK_EASY_PHRASES)}|\\b\\d{1,3}\\s?(?:-|–|—|to)\\s?\\d{1,3}\\s*${anyOf(TASK_TIME_UNITS)}\\b`, // "30–45 mins"
);
const TASK_WORK_RE = re(
  `${words(TASK_WORKER_PHRASES)}|${words(TASK_ACTIONS)}\\s+(?:[a-z]{1,15}\\s+)?${anyOf(TASK_OBJECTS)}\\b`,
);
const TASK_REPLY_RE = re(
  `${words(TASK_REPLY_VERBS)}\\s+["'“‘]?${anyOf(TASK_REPLY_WORDS)}\\b|${words(TASK_CHAT_PHRASES)}`,
);

// official-fine-threat
const FINE_TERM_RE = wordsRegex(FINE_TERMS);
const FINE_PAY_RE = re(`${NOT_GOVERNED}${words(FINE_PAY_VERBS)}`);
const FINE_LEGAL_RE = wordsRegex(FINE_LEGAL_THREATS);
const FINE_DEADLINE_WORDS_RE = wordsRegex(FINE_DEADLINE_WORDS);

// recruiter-bait
const RECRUITER_RE = re(
  `${words(RECRUITER_INTROS)}\\s+(?!(?:a|an|the|your|our|my|just|not|here)\\b)[a-z]{2,20}(?:\\s+[a-z]{2,20})?\\s+` +
    `${anyOf(RECRUITER_INTRO_LINKS)}\\b` +
    `|${words(RECRUITER_TITLES)}`,
);
const JOB_RE = wordsRegex(JOB_WORDS);
const JOB_DOC_RE = wordsRegex(JOB_DOC_WORDS);

// utility-disconnection-threat
const UTILITY_RE = wordsRegex(UTILITY_WORDS);
const DISCONNECT_RE = re(
  `${words(DISCONNECT_PHRASES)}|${words(DISCONNECT_SOFT_WORDS)}\\s+${anyOf(DISCONNECT_TIME_WORDS)}\\b`,
);
const UNPAID_RE = re(
  `${words(UNPAID_WORDS)}\\s+(?:[a-z]{1,15}\\s+)?${anyOf(BILL_WORDS)}\\b` + // "unpaid bill", "overdue electricity bill"
    `|${words(BILL_WORDS)}\\s+(?:is|are|remains|remain)\\s+(?:still\\s+)?${anyOf(UNPAID_WORDS)}\\b` + // "bill is overdue"
    `|\\bdues\\b`,
);
const PAY_NOW_RE = re(`${words(PAY_NOW_VERBS)}(?:\\s+[a-z']{1,15}){0,${PAY_NOW_GAP_WORDS}}?\\s+${anyOf(PAY_NOW_WORDS)}\\b`);

// payment-failed-lure
const PAYMENT_FAILED_RE = re(
  [
    // "Payment failed", "your subscription payment was declined"
    `${words(PAYMENT_SUBJECTS)}\\s+(?:[a-z]{1,15}\\s+)?(?:(?:has|had|was|is)\\s+)?${anyOf(PAYMENT_FAILED_STATES)}\\b`,
    // "We couldn't process your payment"
    `\\b(?:could\\s+not|couldn't|unable\\s+to|failed\\s+to)\\s+(?:process|charge|renew|complete)\\s+your\\s+(?:[a-z]{1,15}\\s+)?${anyOf(["payment", "card", "subscription", "renewal"])}\\b`,
    // "Your card ending in 4821 was declined", "card has expired"
    `\\bcards?\\b(?:\\s+[a-z0-9]{1,15}){0,4}?\\s+(?:(?:was|has\\s+been|is|has|got)\\s+)?${anyOf(CARD_FAILED_STATES)}\\b`,
  ].join("|"),
);
const PAYMENT_UPDATE_RE = re(
  `${NOT_GOVERNED}${words(PAYMENT_UPDATE_VERBS)}\\s+(?:your\\s+|the\\s+|a\\s+)?(?:[a-z]{1,15}\\s+)?${anyOf(PAYMENT_DETAIL_WORDS)}\\b`,
);
// "or your account will be permanently deleted"
const ACCOUNT_THREAT_RE = re(
  `${words(ACCOUNT_THREAT_THINGS)}\\s+(?:will|would|may|is\\s+going\\s+to)\\s+be\\s+(?:[a-z]{1,15}\\s+)?${anyOf(ACCOUNT_THREAT_STATES)}\\b`,
);

// account-security-lure
const LOGIN_ALERT_RE = re(
  [
    `${words(LOGIN_ACTORS)}(?:\\s+[a-z]{1,15}){0,4}?\\s+${anyOf(LOGIN_VERBS)}\\b`, // "Someone in Lisbon signed in"
    `${words(LOGIN_ODD_WORDS)}\\s+(?:[a-z-]{1,15}\\s+)?${anyOf(LOGIN_EVENTS)}\\b`, // "unusual sign-in activity"
    `\\bnew\\s+${anyOf(["sign-in", "sign in", "login", "log-in", "log in"])}\\b`, // "a new sign-in"
  ].join("|"),
);
const SECURE_ACTION_RE = re(
  `${NOT_GOVERNED}${words(SECURE_VERBS)}\\s+(?:the\\s+|this\\s+|your\\s+|that\\s+)?(?:[a-z]{1,15}\\s+)?${anyOf(SECURE_OBJECTS)}\\b`,
);

// Job fee (advance-fee-scheme + context.jobFee): "800 BDT onboarding fee", "refundable security
// deposit", or "lock your slot" together with an amount, in a job context.
const JOB_FEE_RE = re(
  `(?<!\\b${anyOf(JOB_FEE_NEGATIONS)}\\s(?:[a-z]{1,15}\\s)?)${words(JOB_FEE_KINDS)}\\s+(?:[a-z]{1,15}\\s+)?${anyOf(JOB_FEE_WORDS)}\\b` +
    `(?!\\s+(?:is|are|will\\s+be)\\s+(?:covered|waived|free|refunded|paid\\s+by))`,
);
const JOB_SLOT_RE = re(`${words(JOB_SLOT_VERBS)}\\s+(?:your|the|a|this)\\s+(?:[a-z]{1,15}\\s+)?${anyOf(JOB_SLOT_WORDS)}\\b`);
const CUR_AMOUNT_RE = re(CUR_AMOUNT);
const JOB_CONTEXT_EXTRA_RE = wordsRegex(JOB_CONTEXT_EXTRA);

// task-job-scam, remote-work path
const REMOTE_WORK_RE = wordsRegex(REMOTE_WORK_PHRASES);
const REMOTE_PAY_RE = re(`${CUR_RANGE}\\s*(?:${anyOf(REMOTE_PAY_PERIODS)}\\b|\\/\\s?(?:day|week|wk)\\b)`);
const NO_EXPERIENCE_RE = re(`\\bno\\s+(?:${anyOf(NO_EXPERIENCE_FILLERS)}\\s+)?${anyOf(NO_EXPERIENCE_WORDS)}\\b`);
const CHAT_APP_RE = re(
  `${words(CHAT_CONTACT_VERBS)}${near(CHAT_PROXIMITY_CHARS)}\\b(?:on|via|through|in|at|over)\\s+${anyOf(CHAT_APPS)}\\b`,
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

/** Flag + cursed phrases for a family: evidence is the first `lead` match, phrases are all cues. */
function familySignal(id, weight, lead, cues) {
  if (lead.length === 0) return { flag: null, phrases: [] };
  const reason = CURSED_PHRASE_REASONS[id];
  const all = [...lead, ...cues].sort((a, b) => a.index - b.index);
  return { flag: makeRedFlag(id, weight, lead[0].text), phrases: all.map((m) => ({ text: m.text, reason })) };
}

const NO_SIGNAL = { flag: null, phrases: [] };

function detectDeliveryScam(norm, links) {
  if (links.length === 0) return NO_SIGNAL;
  const failure = findAll(norm, DELIVERY_FAILURE_RE);
  if (failure.length === 0 || findAll(norm, DELIVERY_CONTEXT_RE).length === 0) return NO_SIGNAL;
  const weight = links.some((l) => l.shortener) ? W_DELIVERY_SCAM_SHORTENER : W_DELIVERY_SCAM;
  return familySignal("delivery-scam", weight, failure, []);
}

function detectSeedPhrase(norm, links) {
  const request = findAll(norm, SEED_REQUEST_RE);
  const walletFix = links.length > 0 ? findAll(norm, WALLET_FIX_RE) : [];
  const lead = [...request, ...walletFix].sort((a, b) => a.index - b.index);
  return familySignal("seed-phrase-request", W_SEED_PHRASE_REQUEST, lead, []);
}

function detectInvestment(norm) {
  const promise = findAll(norm, INVEST_PROMISE_RE);
  if (promise.length === 0) return NO_SIGNAL;
  const context = outside(findAll(norm, INVEST_CONTEXT_RE), promise);
  if (context.length === 0) return NO_SIGNAL;
  return familySignal("investment-guarantee", W_INVESTMENT_GUARANTEE, promise, context);
}

function detectTaskJob(norm) {
  const work = findAll(norm, TASK_WORK_RE);
  const pay = findAll(norm, TASK_PAY_RE);
  const easy = findAll(norm, TASK_EASY_RE);
  const reply = findAll(norm, TASK_REPLY_RE);
  const others = (pay.length > 0) + (easy.length > 0) + (reply.length > 0);
  // Paid simple tasks plus one more cue, or pay + easy hours + "reply YES" together.
  if (work.length > 0 ? others >= 1 : others === 3) {
    const lead = [...work, ...pay].sort((a, b) => a.index - b.index);
    return familySignal("task-job-scam", W_TASK_JOB_SCAM, lead, [...easy, ...reply]);
  }
  // Round 2: remote / data-entry work + daily or weekly pay + "no experience" + a chat app.
  const remote = findAll(norm, REMOTE_WORK_RE);
  const remotePay = findAll(norm, REMOTE_PAY_RE);
  const noExperience = findAll(norm, NO_EXPERIENCE_RE);
  const chat = [...findAll(norm, CHAT_APP_RE), ...reply];
  if (remote.length === 0 || remotePay.length === 0 || noExperience.length === 0 || chat.length === 0) return NO_SIGNAL;
  return familySignal("task-job-scam", W_TASK_JOB_SCAM, remote, [...remotePay, ...noExperience, ...chat]);
}

function detectOfficialFine(norm, links) {
  if (links.length === 0) return NO_SIGNAL;
  const term = findAll(norm, FINE_TERM_RE);
  const pay = findAll(norm, FINE_PAY_RE);
  if (term.length === 0 || pay.length === 0) return NO_SIGNAL;
  const pressure = matchesInOrder(norm, [
    URGENCY_DEADLINE_RE,
    URGENCY_DEADLINE_EXTRA_RE,
    FINE_DEADLINE_WORDS_RE,
    FINE_LEGAL_RE,
    URGENCY_AVOID_RE,
  ]);
  if (pressure.length === 0) return NO_SIGNAL;
  return familySignal("official-fine-threat", W_OFFICIAL_FINE_THREAT, term, pressure);
}

function linkMentionsDoc(link) {
  return link.text
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .some((part) => JOB_DOC_LINK_PARTS.includes(part));
}

function detectRecruiterBait(norm, links) {
  const unfamiliar = links.filter((l) => !RECRUITER_TRUSTED_DOMAINS.includes(registrableDomain(l.host)));
  if (unfamiliar.length === 0) return NO_SIGNAL;
  const recruiter = findAll(norm, RECRUITER_RE);
  const job = findAll(norm, JOB_RE);
  if (recruiter.length === 0 || job.length === 0) return NO_SIGNAL;
  const doc = findAll(norm, JOB_DOC_RE);
  if (doc.length === 0 && !unfamiliar.some(linkMentionsDoc)) return NO_SIGNAL;
  return familySignal("recruiter-bait", W_RECRUITER_BAIT, recruiter, [...job, ...doc]);
}

/** A link that is not an ordinary company address: lure words, risky ending, shortener or raw IP. */
// unfamiliar-link-pressure: pressure words in the text. The lookarounds skip words that are part
// of a hostname or path ("verify" in "badge-verify.example"), so a domain never supplies its own
// pressure.
const PRESSURE_RE = re(
  `(?<![.\\/-])(?:${words(PRESSURE_DEADLINE_PHRASES)}|\\bwithin\\s+\\d{1,3}\\s*${anyOf(PRESSURE_DEADLINE_UNITS)}\\b|` +
    `${words(PRESSURE_THREAT_WORDS)}|${words(PRESSURE_ASK_WORDS)})(?![.\\/-][a-z0-9])`,
);

// tech-support-scam: a scare (malware event, infected, detected on your device, at risk, "5 viruses",
// an error code) AND a hook (call/contact support, or install/open a remote tool or session).
// Error codes are matched on the normalized text, where l33t mapping turns "0x80" into "ox8o".
// A conditional ("If you think your account is at risk, contact us") is advice, not a claim.
const TECH_SCARE_RE = re(
  `(?<!\\b(?:if|whether|in\\s+case)\\b[^.!?\\n]{0,40})(?:` +
  [
    `${words(MALWARE_WORDS)}(?:[\\s.]+[a-z]{2,15}){0,2}?\\s+${anyOf(MALWARE_EVENT_WORDS)}\\b`, // "Trojan.Spyware detected"
    `\\binfected\\s+with\\b|\\b(?:is|are|been|was|were)\\s+infected\\b`, // "has been infected"
    `\\b(?:detected|found)\\s+(?:on|in)\\s+your\\s+(?:[a-z]{2,15}\\s+){0,2}?${anyOf(SCARE_DEVICE_WORDS)}\\b`, // "detected on your Windows PC"
    `${words(AT_RISK_SUBJECTS)}\\s+(?:is|are)\\s+(?:now\\s+)?at\\s+risk\\b`, // "your banking passwords are at risk"
    `\\b\\d{1,3}\\s+${anyOf(SCARE_COUNT_WORDS)}\\b`, // "5 viruses"
    `\\berror\\b[^.!?\\n]{0,12}?\\b[0o]x[0-9a-fo]{4,8}\\b`, // "Error #0x8007002"
  ].join("|") +
  ")",
);
const TECH_HOOK_RE = re(
  `${NOT_GOVERNED}${words(SUPPORT_CALL_VERBS)}${NEAR}${words(SUPPORT_WORDS)}` + // "Call our certified support desk"
    `|${NOT_GOVERNED}${words(REMOTE_NAMED_VERBS)}${NEAR}(?:${words(REMOTE_TOOL_NAMES)}|${words(REMOTE_SESSION_PHRASES)})`, // "install AnyDesk"
);

function detectTechSupport(norm) {
  const scare = findAll(norm, TECH_SCARE_RE);
  if (scare.length === 0) return NO_SIGNAL;
  const hook = findAll(norm, TECH_HOOK_RE);
  if (hook.length === 0) return NO_SIGNAL;
  return familySignal("tech-support-scam", W_TECH_SUPPORT_SCAM, scare, hook);
}

function detectUnfamiliarLinkPressure(norm, links, brands) {
  const unfamiliar = links.find((l) => isUnfamiliarDomain(l, brands));
  if (!unfamiliar) return NO_SIGNAL;
  const pressure = findAll(norm, PRESSURE_RE);
  if (pressure.length === 0) return NO_SIGNAL;
  const reason = CURSED_PHRASE_REASONS["unfamiliar-link-pressure"];
  return {
    flag: makeRedFlag("unfamiliar-link-pressure", W_UNFAMILIAR_LINK_PRESSURE, unfamiliar.host),
    phrases: pressure.map((m) => ({ text: m.text, reason })),
  };
}

function isSuspiciousLink(link, brands) {
  return isLureDomain(link.host, brands) || hasRiskyTld(link.host) || link.shortener || /^[\d.]+$/.test(link.host);
}

function detectUtilityDisconnection(norm, links) {
  const disconnect = findAll(norm, DISCONNECT_RE);
  if (disconnect.length === 0) return NO_SIGNAL;
  const utility = findAll(norm, UTILITY_RE);
  const unpaid = findAll(norm, UNPAID_RE);
  if (utility.length === 0 || unpaid.length === 0) return NO_SIGNAL;
  const payNow = findAll(norm, PAY_NOW_RE);
  if (links.length === 0 && payNow.length === 0) return NO_SIGNAL;
  return familySignal("utility-disconnection-threat", W_UTILITY_DISCONNECTION_THREAT, disconnect, [...unpaid, ...payNow]);
}

function detectPaymentFailed(norm, links, brands) {
  if (links.length === 0) return NO_SIGNAL;
  const failed = findAll(norm, PAYMENT_FAILED_RE);
  const update = findAll(norm, PAYMENT_UPDATE_RE);
  if (failed.length === 0 || update.length === 0) return NO_SIGNAL;
  // An hours-level deadline or a deletion threat; "within 7 days" alone is an ordinary grace period.
  const pressure = matchesInOrder(norm, [URGENCY_DEADLINE_RE, ACCOUNT_THREAT_RE]);
  if (pressure.length === 0 && !links.some((l) => isSuspiciousLink(l, brands))) return NO_SIGNAL;
  return familySignal("payment-failed-lure", W_PAYMENT_FAILED_LURE, failed, [...update, ...pressure]);
}

function detectAccountSecurity(norm, links, brands) {
  if (!links.some((l) => isSuspiciousLink(l, brands))) return NO_SIGNAL;
  const alert = findAll(norm, LOGIN_ALERT_RE);
  const action = findAll(norm, SECURE_ACTION_RE);
  if (alert.length === 0 || action.length === 0) return NO_SIGNAL;
  return familySignal("account-security-lure", W_ACCOUNT_SECURITY_LURE, alert, action);
}

/** Fee matches that ask for money before a job starts; empty without a job context. */
function jobFeeMatches(norm) {
  const fee = findAll(norm, JOB_FEE_RE);
  const slot = findAll(norm, CUR_AMOUNT_RE).length > 0 ? findAll(norm, JOB_SLOT_RE) : [];
  if (fee.length === 0 && slot.length === 0) return [];
  const jobContext =
    findAll(norm, JOB_RE).length > 0 || findAll(norm, RECRUITER_RE).length > 0 || findAll(norm, JOB_CONTEXT_EXTRA_RE).length > 0;
  return jobContext ? [...fee, ...slot] : [];
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
 * @param {ReadonlyArray<{ name: string, domains: ReadonlyArray<string> }>} [brands] official domains
 *        that never count as lookalike lure domains
 * @returns {{ flags: object[], cursedPhrases: object[], paymentInstruction: boolean,
 *             secretRequest: boolean, jobFee: boolean }}
 */
export function detectContent(input, brands = DEFAULT_BRANDS) {
  const norm = normalize(input);
  const urgencyEn = phraseSignal(norm, "urgency-en", W_URGENCY_EN, [
    URGENCY_EN_RE,
    URGENCY_EXTRA_RE,
    URGENCY_AVOID_RE,
    URGENCY_LOCKED_RE,
    URGENCY_DEVICE_RE,
    URGENCY_DEADLINE_RE,
    URGENCY_DEADLINE_EXTRA_RE,
    URGENCY_SCARCITY_RE,
    URGENCY_IMMEDIACY_RE,
  ]);
  const notRequests = [...findAll(norm, NEGATED_REQUEST_RE), ...findAll(norm, DELIVERED_CODE_RE)];
  const credential = signalFrom(
    "credential-request",
    W_CREDENTIAL_REQUEST,
    outside(credentialRequests(norm), notRequests),
  );
  const prize = phraseSignal(norm, "prize-lottery", W_PRIZE_LOTTERY, [PRIZE_RE, CONGRATS_RE, MONEY_RE, PERCENT_RETURN_RE]);
  const jobFee = jobFeeMatches(norm);
  const advanceFee = signalFrom(
    "advance-fee-scheme",
    W_ADVANCE_FEE_SCHEME,
    [...matchesInOrder(norm, [ADVANCE_FEE_RE, TRANSFER_OF_MONEY_RE, FEE_CONDITION_RE]), ...jobFee].sort(
      (a, b) => a.index - b.index,
    ),
  );
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
  const links = findLinks(input);
  const delivery = detectDeliveryScam(norm, links);
  const seedPhrase = detectSeedPhrase(norm, links);
  const investment = detectInvestment(norm);
  const taskJob = detectTaskJob(norm);
  const officialFine = detectOfficialFine(norm, links);
  const recruiter = detectRecruiterBait(norm, links);
  const utility = detectUtilityDisconnection(norm, links);
  const paymentFailed = detectPaymentFailed(norm, links, brands);
  const accountSecurity = detectAccountSecurity(norm, links, brands);
  const unfamiliarLink = detectUnfamiliarLinkPressure(norm, links, brands);
  const techSupport = detectTechSupport(norm);

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
    delivery.flag,
    seedPhrase.flag,
    investment.flag,
    taskJob.flag,
    officialFine.flag,
    recruiter.flag,
    utility.flag,
    paymentFailed.flag,
    accountSecurity.flag,
    unfamiliarLink.flag,
    techSupport.flag,
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
    ...delivery.phrases,
    ...seedPhrase.phrases,
    ...investment.phrases,
    ...taskJob.phrases,
    ...officialFine.phrases,
    ...recruiter.phrases,
    ...utility.phrases,
    ...paymentFailed.phrases,
    ...accountSecurity.phrases,
    ...unfamiliarLink.phrases,
    ...techSupport.phrases,
  ]);
  return {
    flags,
    cursedPhrases,
    paymentInstruction: findAll(norm, PAYMENT_INSTRUCTION_RE).length > 0,
    secretRequest: findAll(norm, SECRET_REQUEST_RE).length > 0,
    jobFee: jobFee.length > 0,
  };
}
