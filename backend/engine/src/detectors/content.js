// Content detector: urgency-en, credential-request, suspicious-attachment, prize-lottery,
// advance-fee-scheme, financial-info-request, unusual-payment-method, secrecy-pressure.
// All Content category. Every signal except suspicious-attachment also produces cursed phrases.

import {
  W_URGENCY_EN,
  W_CREDENTIAL_REQUEST,
  W_SUSPICIOUS_ATTACHMENT,
  W_PRIZE_LOTTERY,
  W_ADVANCE_FEE_SCHEME,
  W_FINANCIAL_INFO_REQUEST,
  W_UNUSUAL_PAYMENT_METHOD,
  W_SECRECY_PRESSURE,
  URGENCY_EN_PHRASES,
  DANGEROUS_EXTENSIONS,
  JS_LIBRARY_ALLOWLIST,
  PRIZE_PHRASES,
  CONGRATS_WORDS,
  PRIZE_WORDS,
  CURRENCY_SYMBOLS,
  CURRENCY_CODES,
  CURRENCY_WORDS,
  LARGE_AMOUNT_WORDS,
  ADVANCE_FEE_PHRASES,
  FINANCIAL_REQUEST_VERBS,
  FINANCIAL_INFO_TERMS,
  NEGATION_WORDS,
  PAYMENT_VERBS,
  PAYMENT_METHODS,
  MOBILE_WALLET_TERMS,
  FEE_WORDS,
  SECRECY_PHRASES,
  REQUEST_PROXIMITY_CHARS,
  PRIZE_PROXIMITY_CHARS,
  NEGATION_WINDOW_CHARS,
  MONEY_DIGITS_MAX,
  MONEY_SPACE_MAX,
  MAX_CURSED_PHRASES,
  CURSED_PHRASE_REASONS,
} from "../config.js";
import { makeRedFlag } from "../util/flag.js";

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

function wordsRegex(phrases) {
  return new RegExp(`\\b${anyOf(phrases)}\\b`, "gi");
}

// Same sentence, bounded distance: no sentence end and no line break in between.
const NEAR = `[^.!?\\n]{0,${REQUEST_PROXIMITY_CHARS}}?`;
// "never share your card number" / "do not pay with gift cards" are warnings, not requests.
const NOT_NEGATED = `(?<!\\b${anyOf(NEGATION_WORDS)}\\b[^.!?\\n]{0,${NEGATION_WINDOW_CHARS}})`;

// A large money amount with a currency marker: "$1 million", "USD 2.5 billion", "5 million dollars".
const MONEY =
  `(?:(?:${CURRENCY_SYMBOLS.map(escapeRegex).join("|")}|\\b${anyOf(CURRENCY_CODES)}\\s{0,${MONEY_SPACE_MAX}})` +
  `\\d[\\d,.]{0,${MONEY_DIGITS_MAX}}\\s{0,${MONEY_SPACE_MAX}}${anyOf(LARGE_AMOUNT_WORDS)}\\b` +
  `|\\b\\d[\\d,.]{0,${MONEY_DIGITS_MAX}}\\s{0,${MONEY_SPACE_MAX}}${anyOf(LARGE_AMOUNT_WORDS)}\\s+${anyOf(CURRENCY_WORDS)}\\b)`;

const URGENCY_EN_RE = wordsRegex(URGENCY_EN_PHRASES);

// The lookarounds skip words that are part of a hostname, e.g. "login" in "login.galactibank.example".
const CREDENTIAL_EN_RE =
  /(?<![.-])\b(?:password|passcode|log\s*in|sign\s+in|username|one[- ]time\s+(?:code|password)|verify\s+your\s+(?:account|identity)|confirm\s+your\s+identity)\b(?![.-][a-z0-9])/gi;
// Case-sensitive so the ordinary word "pin" never fires.
const CREDENTIAL_UPPER_RE = /\b(?:PIN|OTP)\b/g;

const ATTACHMENT_RE = new RegExp(
  String.raw`(?<![\/\w@.-])(\w[\w.-]{0,100})\.(${DANGEROUS_EXTENSIONS.join("|")})(?=["'\s),;!?]|\.(?:\s|$)|$)`,
  "gi",
);
const JS_EXTENSION = "js";

const PRIZE_RE = wordsRegex(PRIZE_PHRASES);
// "Congratulations" alone is harmless ("Congratulations on your new job!"); it only counts when a
// prize word follows shortly after. The lookahead keeps the cursed phrase to the word itself.
const CONGRATS_RE = new RegExp(
  `\\b${anyOf(CONGRATS_WORDS)}\\b(?=[\\s\\S]{0,${PRIZE_PROXIMITY_CHARS}}?\\b${anyOf(PRIZE_WORDS)}\\b)`,
  "gi",
);
const MONEY_RE = new RegExp(MONEY, "gi");

const ADVANCE_FEE_RE = wordsRegex(ADVANCE_FEE_PHRASES);
const TRANSFER_OF_MONEY_RE = new RegExp(`\\btransfer\\s+of\\s+(?:the\\s+sum\\s+of\\s+)?${MONEY}`, "gi");

// Request verb first, then the card or bank term ("Enter your credit card details"). A term
// with no request verb before it ("Thanks for paying by credit card") does not fire.
const FINANCIAL_INFO_RE = new RegExp(
  `${NOT_NEGATED}\\b${anyOf(FINANCIAL_REQUEST_VERBS)}\\b${NEAR}\\b${anyOf(FINANCIAL_INFO_TERMS)}\\b`,
  "gi",
);

const PAYMENT_VERB = `${NOT_NEGATED}\\b${anyOf(PAYMENT_VERBS)}\\b`;
const PAYMENT_METHOD_RE = new RegExp(`${PAYMENT_VERB}${NEAR}\\b${anyOf(PAYMENT_METHODS)}s?\\b`, "gi");
// A mobile wallet is ordinary; paying a "fee" through one is the scam pattern.
const WALLET = `\\b${anyOf(MOBILE_WALLET_TERMS)}\\b`;
const FEE = `\\b${anyOf(FEE_WORDS)}\\b`;
const WALLET_FEE_RE = new RegExp(`${PAYMENT_VERB}${NEAR}(?:${WALLET}${NEAR}${FEE}|${FEE}${NEAR}${WALLET})`, "gi");

const SECRECY_RE = wordsRegex(SECRECY_PHRASES);

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------
/** All matches of the given regexes, ordered by position in the input. */
function matchesInOrder(input, regexes) {
  const found = [];
  for (const re of regexes) {
    for (const m of input.matchAll(re)) found.push({ text: m[0], index: m.index });
  }
  return found.sort((a, b) => a.index - b.index);
}

function phraseSignal(input, id, weight, regexes) {
  const matches = matchesInOrder(input, regexes);
  if (matches.length === 0) return { flag: null, phrases: [] };
  const reason = CURSED_PHRASE_REASONS[id];
  return {
    flag: makeRedFlag(id, weight, matches[0].text),
    phrases: matches.map((m) => ({ text: m.text, reason })),
  };
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

/** @param {string} input */
export function detectContent(input) {
  const urgencyEn = phraseSignal(input, "urgency-en", W_URGENCY_EN, [URGENCY_EN_RE]);
  const credential = phraseSignal(input, "credential-request", W_CREDENTIAL_REQUEST, [
    CREDENTIAL_EN_RE,
    CREDENTIAL_UPPER_RE,
  ]);
  const prize = phraseSignal(input, "prize-lottery", W_PRIZE_LOTTERY, [PRIZE_RE, CONGRATS_RE, MONEY_RE]);
  const advanceFee = phraseSignal(input, "advance-fee-scheme", W_ADVANCE_FEE_SCHEME, [
    ADVANCE_FEE_RE,
    TRANSFER_OF_MONEY_RE,
  ]);
  const financialInfo = phraseSignal(input, "financial-info-request", W_FINANCIAL_INFO_REQUEST, [FINANCIAL_INFO_RE]);
  const payment = phraseSignal(input, "unusual-payment-method", W_UNUSUAL_PAYMENT_METHOD, [
    PAYMENT_METHOD_RE,
    WALLET_FEE_RE,
  ]);
  const secrecy = phraseSignal(input, "secrecy-pressure", W_SECRECY_PRESSURE, [SECRECY_RE]);

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
  ].filter(Boolean);
  const cursedPhrases = dedupeAndCap([
    ...urgencyEn.phrases,
    ...credential.phrases,
    ...prize.phrases,
    ...advanceFee.phrases,
    ...financialInfo.phrases,
    ...payment.phrases,
    ...secrecy.phrases,
  ]);
  return { flags, cursedPhrases };
}
