// Content detector: urgency-en, urgency-bn, credential-request, suspicious-attachment.
// All Content category. The first three also produce cursed phrases.

import {
  W_URGENCY_EN,
  W_URGENCY_BN,
  W_CREDENTIAL_REQUEST,
  W_SUSPICIOUS_ATTACHMENT,
  URGENCY_EN_PHRASES,
  URGENCY_BN_PHRASES,
  CREDENTIAL_BN_TERMS,
  DANGEROUS_EXTENSIONS,
  JS_LIBRARY_ALLOWLIST,
  MAX_CURSED_PHRASES,
  CURSED_PHRASE_REASONS,
} from "../config.js";
import { makeRedFlag } from "../util/flag.js";

// ---------------------------------------------------------------------------
// Regex builders. Phrases are fixed strings: escaped, joined with "|", and single
// spaces become \s+. \s+ only ever sits between fixed words, so there is no nesting.
// ---------------------------------------------------------------------------
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function phrasePattern(phrase) {
  return escapeRegex(phrase).split(" ").join("\\s+");
}

// Bangla letters with a nukta can be typed precomposed (U+09DC/09DD/09DF) or as base + U+09BC.
// NFC turns the precomposed forms into base + nukta; the pattern then accepts either spelling.
const BN_NUKTA_FORMS = [
  ["ড়", "ড়"], // ড়
  ["ঢ়", "ঢ়"], // ঢ়
  ["য়", "য়"], // য়
];

function bnPhrasePattern(phrase) {
  let p = phrasePattern(phrase.normalize("NFC"));
  for (const [decomposed, precomposed] of BN_NUKTA_FORMS) {
    p = p.split(decomposed).join(`(?:${decomposed}|${precomposed})`);
  }
  return p;
}

const URGENCY_EN_RE = new RegExp(`\\b(?:${URGENCY_EN_PHRASES.map(phrasePattern).join("|")})\\b`, "gi");
// No \b: word boundaries do not work for Bangla script.
const URGENCY_BN_RE = new RegExp(`(?:${URGENCY_BN_PHRASES.map(bnPhrasePattern).join("|")})`, "gu");

// The lookarounds skip words that are part of a hostname, e.g. "login" in "login.galactibank.example".
const CREDENTIAL_EN_RE =
  /(?<![.-])\b(?:password|passcode|log\s*in|sign\s+in|username|one[- ]time\s+(?:code|password)|verify\s+your\s+(?:account|identity)|confirm\s+your\s+identity)\b(?![.-][a-z0-9])/gi;
// Case-sensitive so the ordinary word "pin" never fires.
const CREDENTIAL_UPPER_RE = /\b(?:PIN|OTP)\b/g;
const CREDENTIAL_BN_RE = new RegExp(`(?:${CREDENTIAL_BN_TERMS.map(bnPhrasePattern).join("|")})`, "gu");

const ATTACHMENT_RE = new RegExp(
  String.raw`(?<![\/\w@.-])(\w[\w.-]{0,100})\.(${DANGEROUS_EXTENSIONS.join("|")})(?=["'\s),;!?]|\.(?:\s|$)|$)`,
  "gi",
);
const JS_EXTENSION = "js";

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
  const urgencyBn = phraseSignal(input, "urgency-bn", W_URGENCY_BN, [URGENCY_BN_RE]);
  const credential = phraseSignal(input, "credential-request", W_CREDENTIAL_REQUEST, [
    CREDENTIAL_EN_RE,
    CREDENTIAL_UPPER_RE,
    CREDENTIAL_BN_RE,
  ]);

  const flags = [urgencyEn.flag, urgencyBn.flag, credential.flag, detectAttachment(input)].filter(Boolean);
  const cursedPhrases = dedupeAndCap([...urgencyEn.phrases, ...urgencyBn.phrases, ...credential.phrases]);
  return { flags, cursedPhrases };
}
