// Identity detector: typosquatting, homograph-punycode, display-name-mismatch.
// All signals are Identity/Auth. Produces no cursed phrases.

import {
  W_TYPOSQUATTING,
  W_HOMOGRAPH_PUNYCODE,
  W_DISPLAY_NAME_MISMATCH,
  TYPO_SHORT_NAME_MAX_LEN,
  TYPO_MAX_DISTANCE_SHORT,
  TYPO_MAX_DISTANCE_LONG,
  TYPO_MIN_FUZZY_LEN,
  TYPO_CONTAINS_MIN_LEN,
  MAX_EVIDENCE_LENGTH,
} from "../config.js";
import { extractAsciiHostnames, extractUnicodeHostnames, registrableLabel, isLegitimate } from "../util/hostname.js";
import { levenshtein } from "../util/levenshtein.js";
import { makeRedFlag } from "../util/flag.js";

const PUNYCODE_PREFIX = "xn--";
const LATIN_RE = /[A-Za-z]/;
const CYRILLIC_GREEK_RE = /[Ͱ-ϿЀ-ӿ]/;
const FROM_LINE_RE =
  /(?:^|\n)[ \t]*From:[ \t]*(?:"([^"\n]{1,100})"|([^<\n]{1,100}?))[ \t]*<[^@<>\s]{1,64}@([a-z0-9.-]{1,253})>/gi;

/** Brand names are compared as lowercase a-z0-9. */
function normalizeName(s) {
  return s.toLowerCase().replace(/[^a-z0-9]/g, "");
}

const CANON_CHAR_MAP = { 0: "o", 3: "e", 4: "a", 5: "s", 1: "l", i: "l", l: "l" };

/** Collapses common look-alike spellings so "galact1bank" and "galactibank" compare equal. */
function canon(s) {
  return s
    .toLowerCase()
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/[0345il1]/g, (c) => CANON_CHAR_MAP[c]);
}

function looksLikeBrand(label, name) {
  if (label === name) return true; // exact label on a domain the brand does not own
  if (name.length >= TYPO_MIN_FUZZY_LEN) {
    const maxDistance = name.length <= TYPO_SHORT_NAME_MAX_LEN ? TYPO_MAX_DISTANCE_SHORT : TYPO_MAX_DISTANCE_LONG;
    if (levenshtein(canon(label), canon(name)) <= maxDistance) return true;
  }
  return name.length >= TYPO_CONTAINS_MIN_LEN && label.includes(name);
}

function detectTyposquatting(input, brands) {
  const names = brands.map((b) => normalizeName(b.name)).filter((n) => n.length > 0);
  for (const host of extractAsciiHostnames(input)) {
    if (brands.some((b) => isLegitimate(host, b))) continue;
    const label = registrableLabel(host);
    if (names.some((name) => looksLikeBrand(label, name))) {
      return makeRedFlag("typosquatting", W_TYPOSQUATTING, host);
    }
  }
  return null;
}

function isSuspiciousLabel(label) {
  if (label.toLowerCase().startsWith(PUNYCODE_PREFIX)) return true;
  return LATIN_RE.test(label) && CYRILLIC_GREEK_RE.test(label);
}

function detectHomograph(input) {
  for (const host of extractUnicodeHostnames(input)) {
    if (host.split(".").some(isSuspiciousLabel)) {
      return makeRedFlag("homograph-punycode", W_HOMOGRAPH_PUNYCODE, host);
    }
  }
  return null;
}

function detectDisplayNameMismatch(input, brands) {
  for (const m of input.matchAll(FROM_LINE_RE)) {
    const displayName = normalizeName(m[1] ?? m[2] ?? "");
    const domain = m[3].toLowerCase();
    const impersonated = brands.find((b) => {
      const name = normalizeName(b.name);
      return name.length > 0 && displayName.includes(name);
    });
    if (impersonated && !isLegitimate(domain, impersonated)) {
      const evidence = m[0].trim().slice(0, MAX_EVIDENCE_LENGTH);
      return makeRedFlag("display-name-mismatch", W_DISPLAY_NAME_MISMATCH, evidence);
    }
  }
  return null;
}

/**
 * @param {string} input
 * @param {Array<{name: string, domains: string[]}>} brands
 */
export function detectIdentity(input, brands) {
  const flags = [
    detectTyposquatting(input, brands),
    detectHomograph(input),
    detectDisplayNameMismatch(input, brands),
  ].filter(Boolean);
  return { flags, cursedPhrases: [] };
}
