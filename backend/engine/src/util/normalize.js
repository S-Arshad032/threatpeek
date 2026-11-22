// Text normalization for the content detector. It undoes common obfuscation so the phrase
// regexes see plain words, and keeps an offset map so every match can be mapped back to the
// ORIGINAL text: evidence and cursed phrases always quote what the user pasted.
//
// Steps, in order:
//   1. Unicode NFKC (per base character plus its combining marks) and lowercase.
//   2. Remove zero-width and control characters (line breaks and tabs are kept as whitespace).
//   3. Collapse each run of whitespace to one character: "\n" if the run had a line break
//      (sentence boundaries matter to the proximity rules), otherwise " ".
//   4. Inside a token that also contains letters, map leetspeak symbols (@->a, 0->o, 1->i,
//      3->e, 5->s, $->s). Plain numbers ("1000000", "$100"), amounts ("$1million"), number+unit
//      ("10am", "2nd") and letters+number codes ("mp3", "room101") are left alone.
//   5. Collapse spaced-out words: LEET_SPACED_MIN_LETTERS or more single letters separated by
//      single spaces ("p a s s w o r d" -> "password").
//
// Linear time: every step is one pass over the text; the regexes used are bounded and anchored
// to one token.

import { LEET_MAP, SPACED_LETTERS_MIN } from "../config.js";

const ZERO_WIDTH_RE = /[­᠎​-‏‪-‮⁠-⁤﻿]/u;
const CONTROL_RE = /\p{Cc}/u;
const KEEP_CONTROL = new Set(["\n", "\r", "\t"]);
const WHITESPACE_RE = /\s/u;
const COMBINING_RE = /\p{M}/u;
const LETTER_RE = /\p{L}/u;
const TOKEN_CHAR_RE = /[\p{L}\p{N}@$]/u;

// Tokens that keep their digits and symbols (checked on the lowercased token).
const CURRENCY_NEXT_TO_DIGIT_RE = /[$£€]\d|\d[$£€]/u;
const NUMBER_THEN_LETTERS_RE = /^[\d.,]+\p{L}*$/u;
const LETTERS_THEN_NUMBER_RE = /^\p{L}+[\d.,]+$/u;

/**
 * @typedef {{ input: string, text: string, cased: string, toOriginal: (start: number, end: number) => [number, number] }} Normalized
 * `text` is the normalized, lowercased text. `cased` is the same text before lowercasing and
 * leetspeak mapping, with the same length and offsets (used by case-sensitive patterns).
 * `toOriginal(start, end)` maps a [start, end) span of `text` to a span of the original input.
 */

/** Splits the input into units: one base character with its combining marks. */
function* units(input) {
  let i = 0;
  while (i < input.length) {
    const start = i;
    i += input.codePointAt(i) > 0xffff ? 2 : 1;
    while (i < input.length && COMBINING_RE.test(String.fromCodePoint(input.codePointAt(i)))) {
      i += input.codePointAt(i) > 0xffff ? 2 : 1;
    }
    yield { raw: input.slice(start, i), start, end: i };
  }
}

/** Steps 1-3: one entry per output code point, each with the original span it came from. */
function foldAndCollapse(input) {
  const out = []; // { lower, cased, start, end }
  let pendingSpace = null; // whitespace run waiting to be emitted
  for (const u of units(input)) {
    const first = String.fromCodePoint(u.raw.codePointAt(0));
    if (ZERO_WIDTH_RE.test(first)) continue;
    if (CONTROL_RE.test(first) && !KEEP_CONTROL.has(first)) continue;
    const nfkc = u.raw.normalize("NFKC");
    for (const ch of nfkc) {
      if (WHITESPACE_RE.test(ch)) {
        if (pendingSpace === null) pendingSpace = { lower: " ", cased: " ", start: u.start, end: u.end };
        pendingSpace.end = u.end;
        if (ch === "\n") pendingSpace.lower = pendingSpace.cased = "\n";
        continue;
      }
      if (ZERO_WIDTH_RE.test(ch) || (CONTROL_RE.test(ch) && !KEEP_CONTROL.has(ch))) continue;
      if (pendingSpace !== null) {
        out.push(pendingSpace);
        pendingSpace = null;
      }
      const lower = ch.toLowerCase();
      // A character whose lowercase form has a different length keeps its case so both
      // strings stay aligned (e.g. U+0130); the regexes are case-insensitive anyway.
      out.push({ lower: lower.length === ch.length ? lower : ch, cased: ch, start: u.start, end: u.end });
    }
  }
  if (pendingSpace !== null) out.push(pendingSpace);
  return out;
}

/** Step 4: leetspeak inside tokens that also contain letters. */
function mapLeet(chars) {
  let i = 0;
  while (i < chars.length) {
    if (!TOKEN_CHAR_RE.test(chars[i].lower)) {
      i++;
      continue;
    }
    let j = i;
    while (j < chars.length && TOKEN_CHAR_RE.test(chars[j].lower)) j++;
    const token = chars.slice(i, j).map((c) => c.lower).join("");
    const hasLetter = LETTER_RE.test(token);
    const keep =
      CURRENCY_NEXT_TO_DIGIT_RE.test(token) ||
      NUMBER_THEN_LETTERS_RE.test(token) ||
      LETTERS_THEN_NUMBER_RE.test(token);
    if (hasLetter && !keep) {
      for (let k = i; k < j; k++) {
        const mapped = LEET_MAP[chars[k].lower];
        if (mapped !== undefined) chars[k].lower = mapped;
      }
    }
    i = j;
  }
}

/** Step 5: "p a s s w o r d" -> "password" (the spaces are dropped, offsets kept). */
function collapseSpacedLetters(chars) {
  const isLetter = (k) => k >= 0 && k < chars.length && LETTER_RE.test(chars[k].lower);
  const isSpace = (k) => k >= 0 && k < chars.length && chars[k].lower === " ";
  const out = [];
  let i = 0;
  while (i < chars.length) {
    // A run starts at a single letter not glued to a previous letter or digit.
    const standalone = isLetter(i) && !isLetter(i - 1) && !(i > 0 && /\p{N}/u.test(chars[i - 1].lower));
    if (standalone) {
      let j = i; // index of the last letter in the run
      let count = 1;
      while (isSpace(j + 1) && isLetter(j + 2) && !isLetter(j + 3) && !/\p{N}/u.test(chars[j + 3]?.lower ?? "")) {
        j += 2;
        count++;
      }
      if (count >= SPACED_LETTERS_MIN && !isLetter(i + 1)) {
        for (let k = i; k <= j; k += 2) out.push(chars[k]);
        i = j + 1;
        continue;
      }
    }
    out.push(chars[i]);
    i++;
  }
  return out;
}

/**
 * @param {string} input
 * @returns {Normalized}
 */
export function normalize(input) {
  const chars = foldAndCollapse(input);
  mapLeet(chars);
  const collapsed = collapseSpacedLetters(chars);

  let text = "";
  let cased = "";
  const starts = [];
  const ends = [];
  for (const c of collapsed) {
    // `lower` and `cased` always have the same length (see foldAndCollapse and LEET_MAP).
    text += c.lower;
    cased += c.cased;
    for (let k = 0; k < c.lower.length; k++) {
      starts.push(c.start);
      ends.push(c.end);
    }
  }

  return {
    input,
    text,
    cased,
    toOriginal(start, end) {
      if (end <= start) return [starts[start] ?? input.length, starts[start] ?? input.length];
      return [starts[start], ends[end - 1]];
    },
  };
}
