// Top-level orchestrator: validates input, runs the detectors, blends the layers and
// assembles the RiskResult. Pure and deterministic: no I/O, no randomness, no shared state.

import { MAX_INPUT_LENGTH, SIGNAL_CATEGORY, CATEGORY_CAPS, SCORE_MIN, SCORE_MAX } from "./config.js";
import { DEFAULT_BRANDS } from "./brands.js";
import { detectIdentity } from "./detectors/identity.js";
import { detectAuthHeaders } from "./detectors/auth-headers.js";
import { detectLinks } from "./detectors/link.js";
import { detectContent } from "./detectors/content.js";
import { blend } from "./blend.js";
import { verdictFor } from "./verdict.js";

/**
 * @typedef {{ id: string, weight: number, evidence: string, explanation: string }} RedFlag
 * @typedef {{ text: string, reason: string }} CursedPhrase
 * @typedef {{ riskScore: number, verdict: "pookie" | "skeptical" | "poltergeist",
 *             redFlags: RedFlag[], cursedPhrases: CursedPhrase[], confidence: "limited" | "full" }} RiskResult
 * @typedef {{ l2Hit?: boolean, l3Score?: number | null,
 *             brands?: Array<{ name: string, domains: string[] }> }} ScoreOptions
 */

/** Sums weights per category, caps each category, and clamps the total. */
function computeL1(redFlags) {
  const totals = {};
  for (const flag of redFlags) {
    const category = SIGNAL_CATEGORY[flag.id];
    totals[category] = (totals[category] ?? 0) + flag.weight;
  }
  let sum = 0;
  for (const [category, total] of Object.entries(totals)) {
    sum += Math.min(total, CATEGORY_CAPS[category]);
  }
  return Math.min(SCORE_MAX, Math.max(SCORE_MIN, sum));
}

/** Keeps the first flag for each signal id (one-flag-per-signal rule). */
function uniqueById(flags) {
  const seen = new Set();
  return flags.filter((f) => (seen.has(f.id) ? false : (seen.add(f.id), true)));
}

/**
 * @param {string} input
 * @param {ScoreOptions | null} [options]
 * @returns {RiskResult}
 */
export function score(input, options) {
  if (typeof input !== "string") throw new TypeError("input must be a string");
  if (input.length > MAX_INPUT_LENGTH) throw new RangeError(`input exceeds ${MAX_INPUT_LENGTH} characters`);

  const opts = options ?? {};
  const l2Hit = opts.l2Hit === true; // only boolean true activates L2
  const l3Score = opts.l3Score === undefined ? null : opts.l3Score;
  if (l3Score !== null) {
    if (typeof l3Score !== "number" || !Number.isInteger(l3Score) || l3Score < SCORE_MIN || l3Score > SCORE_MAX) {
      throw new RangeError(`l3Score must be an integer ${SCORE_MIN}-${SCORE_MAX} or null`);
    }
  }
  const brands = Array.isArray(opts.brands) ? opts.brands : DEFAULT_BRANDS;

  // Fixed detector order gives a deterministic flag order.
  const identity = detectIdentity(input, brands);
  const authHeaders = detectAuthHeaders(input);
  const links = detectLinks(input);
  const content = detectContent(input);

  const redFlags = uniqueById([...identity.flags, ...authHeaders.flags, ...links.flags, ...content.flags]);
  const l1Score = computeL1(redFlags);
  const riskScore = blend(
    l1Score,
    l2Hit,
    l3Score,
    redFlags.map((f) => f.id),
  );

  return {
    riskScore,
    verdict: verdictFor(riskScore),
    redFlags,
    cursedPhrases: content.cursedPhrases,
    confidence: l3Score !== null ? "full" : "limited",
  };
}
