// Maps a riskScore to the ghost verdict shown in the UI.

import { VERDICT_POOKIE_MAX, VERDICT_SKEPTICAL_MAX } from "./config.js";

/**
 * @param {number} riskScore integer 0-100
 * @returns {"pookie" | "skeptical" | "poltergeist"}
 */
export function verdictFor(riskScore) {
  if (riskScore <= VERDICT_POOKIE_MAX) return "pookie"; // 0-30
  if (riskScore <= VERDICT_SKEPTICAL_MAX) return "skeptical"; // 31-69
  return "poltergeist"; // 70-100
}
