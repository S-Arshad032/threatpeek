// Combines L1 heuristics, the L2 blacklist hit and the optional L3 AI score into one riskScore.

import {
  BLEND_L1_WEIGHT,
  BLEND_L3_WEIGHT,
  BLEND_L1_FLOOR_FACTOR,
  BLEND_L2_FLOOR,
  FLOOR_TYPOSQUAT_CRED,
  FLOOR_RAWIP_CRED,
  FLOOR_AUTH_DISPLAY,
  FLOOR_CRED_URGENCY,
  FLOOR_ATTACHMENT,
  SCORE_MIN,
  SCORE_MAX,
} from "./config.js";

/**
 * @param {number} l1Score              integer 0-100
 * @param {boolean} l2Hit
 * @param {number | null} l3Score       integer 0-100 or null
 * @param {string[] | Set<string>} flags signal ids that fired
 * @returns {number} integer riskScore 0-100
 */
export function blend(l1Score, l2Hit, l3Score, flags) {
  const flagSet = new Set(flags);
  const has = (id) => flagSet.has(id);

  let risk;
  if (l2Hit) {
    risk = Math.max(BLEND_L2_FLOOR, l1Score); // 4.1
  } else if (l3Score != null) {
    risk = BLEND_L1_WEIGHT * l1Score + BLEND_L3_WEIGHT * l3Score; // 4.2
  } else {
    risk = l1Score; // 4.3
  }

  risk = Math.max(risk, BLEND_L1_FLOOR_FACTOR * l1Score); // 4.4

  // Hard floors only ever raise the score.
  if (has("typosquatting") && has("credential-request")) risk = Math.max(risk, FLOOR_TYPOSQUAT_CRED); // 4.5
  if (has("raw-ip-url") && has("credential-request")) risk = Math.max(risk, FLOOR_RAWIP_CRED); // 4.6
  if ((has("spf-fail") || has("dkim-fail")) && has("display-name-mismatch")) {
    risk = Math.max(risk, FLOOR_AUTH_DISPLAY); // 4.7
  }
  if (has("credential-request") && (has("urgency-en") || has("urgency-bn"))) {
    risk = Math.max(risk, FLOOR_CRED_URGENCY); // 4.8
  }
  if (has("suspicious-attachment")) risk = Math.max(risk, FLOOR_ATTACHMENT); // 4.9

  return Math.round(Math.min(SCORE_MAX, Math.max(SCORE_MIN, risk))); // 4.10
}
