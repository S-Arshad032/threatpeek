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
  FLOOR_PRIZE_PAYMENT,
  FLOOR_FINANCIAL_INFO,
  FLOOR_UNUSUAL_PAYMENT,
  FLOOR_CODE_SHARING,
  FLOOR_MISTAKEN_PAYMENT,
  FLOOR_SECRET_REQUEST,
  FLOOR_DELIVERY_SCAM,
  FLOOR_SEED_PHRASE,
  FLOOR_INVESTMENT,
  FLOOR_INVESTMENT_PRESSURE,
  FLOOR_TASK_JOB,
  FLOOR_OFFICIAL_FINE,
  FLOOR_RECRUITER_BAIT,
  FLOOR_UTILITY_DISCONNECTION,
  FLOOR_PAYMENT_FAILED,
  FLOOR_ACCOUNT_SECURITY,
  FLOOR_JOB_FEE,
  SCORE_MIN,
  SCORE_MAX,
} from "./config.js";

/**
 * @param {number} l1Score              integer 0-100
 * @param {boolean} l2Hit
 * @param {number | null} l3Score       integer 0-100 or null
 * @param {string[] | Set<string>} flags signal ids that fired
 * @param {{ paymentInstruction?: boolean, secretRequest?: boolean, jobFee?: boolean }} [context] facts from the content
 *        detector that are not signals: `paymentInstruction` is true when the message explicitly
 *        says where to send the payment ("send it to me", "pay to this account", "send me the
 *        codes"); `secretRequest` is true when the message tells the reader to hand over a
 *        password, PIN, passcode, login or security answer ("Send us your password"); `jobFee` is
 *        true when a job or hiring message asks for an onboarding, registration, training or
 *        similar fee up front
 * @returns {number} integer riskScore 0-100
 */
export function blend(l1Score, l2Hit, l3Score, flags, context) {
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
  if (has("credential-request") && has("urgency-en")) risk = Math.max(risk, FLOOR_CRED_URGENCY); // 4.8
  if (has("suspicious-attachment")) risk = Math.max(risk, FLOOR_ATTACHMENT); // 4.9
  if (
    (has("prize-lottery") || has("advance-fee-scheme")) &&
    (has("financial-info-request") || has("unusual-payment-method"))
  ) {
    risk = Math.max(risk, FLOOR_PRIZE_PAYMENT); // 4.10
  }
  if (has("financial-info-request")) risk = Math.max(risk, FLOOR_FINANCIAL_INFO); // 4.11
  // 4.12: a gift card or crypto alone is ordinary ("Buy a gift card for your mom"); it needs pressure
  // or an explicit hand-over instruction to count as a payment demand.
  const paymentPressure =
    has("urgency-en") ||
    has("secrecy-pressure") ||
    has("prize-lottery") ||
    has("advance-fee-scheme") ||
    context?.paymentInstruction === true;
  if (has("unusual-payment-method") && paymentPressure) risk = Math.max(risk, FLOOR_UNUSUAL_PAYMENT); // 4.12
  if (has("code-sharing-request")) risk = Math.max(risk, FLOOR_CODE_SHARING); // 4.14
  if (has("mistaken-payment")) risk = Math.max(risk, FLOOR_MISTAKEN_PAYMENT); // 4.15
  // 4.16: "Send us your password" is a direct instruction to hand over a secret. The word
  // "password" alone (a reset mail, a security tip) has no floor; only the instruction does.
  if (context?.secretRequest === true) risk = Math.max(risk, FLOOR_SECRET_REQUEST); // 4.16

  // 4.17-4.22: scam families. Every one of these signals already needs several cues together
  // (see detectors/content.js), so the floor never rests on a single word.
  if (has("delivery-scam")) risk = Math.max(risk, FLOOR_DELIVERY_SCAM); // 4.17
  if (has("seed-phrase-request")) risk = Math.max(risk, FLOOR_SEED_PHRASE); // 4.18
  if (has("investment-guarantee")) {
    const pressured = has("urgency-en") || has("unusual-payment-method");
    risk = Math.max(risk, pressured ? FLOOR_INVESTMENT_PRESSURE : FLOOR_INVESTMENT); // 4.19
  }
  if (has("task-job-scam")) risk = Math.max(risk, FLOOR_TASK_JOB); // 4.20
  if (has("official-fine-threat")) risk = Math.max(risk, FLOOR_OFFICIAL_FINE); // 4.21
  if (has("recruiter-bait")) risk = Math.max(risk, FLOOR_RECRUITER_BAIT); // 4.22

  // 4.23-4.26: round 2. Same rule: each signal is already a compound of several cues.
  if (has("utility-disconnection-threat")) risk = Math.max(risk, FLOOR_UTILITY_DISCONNECTION); // 4.23
  if (has("payment-failed-lure")) risk = Math.max(risk, FLOOR_PAYMENT_FAILED); // 4.24
  if (has("account-security-lure")) risk = Math.max(risk, FLOOR_ACCOUNT_SECURITY); // 4.25
  if (has("advance-fee-scheme") && context?.jobFee === true) risk = Math.max(risk, FLOOR_JOB_FEE); // 4.26

  return Math.round(Math.min(SCORE_MAX, Math.max(SCORE_MIN, risk))); // 4.13
}
