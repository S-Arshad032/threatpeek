// Builds RedFlag objects with the plain-English explanation for their signal id.

import { EXPLANATION_TEMPLATES, EVIDENCE_PLACEHOLDER } from "../config.js";

/**
 * @param {string} id        signal id (key of EXPLANATION_TEMPLATES)
 * @param {number} weight
 * @param {string} evidence  text taken from the input (untrusted; UI must render as plain text)
 * @returns {{ id: string, weight: number, evidence: string, explanation: string }}
 */
export function makeRedFlag(id, weight, evidence) {
  const template = EXPLANATION_TEMPLATES[id];
  // Function replacer so "$&", "$1" etc. inside the evidence are inserted literally.
  const explanation = template.replace(EVIDENCE_PLACEHOLDER, () => evidence);
  return { id, weight, evidence, explanation };
}
