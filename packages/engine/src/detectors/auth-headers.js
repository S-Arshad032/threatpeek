// Auth-headers detector: spf-fail, dkim-fail, dmarc-fail. All Identity/Auth.
// Only result headers count. DKIM-Signature carries a signature, not a result, so it never fires.
// Produces no cursed phrases.

import { W_SPF_FAIL, W_DKIM_FAIL, W_DMARC_FAIL } from "../config.js";
import { makeRedFlag } from "../util/flag.js";

const FOLDED_LINE_RE = /\r?\n[ \t]+/g;
const AUTH_RESULTS_LINE_RE = /^Authentication-Results[ \t]*:[^\n]{1,2000}/gim;
const AUTH_RESULT_RE = /\b(spf|dkim|dmarc)\s*=\s*(fail|softfail|permerror)\b/gi;
const RECEIVED_SPF_RE = /^Received-SPF[ \t]*:[ \t]*(fail|softfail)\b/gim;

// Fixed output order keeps results deterministic.
const SIGNALS = [
  { method: "spf", id: "spf-fail", weight: W_SPF_FAIL },
  { method: "dkim", id: "dkim-fail", weight: W_DKIM_FAIL },
  { method: "dmarc", id: "dmarc-fail", weight: W_DMARC_FAIL },
];

/** @param {string} input */
export function detectAuthHeaders(input) {
  // Unfold headers so a header folded over several lines is one line.
  const text = input.replace(FOLDED_LINE_RE, " ");
  const evidence = new Map(); // method -> first matched fragment

  for (const line of text.matchAll(AUTH_RESULTS_LINE_RE)) {
    for (const m of line[0].matchAll(AUTH_RESULT_RE)) {
      const method = m[1].toLowerCase();
      if (!evidence.has(method)) evidence.set(method, m[0]);
    }
  }
  if (!evidence.has("spf")) {
    for (const m of text.matchAll(RECEIVED_SPF_RE)) {
      evidence.set("spf", m[0].trim());
      break;
    }
  }

  const flags = SIGNALS.filter((s) => evidence.has(s.method)).map((s) =>
    makeRedFlag(s.id, s.weight, evidence.get(s.method)),
  );
  return { flags, cursedPhrases: [] };
}
