import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { score, blend, verdictFor } from "../src/index.js";
import { ALL_SIGNAL_IDS, MAX_INPUT_LENGTH } from "../src/config.js";

const NUM_RUNS = 100; // every property runs at least 100 iterations
const run = (property) => fc.assert(property, { numRuns: NUM_RUNS });

const VERDICTS = ["pookie", "skeptical", "poltergeist"];
const PHRASE_SIGNALS = new Set([
  "urgency-en",
  "credential-request",
  "prize-lottery",
  "advance-fee-scheme",
  "financial-info-request",
  "unusual-payment-method",
  "secrecy-pressure",
]);
const SAFETY_CLAIM_RE = /\b(safe|risk-free)\b/i;
const TIME_LIMIT_MS = 500;

// ---------------------------------------------------------------------------
// Arbitraries
// ---------------------------------------------------------------------------
const l1Arb = fc.integer({ min: 0, max: 100 });
const l2Arb = fc.boolean();
const l3Arb = fc.oneof(fc.constant(null), fc.integer({ min: 0, max: 100 }));
const flagListArb = fc.array(fc.constantFrom(...ALL_SIGNAL_IDS));
const flagsArb = fc.tuple(flagListArb, fc.boolean()).map(([list, asSet]) => (asSet ? new Set(list) : list));

const invalidL3Arb = fc.oneof(
  fc.constant(NaN),
  fc.constant(Infinity),
  fc.constant(-Infinity),
  fc.double().filter((d) => !Number.isInteger(d)),
  fc.integer({ max: -1 }),
  fc.integer({ min: 101 }),
  fc.string(),
);

const nonStringArb = fc.oneof(
  fc.integer(),
  fc.boolean(),
  fc.constant(null),
  fc.constant(undefined),
  fc.array(fc.anything()),
  fc.object(),
  fc.constant(Symbol("not-a-string")),
);

// Fixtures use fictional brands and reserved TLDs only.
const PHISHY_FRAGMENTS = [
  "hello",
  "\n",
  "Act now",
  "verify immediately",
  "password",
  "OTP",
  "please log in",
  "invoice.exe",
  "Node.js",
  "http://bad.xyz/portal",
  "https://galact1bank.example/login",
  "http://galactibank.xyz",
  "galactibank.example",
  "visit gаlactibank.example",
  "xn--galctibnk-r8a.example",
  "http://203.0.113.5/verify",
  "http://[2001:db8::1]/",
  "From: Galactibank Support <noreply@phish.invalid>\n",
  "Authentication-Results: mx.example.test; spf=fail dkim=fail dmarc=fail\n",
  "Received-SPF: softfail\n",
  '<a href="http://phish.invalid/offer">http://galactibank.example</a>',
  "[galactibank.example](https://phish.invalid/x)",
  "safe.xyz",
  "Congratulations!",
  "You have won $1 million.",
  "lucky winner",
  "Enter your credit card details",
  "reply with your CVV",
  "Thanks for paying by credit card.",
  "We will never ask you to share your card number.",
  "inheritance",
  "transfer of USD 4.5 million",
  "pay the clearance fee",
  "buy Google Play gift cards",
  "pay in bitcoin",
  "send the fee via mobile wallet",
  "Do not tell anyone.",
  "keep this confidential",
];
const phishyArb = fc
  .array(fc.constantFrom(...PHISHY_FRAGMENTS), { maxLength: 40 })
  .map((parts) => parts.join(" "))
  .filter((s) => s.length <= MAX_INPUT_LENGTH);

const textArb = fc.oneof(
  fc.string({ maxLength: MAX_INPUT_LENGTH }),
  fc.string({ unit: "binary", maxLength: MAX_INPUT_LENGTH / 2 }),
  phishyArb,
);

const validOptionsArb = fc.oneof(
  fc.constant(undefined),
  fc.constant(null),
  fc.record({ l2Hit: fc.boolean(), l3Score: l3Arb }, { requiredKeys: [] }),
);

const ADVERSARIAL_FRAGMENTS = [
  "a.", "<a ", "[", "http://", "From: ", "-", "xn--", " ",
  // content proximity regexes: many verbs, negations and near-miss terms in one long sentence
  "enter ", "pay ", "send ", "never ", "not ", "credit ", "card ", "gift ", "mobile ", "wallet ", "fee ",
  "$1", "1,", " million", "congratulations ", "transfer of ", "don't ", "keep this ",
];
const adversarialArb = fc.oneof(
  fc
    .array(fc.constantFrom(...ADVERSARIAL_FRAGMENTS), { maxLength: 1000 })
    .map((a) => a.join(""))
    .filter((s) => s.length <= MAX_INPUT_LENGTH),
  // long runs of a single character
  fc
    .tuple(fc.constantFrom("a", ".", "-", "1", "[", "<", " ", "\n", "@", "x", "é", "$"), fc.integer({ min: 1, max: MAX_INPUT_LENGTH }))
    .map(([c, n]) => c.repeat(n)),
);

// ---------------------------------------------------------------------------
// score() properties
// ---------------------------------------------------------------------------
describe("score properties", () => {
  // Feature: threat-scoring, Property 1: non-string input is rejected with TypeError
  it("P1: non-string input rejection", () => {
    run(fc.property(nonStringArb, (value) => {
      expect(() => score(value)).toThrow(TypeError);
    }));
  });

  // Feature: threat-scoring, Property 2: input length boundary at 4000 characters
  it("P2: input length boundary", () => {
    run(fc.property(fc.string({ minLength: MAX_INPUT_LENGTH + 1, maxLength: MAX_INPUT_LENGTH + 2000 }), (s) => {
      expect(() => score(s)).toThrow(RangeError);
    }));
    run(fc.property(fc.string({ maxLength: MAX_INPUT_LENGTH }), (s) => {
      expect(() => score(s)).not.toThrow();
    }));
  });

  // Feature: threat-scoring, Property 3: invalid l3Score is rejected with RangeError
  it("P3: invalid l3Score rejection", () => {
    run(fc.property(invalidL3Arb, (l3Score) => {
      expect(() => score("hi", { l3Score })).toThrow(RangeError);
    }));
  });

  // Feature: threat-scoring, Property 4: omitted, null and default options are equivalent
  it("P4: options default equivalence", () => {
    run(fc.property(textArb, (input) => {
      const base = score(input);
      expect(score(input, undefined)).toEqual(base);
      expect(score(input, null)).toEqual(base);
      expect(score(input, {})).toEqual(base);
      expect(score(input, { l2Hit: false, l3Score: null })).toEqual(base);
    }));
  });

  // Feature: threat-scoring, Property 5: score is deterministic and keeps no shared state
  it("P5: determinism", () => {
    run(fc.property(textArb, validOptionsArb, textArb, (input, options, other) => {
      const first = score(input, options);
      expect(score(input, options)).toEqual(first);
      score(other);
      expect(score(input, options)).toEqual(first);
    }));
  });

  // Feature: threat-scoring, Property 6: RiskResult has exactly the documented fields
  it("P6: RiskResult shape", () => {
    run(fc.property(textArb, validOptionsArb, (input, options) => {
      const r = score(input, options);
      expect(Object.keys(r).sort()).toEqual(["confidence", "cursedPhrases", "redFlags", "riskScore", "verdict"]);
      expect(Number.isInteger(r.riskScore)).toBe(true);
      expect(r.riskScore).toBeGreaterThanOrEqual(0);
      expect(r.riskScore).toBeLessThanOrEqual(100);
      expect(VERDICTS).toContain(r.verdict);
      expect(Array.isArray(r.redFlags)).toBe(true);
      expect(Array.isArray(r.cursedPhrases)).toBe(true);
    }));
  });

  // Feature: threat-scoring, Property 7: every RedFlag is well-formed and its explanation claims no safety
  it("P7: RedFlag shape", () => {
    run(fc.property(textArb, (input) => {
      for (const f of score(input).redFlags) {
        expect(typeof f.id).toBe("string");
        expect(f.id.length).toBeGreaterThan(0);
        expect(typeof f.weight).toBe("number");
        expect(f.weight).toBeGreaterThan(0);
        expect(typeof f.evidence).toBe("string");
        expect(f.evidence.length).toBeGreaterThan(0);
        expect(typeof f.explanation).toBe("string");
        expect(f.explanation.length).toBeGreaterThan(0);
        // The evidence is quoted user text (it may contain e.g. "safe.xyz"); only the engine's own
        // wording is checked for a claim of safety.
        expect(f.explanation.split(f.evidence).join("")).not.toMatch(SAFETY_CLAIM_RE);
      }
    }));
  });

  // Feature: threat-scoring, Property 8: cursed phrases are well-formed and only present with phrase signals
  it("P8: CursedPhrase shape and population", () => {
    run(fc.property(textArb, (input) => {
      const r = score(input);
      for (const p of r.cursedPhrases) {
        expect(p.text.length).toBeGreaterThan(0);
        expect(p.reason.length).toBeGreaterThan(0);
        expect(input).toContain(p.text);
      }
      const phraseSignalFired = r.redFlags.some((f) => PHRASE_SIGNALS.has(f.id));
      expect(r.cursedPhrases.length > 0).toBe(phraseSignalFired);
    }));
  });

  // Feature: threat-scoring, Property 9: at most one RedFlag per signal id
  it("P9: one flag per signal", () => {
    run(fc.property(textArb, (input) => {
      const ids = score(input).redFlags.map((f) => f.id);
      expect(new Set(ids).size).toBe(ids.length);
    }));
  });

  // Feature: threat-scoring, Property 10: a message with red flags never scores 0
  it("P10: safety floor", () => {
    run(fc.property(textArb, validOptionsArb, (input, options) => {
      const r = score(input, options);
      if (r.redFlags.length > 0) expect(r.riskScore).toBeGreaterThan(0);
    }));
  });

  // Feature: threat-scoring, Property 11: verdict always matches verdictFor(riskScore)
  it("P11: verdict consistency", () => {
    run(fc.property(textArb, validOptionsArb, (input, options) => {
      const r = score(input, options);
      expect(r.verdict).toBe(verdictFor(r.riskScore));
    }));
  });

  // Feature: threat-scoring, Property 12: confidence is "limited" without l3Score and "full" with it
  it("P12: confidence", () => {
    run(fc.property(textArb, l3Arb, fc.boolean(), (input, l3Score, omit) => {
      const r = omit ? score(input) : score(input, { l3Score });
      expect(["limited", "full"]).toContain(r.confidence);
      expect(r.confidence).toBe(!omit && l3Score !== null ? "full" : "limited");
    }));
  });

  // Feature: threat-scoring, Property 20: arbitrary and adversarial input never throws and stays fast
  it("P20: robustness (ReDoS)", () => {
    // Hand-built worst cases for every bounded-gap regex: each start position is a candidate
    // verb/marker and the closing term never arrives (or arrives only at the very end).
    const fill = (unit) => unit.repeat(Math.floor(MAX_INPUT_LENGTH / unit.length));
    const worstCases = [
      fill("enter "),
      fill("enter your "),
      fill("never share "),
      fill("pay send buy "),
      fill("pay mobile wallet "),
      fill("pay fee "),
      fill("congratulations "),
      fill("$1,"),
      fill("1,1."),
      fill("usd 1 "),
      fill("transfer of $1 "),
      fill("don't "),
      fill("enter ").slice(0, MAX_INPUT_LENGTH - 12) + "credit card",
      fill("pay ").slice(0, MAX_INPUT_LENGTH - 10) + "gift cards",
    ];
    for (const input of worstCases) {
      expect(input.length).toBeLessThanOrEqual(MAX_INPUT_LENGTH);
      const start = performance.now();
      expect(() => score(input)).not.toThrow();
      expect(performance.now() - start).toBeLessThan(TIME_LIMIT_MS);
    }
    run(fc.property(fc.oneof(textArb, adversarialArb), (input) => {
      const start = performance.now();
      expect(() => score(input)).not.toThrow();
      expect(performance.now() - start).toBeLessThan(TIME_LIMIT_MS);
    }));
  });
});

// Feature: threat-scoring, Property 21: scam-style text stays in range, is deterministic and meets its floors
describe("scam signal properties", () => {
  const SCAM_FRAGMENTS = PHISHY_FRAGMENTS.slice(PHISHY_FRAGMENTS.indexOf("Congratulations!"));
  const scamArb = fc
    .array(fc.constantFrom(...SCAM_FRAGMENTS, "hello", "\n", "."), { maxLength: 30 })
    .map((parts) => parts.join(" "));

  it("P21: scam text range, determinism and floors", () => {
    run(fc.property(scamArb, validOptionsArb, (input, options) => {
      const r = score(input, options);
      expect(Number.isInteger(r.riskScore)).toBe(true);
      expect(r.riskScore).toBeGreaterThanOrEqual(0);
      expect(r.riskScore).toBeLessThanOrEqual(100);
      expect(score(input, options)).toEqual(r);

      const ids = new Set(r.redFlags.map((f) => f.id));
      const bait = ids.has("prize-lottery") || ids.has("advance-fee-scheme");
      if (bait && (ids.has("financial-info-request") || ids.has("unusual-payment-method"))) {
        expect(r.riskScore).toBeGreaterThanOrEqual(70);
      }
      if (ids.has("financial-info-request")) expect(r.riskScore).toBeGreaterThanOrEqual(50);
      if (ids.has("unusual-payment-method")) expect(r.riskScore).toBeGreaterThanOrEqual(40);
    }));
  });
});

// ---------------------------------------------------------------------------
// blend() and verdictFor() properties
// ---------------------------------------------------------------------------
describe("blend and verdictFor properties", () => {
  // Feature: threat-scoring, Property 13: blend returns an integer in [0, 100]
  it("P13: blend range", () => {
    run(fc.property(l1Arb, l2Arb, l3Arb, flagsArb, (l1, l2, l3, flags) => {
      const r = blend(l1, l2, l3, flags);
      expect(Number.isInteger(r)).toBe(true);
      expect(r).toBeGreaterThanOrEqual(0);
      expect(r).toBeLessThanOrEqual(100);
    }));
  });

  // Feature: threat-scoring, Property 14: with no L2 hit and no L3 score, blend >= l1Score
  it("P14: pure-L1 floor", () => {
    run(fc.property(l1Arb, flagsArb, (l1, flags) => {
      expect(blend(l1, false, null, flags)).toBeGreaterThanOrEqual(l1);
    }));
  });

  // Feature: threat-scoring, Property 15: blend >= round(0.8 * l1Score)
  it("P15: 0.8 x L1 floor", () => {
    run(fc.property(l1Arb, l2Arb, l3Arb, flagsArb, (l1, l2, l3, flags) => {
      expect(blend(l1, l2, l3, flags)).toBeGreaterThanOrEqual(Math.round(0.8 * l1));
    }));
  });

  // Feature: threat-scoring, Property 16: an L2 hit gives blend >= 90
  it("P16: L2 floor", () => {
    run(fc.property(l1Arb, l3Arb, flagsArb, (l1, l3, flags) => {
      expect(blend(l1, true, l3, flags)).toBeGreaterThanOrEqual(90);
    }));
  });

  // Feature: threat-scoring, Property 17: blend is deterministic and Array/Set independent
  it("P17: determinism and representation independence", () => {
    run(fc.property(l1Arb, l2Arb, l3Arb, flagListArb, (l1, l2, l3, list) => {
      const asArray = blend(l1, l2, l3, list);
      expect(blend(l1, l2, l3, list)).toBe(asArray);
      expect(blend(l1, l2, l3, new Set(list))).toBe(asArray);
    }));
  });

  // Feature: threat-scoring, Property 18: the eight hard floors always hold
  it("P18: hard floors", () => {
    const floors = [
      [["typosquatting", "credential-request"], 70],
      [["raw-ip-url", "credential-request"], 70],
      [["spf-fail", "display-name-mismatch"], 60],
      [["dkim-fail", "display-name-mismatch"], 60],
      [["credential-request", "urgency-en"], 55],
      [["suspicious-attachment"], 40],
      [["prize-lottery", "financial-info-request"], 70],
      [["prize-lottery", "unusual-payment-method"], 70],
      [["advance-fee-scheme", "financial-info-request"], 70],
      [["advance-fee-scheme", "unusual-payment-method"], 70],
      [["financial-info-request"], 50],
      [["unusual-payment-method"], 40],
    ];
    run(fc.property(l1Arb, l2Arb, l3Arb, flagListArb, fc.constantFrom(...floors), (l1, l2, l3, extra, [required, min]) => {
      expect(blend(l1, l2, l3, [...extra, ...required])).toBeGreaterThanOrEqual(min);
    }));
  });

  // Feature: threat-scoring, Property 19: verdictFor partitions 0-100 into the three verdicts
  it("P19: verdictFor exhaustiveness", () => {
    const expected = (s) => (s <= 30 ? "pookie" : s <= 69 ? "skeptical" : "poltergeist");
    for (let s = 0; s <= 100; s++) expect(verdictFor(s)).toBe(expected(s));
    run(fc.property(fc.integer({ min: 0, max: 100 }), (s) => {
      expect(VERDICTS).toContain(verdictFor(s));
      expect(verdictFor(s)).toBe(expected(s));
    }));
  });
});
