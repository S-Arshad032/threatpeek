import { describe, it, expect } from "vitest";
import * as C from "../src/config.js";

describe("config", () => {
  it("has an explanation template and category for every signal id", () => {
    expect(C.ALL_SIGNAL_IDS).toHaveLength(13);
    for (const id of C.ALL_SIGNAL_IDS) {
      expect(typeof C.EXPLANATION_TEMPLATES[id]).toBe("string");
      expect(C.EXPLANATION_TEMPLATES[id].length).toBeGreaterThan(0);
      expect(C.CATEGORY_CAPS[C.SIGNAL_CATEGORY[id]]).toBeGreaterThan(0);
    }
  });

  it("has non-empty cursed-phrase reasons for the phrase-producing signals", () => {
    for (const id of ["urgency-en", "urgency-bn", "credential-request"]) {
      expect(C.CURSED_PHRASE_REASONS[id].length).toBeGreaterThan(0);
    }
  });

  it("uses the agreed urgency phrase lists", () => {
    expect(C.URGENCY_EN_PHRASES).toHaveLength(10);
    expect(C.URGENCY_BN_PHRASES[0]).toBe("আপনার অ্যাকাউন্ট স্থগিত হবে");
    expect(C.RISKY_TLDS).toEqual(["xyz", "top", "click", "tk", "ml", "ga", "cf"]);
  });
});
