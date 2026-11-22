import { describe, it, expect } from "vitest";
import * as C from "../src/config.js";

const PHRASE_SIGNALS = [
  "urgency-en",
  "credential-request",
  "prize-lottery",
  "advance-fee-scheme",
  "financial-info-request",
  "unusual-payment-method",
  "secrecy-pressure",
];

describe("config", () => {
  it("has an explanation template and category for every signal id", () => {
    expect(C.ALL_SIGNAL_IDS).toHaveLength(17);
    for (const id of C.ALL_SIGNAL_IDS) {
      expect(typeof C.EXPLANATION_TEMPLATES[id]).toBe("string");
      expect(C.EXPLANATION_TEMPLATES[id].length).toBeGreaterThan(0);
      expect(C.CATEGORY_CAPS[C.SIGNAL_CATEGORY[id]]).toBeGreaterThan(0);
    }
    expect(Object.keys(C.EXPLANATION_TEMPLATES).sort()).toEqual([...C.ALL_SIGNAL_IDS].sort());
  });

  it("has non-empty cursed-phrase reasons for the phrase-producing signals", () => {
    for (const id of PHRASE_SIGNALS) {
      expect(C.CURSED_PHRASE_REASONS[id].length).toBeGreaterThan(0);
    }
    expect(Object.keys(C.CURSED_PHRASE_REASONS).sort()).toEqual([...PHRASE_SIGNALS].sort());
  });

  it("puts the new scam signals in the Content category with the agreed weights", () => {
    for (const id of ["prize-lottery", "advance-fee-scheme", "financial-info-request", "unusual-payment-method", "secrecy-pressure"]) {
      expect(C.SIGNAL_CATEGORY[id]).toBe(C.CATEGORY_CONTENT);
    }
    expect(C.W_PRIZE_LOTTERY).toBe(25);
    expect(C.W_ADVANCE_FEE_SCHEME).toBe(25);
    expect(C.W_FINANCIAL_INFO_REQUEST).toBe(30);
    expect(C.W_UNUSUAL_PAYMENT_METHOD).toBe(20);
    expect(C.W_SECRECY_PRESSURE).toBe(10);
    expect(C.CAP_CONTENT).toBe(45);
    expect([C.FLOOR_PRIZE_PAYMENT, C.FLOOR_FINANCIAL_INFO, C.FLOOR_UNUSUAL_PAYMENT]).toEqual([70, 50, 40]);
  });

  it("is English-only: no Bangla signal, constant or script", () => {
    expect(C.ALL_SIGNAL_IDS).not.toContain("urgency-bn");
    for (const name of ["W_URGENCY_BN", "URGENCY_BN_PHRASES", "CREDENTIAL_BN_TERMS"]) {
      expect(name in C).toBe(false);
    }
    const BENGALI_BLOCK_START = 0x0980;
    const BENGALI_BLOCK_END = 0x09ff;
    const BENGALI_SCRIPT = new RegExp(
      `[${String.fromCodePoint(BENGALI_BLOCK_START)}-${String.fromCodePoint(BENGALI_BLOCK_END)}]`,
    );
    for (const value of Object.values(C)) {
      expect(BENGALI_SCRIPT.test(JSON.stringify(value) ?? "")).toBe(false);
    }
  });

  it("uses the agreed urgency phrase lists", () => {
    expect(C.URGENCY_EN_PHRASES).toHaveLength(10);
    expect(C.RISKY_TLDS).toEqual(["xyz", "top", "click", "tk", "ml", "ga", "cf"]);
  });
});
