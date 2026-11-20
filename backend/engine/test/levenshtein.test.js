import { describe, it, expect } from "vitest";
import { levenshtein } from "../src/util/levenshtein.js";

describe("levenshtein", () => {
  it("handles empty strings", () => {
    expect(levenshtein("", "")).toBe(0);
    expect(levenshtein("", "abc")).toBe(3);
    expect(levenshtein("abcd", "")).toBe(4);
  });

  it("returns exact distances for known pairs", () => {
    expect(levenshtein("kitten", "sitting")).toBe(3);
    expect(levenshtein("flaw", "lawn")).toBe(2);
    expect(levenshtein("galactibank", "galact1bank")).toBe(1);
    expect(levenshtein("same", "same")).toBe(0);
    expect(levenshtein("abc", "xyz")).toBe(3);
  });

  it("returns the exact (uncapped) distance for long, very different strings", () => {
    const a = "a".repeat(100);
    const b = "b".repeat(80);
    expect(levenshtein(a, b)).toBe(100);
    expect(levenshtein("x".repeat(70), "")).toBe(70);
  });

  it("is symmetric", () => {
    expect(levenshtein("trustledger", "trustledgr")).toBe(levenshtein("trustledgr", "trustledger"));
  });
});
