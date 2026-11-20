import { describe, it, expect } from "vitest";
import { score, verdictFor } from "../src/index.js";

describe("score: input validation", () => {
  it("throws TypeError for non-string input", () => {
    expect(() => score(123)).toThrow(TypeError);
    expect(() => score(123)).toThrow("input must be a string");
  });
  it("throws RangeError above 4000 characters but accepts exactly 4000", () => {
    expect(() => score("x".repeat(4001))).toThrow(RangeError);
    expect(() => score("x".repeat(4001))).toThrow("input exceeds 4000 characters");
    expect(() => score("x".repeat(4000))).not.toThrow();
  });
  it("throws RangeError for a non-integer l3Score", () => {
    expect(() => score("hi", { l3Score: 1.5 })).toThrow(RangeError);
    expect(() => score("hi", { l3Score: 1.5 })).toThrow("l3Score must be an integer 0-100 or null");
  });
  it("accepts null options and l3Score boundaries 0 and 100", () => {
    expect(score("hi", null).verdict).toBe("pookie");
    expect(() => score("hi", { l3Score: 0 })).not.toThrow();
    expect(() => score("hi", { l3Score: 100 })).not.toThrow();
  });
  it("treats omitted and empty options the same", () => {
    expect(score("hi")).toEqual(score("hi", {}));
  });
  it("treats a non-boolean l2Hit as false", () => {
    expect(score("hi", { l2Hit: "yes" })).toEqual(score("hi"));
  });
});

describe("score: verdict boundaries", () => {
  it.each([
    ["hi", 67, 30, "pookie"],
    ["hi", 69, 31, "skeptical"],
    ["Act now: http://203.0.113.5/x", 92, 69, "skeptical"],
    ["Act now: http://203.0.113.5/x", 94, 70, "poltergeist"],
  ])("%s with l3Score %i -> %i (%s)", (input, l3Score, expected, verdict) => {
    const result = score(input, { l3Score });
    expect(result.riskScore).toBe(expected);
    expect(result.verdict).toBe(verdict);
    expect(result.verdict).toBe(verdictFor(result.riskScore));
  });
});

describe("score: brands", () => {
  const brands = [{ name: "zorbbank", domains: ["zorbbank.example"] }];
  it("uses a caller-supplied brand list", () => {
    const ids = (input) => score(input, { brands }).redFlags.map((f) => f.id);
    expect(ids("http://zorbbank.example/x")).not.toContain("typosquatting");
    expect(ids("http://zorbb4nk.example/x")).toContain("typosquatting");
    // The default brand is no longer known when a custom list is supplied.
    expect(ids("http://galact1bank.example/x")).not.toContain("typosquatting");
  });
});

describe("score: result", () => {
  it("has a positive riskScore whenever a flag fires", () => {
    for (const input of ["Visit promo.top", "please log in", "Act now"]) {
      const result = score(input);
      expect(result.redFlags.length).toBeGreaterThan(0);
      expect(result.riskScore).toBeGreaterThan(0);
    }
  });
  it("reports limited confidence without l3Score and full with it", () => {
    expect(score("hi").confidence).toBe("limited");
    expect(score("hi", { l3Score: null }).confidence).toBe("limited");
    expect(score("hi", { l3Score: 50 }).confidence).toBe("full");
  });
  it("applies category caps", () => {
    // display-name-mismatch 25 + spf-fail 20 + dkim-fail 20 = 65 -> capped at 40
    const input =
      "From: Galactibank <a@phish.invalid>\nAuthentication-Results: mx.example.test; spf=fail; dkim=fail";
    const result = score(input);
    expect(result.redFlags.map((f) => f.id).sort()).toEqual(["display-name-mismatch", "dkim-fail", "spf-fail"]);
    expect(result.riskScore).toBe(60); // L1 40, then the 4.7 floor
  });
});
