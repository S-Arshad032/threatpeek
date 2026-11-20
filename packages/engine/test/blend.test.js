import { describe, it, expect } from "vitest";
import { blend } from "../src/blend.js";

describe("blend: layer rules", () => {
  it("4.3: pure L1 with no flags", () => {
    expect(blend(0, false, null, [])).toBe(0);
    expect(blend(35, false, null, [])).toBe(35);
  });

  it("4.1: an L2 hit raises the score to at least 90", () => {
    expect(blend(50, true, null, [])).toBe(90);
    expect(blend(95, true, null, [])).toBe(95);
    expect(blend(0, true, 0, [])).toBe(90); // L2 takes precedence over L3
  });

  it("4.2: weighted L1/L3 blend", () => {
    expect(blend(20, false, 80, [])).toBe(Math.round(0.55 * 20 + 0.45 * 80));
    expect(blend(20, false, 80, [])).toBe(47);
  });

  it("4.4: the result never drops below 0.8 x L1", () => {
    // 0.55*100 + 0.45*0 = 55 < 80
    expect(blend(100, false, 0, [])).toBe(80);
  });

  it("4.10: clamps and rounds", () => {
    expect(blend(100, true, 100, [])).toBe(100);
    expect(Number.isInteger(blend(33, false, 33, []))).toBe(true);
  });
});

describe("blend: hard floors", () => {
  it("4.5: typosquatting + credential-request >= 70", () => {
    expect(blend(35, false, null, ["typosquatting", "credential-request"])).toBe(70);
  });
  it("4.6: raw-ip-url + credential-request >= 70", () => {
    expect(blend(55, false, null, ["raw-ip-url", "credential-request"])).toBe(70);
  });
  it("4.7: spf-fail or dkim-fail + display-name-mismatch >= 60", () => {
    expect(blend(40, false, null, ["spf-fail", "display-name-mismatch"])).toBe(60);
    expect(blend(40, false, null, ["dkim-fail", "display-name-mismatch"])).toBe(60);
    expect(blend(40, false, null, ["dmarc-fail", "display-name-mismatch"])).toBe(40);
  });
  it("4.8: credential-request + urgency >= 55", () => {
    expect(blend(35, false, null, ["credential-request", "urgency-en"])).toBe(55);
    expect(blend(35, false, null, ["credential-request", "urgency-bn"])).toBe(55);
  });
  it("4.9: suspicious-attachment >= 40", () => {
    expect(blend(0, false, null, ["suspicious-attachment"])).toBe(40);
  });
  it("floors never lower a higher score", () => {
    expect(blend(90, false, null, ["suspicious-attachment"])).toBe(90);
  });
});

describe("blend: flag representation", () => {
  it("Array and Set give the same result", () => {
    const flags = ["typosquatting", "credential-request"];
    expect(blend(35, false, 10, flags)).toBe(blend(35, false, 10, new Set(flags)));
  });
});
