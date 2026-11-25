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

  it("4.13: clamps and rounds", () => {
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
  });
  it("4.9: suspicious-attachment >= 40", () => {
    expect(blend(0, false, null, ["suspicious-attachment"])).toBe(40);
  });
  it("4.10: (prize-lottery or advance-fee-scheme) + (financial-info-request or unusual-payment-method) >= 70", () => {
    expect(blend(45, false, null, ["prize-lottery", "financial-info-request"])).toBe(70);
    expect(blend(45, false, null, ["prize-lottery", "unusual-payment-method"])).toBe(70);
    expect(blend(45, false, null, ["advance-fee-scheme", "financial-info-request"])).toBe(70);
    expect(blend(45, false, null, ["advance-fee-scheme", "unusual-payment-method"])).toBe(70);
    // A prize claim or an advance-fee story alone has no floor.
    expect(blend(25, false, null, ["prize-lottery"])).toBe(25);
    expect(blend(45, false, null, ["prize-lottery", "advance-fee-scheme"])).toBe(45);
  });
  it("4.11: financial-info-request >= 50", () => {
    expect(blend(30, false, null, ["financial-info-request"])).toBe(50);
    expect(blend(30, false, 0, ["financial-info-request"])).toBe(50);
  });
  it("4.12: unusual-payment-method + pressure or a hand-over instruction >= 40", () => {
    expect(blend(30, false, null, ["unusual-payment-method", "secrecy-pressure"])).toBe(40);
    expect(blend(35, false, null, ["unusual-payment-method", "urgency-en"])).toBe(40);
    expect(blend(20, false, null, ["unusual-payment-method"], { paymentInstruction: true })).toBe(40);
    expect(blend(45, false, null, ["unusual-payment-method", "prize-lottery"])).toBe(70); // 4.10 is higher
  });
  it("4.12: unusual-payment-method alone has no floor", () => {
    // "Buy a gift card for your mom" is not a payment demand.
    expect(blend(20, false, null, ["unusual-payment-method"])).toBe(20);
    expect(blend(20, false, null, ["unusual-payment-method"], {})).toBe(20);
    expect(blend(20, false, null, ["unusual-payment-method"], { paymentInstruction: false })).toBe(20);
    expect(blend(30, false, null, ["unusual-payment-method", "credential-request"])).toBe(30);
  });
  it("4.14: code-sharing-request >= 50", () => {
    expect(blend(30, false, null, ["code-sharing-request"])).toBe(50);
    expect(blend(30, false, 0, ["code-sharing-request"])).toBe(50);
  });
  it("4.15: mistaken-payment >= 40", () => {
    expect(blend(25, false, null, ["mistaken-payment"])).toBe(40);
  });
  it("4.16: context.secretRequest >= 45", () => {
    expect(blend(20, false, null, ["credential-request"], { secretRequest: true })).toBe(45);
    expect(blend(20, false, 0, ["credential-request"], { secretRequest: true })).toBe(45);
    expect(blend(20, false, 80, ["credential-request"], { secretRequest: true })).toBe(47); // already higher
  });
  it("credential-request alone has no floor (no secretRequest)", () => {
    expect(blend(20, false, null, ["credential-request"])).toBe(20);
    expect(blend(20, false, null, ["credential-request"], { secretRequest: false })).toBe(20);
  });
  it("remote-access-request alone has no floor", () => {
    expect(blend(25, false, null, ["remote-access-request"])).toBe(25);
  });
  it("secrecy-pressure alone has no floor", () => {
    expect(blend(10, false, null, ["secrecy-pressure"])).toBe(10);
  });
  it("floors never lower a higher score", () => {
    expect(blend(90, false, null, ["prize-lottery", "financial-info-request"])).toBe(90);
    expect(blend(90, false, null, ["suspicious-attachment"])).toBe(90);
  });
});

describe("blend: scam-family floors (4.17-4.22)", () => {
  it("each family signal lifts the score to its floor", () => {
    expect(blend(25, false, null, ["delivery-scam"])).toBe(50); // 4.17
    expect(blend(35, false, null, ["seed-phrase-request"])).toBe(70); // 4.18
    expect(blend(25, false, null, ["investment-guarantee"])).toBe(55); // 4.19
    expect(blend(25, false, null, ["task-job-scam"])).toBe(50); // 4.20
    expect(blend(25, false, null, ["official-fine-threat"])).toBe(60); // 4.21
    expect(blend(20, false, null, ["recruiter-bait"])).toBe(50); // 4.22
  });
  it("investment-guarantee with pressure or an unusual payment method reaches 70", () => {
    expect(blend(40, false, null, ["urgency-en", "investment-guarantee"])).toBe(70);
    expect(blend(45, false, null, ["investment-guarantee", "unusual-payment-method"])).toBe(70);
    expect(blend(45, false, null, ["investment-guarantee", "prize-lottery"])).toBe(55);
  });
  it("the weak signals around the families have no floor of their own", () => {
    expect(blend(10, false, null, ["defanged-link"])).toBe(10);
    expect(blend(15, false, null, ["urgency-en"])).toBe(15);
    expect(blend(25, false, null, ["urgency-en", "defanged-link"])).toBe(25);
  });
  it("family floors never lower a higher score", () => {
    expect(blend(90, false, null, ["delivery-scam"])).toBe(90);
    expect(blend(95, false, null, ["seed-phrase-request"])).toBe(95);
  });
});

describe("blend: flag representation", () => {
  it("Array and Set give the same result", () => {
    const flags = ["typosquatting", "credential-request"];
    expect(blend(35, false, 10, flags)).toBe(blend(35, false, 10, new Set(flags)));
  });
});
