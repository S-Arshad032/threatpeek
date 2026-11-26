import { describe, it, expect } from "vitest";
import { score } from "../src/index.js";
import { detectLinks } from "../src/detectors/link.js";
import { detectContent } from "../src/detectors/content.js";
import { blend } from "../src/blend.js";
import {
  W_LOOKALIKE_LURE_DOMAIN,
  W_LOOKALIKE_LURE_DOMAIN_STRONG,
  FLOOR_JOB_FEE,
  EXPLANATION_TEMPLATES,
  CURSED_PHRASE_REASONS,
} from "../src/config.js";

// Round 2 signals (lookalike-lure-domain, utility-disconnection-threat, payment-failed-lure,
// account-security-lure) and the job extensions (job fee floor 4.26, remote-work task-job path).
// Every message is written for this file: fictional names, reserved or made-up domains, and
// wording that does not come from any benchmark set.
const ids = (input) => score(input).redFlags.map((f) => f.id);
const linkFlag = (input) => detectLinks(input).flags.find((f) => f.id === "lookalike-lure-domain");

const PARAPHRASES = {
  "utility-disconnection-threat": [
    "Notice from Riverton Power: your supply will be disconnected today at 6 PM because of an overdue bill. Pay at power-bill-help.example/pay",
    "Your home internet connection will be cut off tonight over unpaid dues of $42. Settle now to keep service: net-billing-check.test",
    "WATER BOARD: service termination scheduled for your meter due to an outstanding balance. Pay now to avoid disconnection.",
  ],
  "payment-failed-lure": [
    "Streamly: your renewal payment was declined. Re-enter your card details at account-billing-fix.example within 24 hours or your profile will be deleted.",
    "We could not process your subscription payment. Please update your billing information here: pay-verify-portal[.]online",
    "Your card on file has expired. Verify your payment details at bit.ly/upd-77 or your membership will be suspended.",
  ],
  "account-security-lure": [
    "Alert: someone from an unknown location signed into your Mailora account. If this was not you, cancel the session at mailora-login-secure.example",
    "Unusual sign-in activity detected on your profile. Secure your account now: account-verify-check[.]site",
    "A suspicious login attempt was blocked. Review this activity at security-alert-help.example/review to keep your account safe.",
  ],
};

const JOB_FEE = [
  "Hi, I'm Lena from Corvana Talent. You are shortlisted for the support analyst role. Pay a 1,500 BDT registration fee to confirm your interview.",
  "Congratulations, you have been hired as a remote assistant! Before onboarding, send the $60 training fee to our HR team.",
  "Our hiring team picked you for the warehouse position. A refundable security deposit of $120 is needed to lock your slot.",
];

const REMOTE_TASK = [
  "Remote typing work available: earn $35 per day. No experience needed. Message our coordinator on WhatsApp to begin.",
  "Data entry openings from home, 2,000 BDT daily. No prior experience required. Contact the team via Telegram today.",
  "Work from home doing product reviews for $250 weekly. No special skills needed, just text us on WhatsApp.",
];

// Required negatives plus near misses for each new rule. All must stay below 30.
const NEGATIVES = [
  "Your electricity bill of BDT 1,200 is due on the 10th. Pay in the official app.",
  "Your subscription payment failed. Update your payment method in your account settings at example-streaming.com/account.",
  "We detected a sign-in from a new device. If this was you, no action is needed.",
  "We are hiring a full-time developer. Apply on our careers page.",
  "Your OTP is 123456. Do not share it.",
  "Your parcel was delivered today.",
  // Near misses.
  "Planned maintenance: power supply in Block C will be switched off from 10 AM to 2 PM on Sunday.",
  "Your payment failed. Update your payment method within 7 days at streamly.example/account to keep watching.",
  "Unusual sign-in activity was detected. Review your recent activity in the Mailora app.",
  "Someone signed in to your account from Chrome on Windows. If this was you, you can ignore this email.",
  "We are hiring interns. There is no registration fee. Apply at careers.example/jobs",
  "Remote role for a senior engineer, salary $6,000 per month. Interviews via our careers portal.",
  "Visit help-center.example for answers to common questions.",
  "Your card ending in 1234 was declined at Grocer Mart. If this was you, try another card.",
];

describe("round 2: lookalike-lure-domain", () => {
  it("fires on 2+ hyphen-joined lure words, stronger on a risky TLD or defanged link", () => {
    expect(linkFlag("Go to secure-login-help.example now")).toMatchObject({ weight: W_LOOKALIKE_LURE_DOMAIN, evidence: "secure-login-help.example" });
    expect(linkFlag("Go to billing-update.xyz now").weight).toBe(W_LOOKALIKE_LURE_DOMAIN_STRONG);
    expect(linkFlag("Go to wallet-sync[.]example now").weight).toBe(W_LOOKALIKE_LURE_DOMAIN_STRONG);
    expect(linkFlag("https://parcel-track-check.test/a1").evidence).toBe("parcel-track-check.test");
  });
  it("does not fire on one lure word, unhyphenated names, subdomains or brand domains", () => {
    expect(linkFlag("See help-center.example")).toBeUndefined();
    expect(linkFlag("See securelogin.example")).toBeUndefined();
    expect(linkFlag("See pay-verify.galactibank.example")).toBeUndefined();
    expect(detectLinks("See pay-help.example", [{ name: "payhelp", domains: ["pay-help.example"] }]).flags).toEqual([]);
  });
  it("adds the round 2 endings to the risky TLD list", () => {
    for (const tld of ["support", "online", "click", "xyz", "info", "site", "top", "icu"]) {
      expect(ids(`see notice.${tld} for details`)).toContain("risky-tld");
    }
  });
});

describe("round 2: new families", () => {
  for (const [signal, texts] of Object.entries(PARAPHRASES)) {
    it.each(texts)(`${signal}: %s`, (text) => {
      const r = score(text);
      expect(r.redFlags.map((f) => f.id)).toContain(signal);
      expect(r.riskScore).toBeGreaterThanOrEqual(50);
    });
  }
  it("account-security-lure needs a suspicious link, not just any link", () => {
    expect(ids("Someone signed into your account. Cancel the session at mailora.example/security")).not.toContain(
      "account-security-lure",
    );
    expect(ids("Someone signed into your account. Cancel the session now.")).not.toContain("account-security-lure");
  });
  it("utility-disconnection-threat needs a link or a pay-now order", () => {
    expect(ids("Your power will be disconnected over an unpaid bill. Visit our office.")).not.toContain(
      "utility-disconnection-threat",
    );
  });
});

describe("round 2: job fee and remote task jobs", () => {
  it.each(JOB_FEE)("job fee reaches the 60 floor: %s", (text) => {
    const r = score(text);
    expect(r.redFlags.map((f) => f.id)).toContain("advance-fee-scheme");
    expect(r.riskScore).toBeGreaterThanOrEqual(FLOOR_JOB_FEE);
    expect(detectContent(text).jobFee).toBe(true);
  });
  it("a fee without a job context is not a job fee", () => {
    expect(detectContent("The conference registration fee is $40.").jobFee).toBe(false);
  });
  it("the job fee floor needs the advance-fee-scheme signal", () => {
    expect(blend(0, false, null, [], { jobFee: true })).toBe(0);
    expect(blend(25, false, null, ["advance-fee-scheme"], { jobFee: true })).toBe(FLOOR_JOB_FEE);
  });
  it.each(REMOTE_TASK)("remote task job: %s", (text) => {
    const r = score(text);
    expect(r.redFlags.map((f) => f.id)).toContain("task-job-scam");
    expect(r.riskScore).toBeGreaterThanOrEqual(50);
  });
});

describe("round 2: negatives stay below 30", () => {
  it.each(NEGATIVES)("%s", (text) => {
    expect(score(text).riskScore).toBeLessThan(30);
  });
});

describe("round 2: explanations", () => {
  it("every new signal has an explanation and the content ones a cursed-phrase reason", () => {
    for (const id of ["lookalike-lure-domain", "utility-disconnection-threat", "payment-failed-lure", "account-security-lure"]) {
      expect(EXPLANATION_TEMPLATES[id].length).toBeGreaterThan(0);
    }
    for (const id of ["utility-disconnection-threat", "payment-failed-lure", "account-security-lure"]) {
      expect(CURSED_PHRASE_REASONS[id].length).toBeGreaterThan(0);
    }
  });
});
