import { describe, it, expect } from "vitest";
import { score } from "../src/index.js";
import { SIGNAL_CATEGORY, CATEGORY_CONTENT } from "../src/config.js";

// Fixtures use fictional brands and reserved TLDs (.example, .test, .invalid) only.
const PHRASE_SIGNALS = new Set([
  "urgency-en",
  "credential-request",
  "prize-lottery",
  "advance-fee-scheme",
  "financial-info-request",
  "unusual-payment-method",
  "secrecy-pressure",
]);

const GOLDEN = [
  {
    name: "1. clean message",
    input: "Hi, lunch at 1pm tomorrow? Let me know.",
    flags: [],
    riskScore: 0,
    verdict: "pookie",
  },
  {
    name: "2. risky-tld + credential-request (no floor)",
    input: "Check your balance at http://bad.xyz/portal and enter your password.",
    flags: ["risky-tld", "credential-request"],
    riskScore: 35,
    verdict: "skeptical",
  },
  {
    name: "3. typosquatting + credential-request (floor 4.5)",
    input: "Your Galactibank account: log in at https://galact1bank.example/login to continue.",
    flags: ["typosquatting", "credential-request"],
    riskScore: 70,
    verdict: "poltergeist",
  },
  {
    name: "4. raw IP + credential-request (floor 4.6)",
    input: "Enter your OTP at http://203.0.113.5/verify",
    flags: ["raw-ip-url", "credential-request"],
    riskScore: 70,
    verdict: "poltergeist",
  },
  {
    name: "5. SPF fail + display-name mismatch (floor 4.7)",
    input:
      "From: Galactibank Support <noreply@mail-alerts.invalid>\n" +
      "Authentication-Results: mx.example.test; spf=fail smtp.mailfrom=mail-alerts.invalid\n" +
      "\n" +
      "Please review your statement.",
    flags: ["display-name-mismatch", "spf-fail"],
    riskScore: 60,
    verdict: "skeptical",
  },
  {
    name: "6. L2 blacklist hit (rule 4.1)",
    input: "Meeting notes attached for review.",
    options: { l2Hit: true },
    flags: [],
    riskScore: 90,
    verdict: "poltergeist",
  },
  {
    name: "7. L3 score supplied (rule 4.2)",
    input: "Please send your password.",
    options: { l3Score: 80 },
    flags: ["credential-request"],
    riskScore: 47, // round(0.55 * 20 + 0.45 * 80)
    verdict: "skeptical",
    confidence: "full",
  },
  {
    name: "8. urgency + credential-request (floor 4.8)",
    input: "Act now: please confirm your password.",
    flags: ["urgency-en", "credential-request"],
    riskScore: 55,
    verdict: "skeptical",
  },
  {
    name: "9. suspicious attachment only (floor 4.9)",
    input: "Please open invoice.exe to see your order.",
    flags: ["suspicious-attachment"],
    riskScore: 40,
    verdict: "skeptical",
  },
  {
    name: "10. link-text mismatch only",
    input: 'Click <a href="http://phish.invalid/offer">http://galactibank.example</a> to see it.',
    flags: ["link-text-mismatch"],
    riskScore: 35,
    verdict: "skeptical",
  },
  {
    name: "11. prize + card-details request (floor 4.10)",
    input: "Congratulations! You have won $1 million. Enter your credit card details to get that money.",
    flags: ["prize-lottery", "financial-info-request"],
    riskScore: 70, // L1 45 (55 capped), then the 4.10 floor
    verdict: "poltergeist",
  },
  {
    name: "12. gift-card scam (floor 4.12)",
    input:
      "Hi, it's your manager. I need a quick favour: buy four Google Play gift cards of $100 each and " +
      "send me the codes within the hour. Do not tell anyone, it's a surprise for the team.",
    flags: ["unusual-payment-method", "secrecy-pressure"],
    riskScore: 40, // L1 30, then the 4.12 floor
    verdict: "skeptical",
  },
  {
    name: "13. inheritance / advance-fee scam (floor 4.10)",
    input:
      "Dear friend, I am the lawyer of the late Mr Ostrander Vell, who left an inheritance with no heir. " +
      "You are named as the beneficiary for the transfer of $4.5 million. To release the funds, pay the " +
      "$300 clearance fee by wire transfer. Keep this confidential.",
    flags: ["prize-lottery", "advance-fee-scheme", "unusual-payment-method", "secrecy-pressure"],
    riskScore: 70, // L1 45 (80 capped), then the 4.10 floor
    verdict: "poltergeist",
  },
];

describe("golden tests", () => {
  it.each(GOLDEN)("$name", (g) => {
    const result = score(g.input, g.options);
    const ids = result.redFlags.map((f) => f.id);

    expect(new Set(ids)).toEqual(new Set(g.flags));
    expect(ids).toHaveLength(g.flags.length);
    expect(result.riskScore).toBe(g.riskScore);
    expect(result.verdict).toBe(g.verdict);
    expect(result.confidence).toBe(g.confidence ?? "limited");

    const phraseSignalFired = ids.some((id) => PHRASE_SIGNALS.has(id));
    expect(result.cursedPhrases.length > 0).toBe(phraseSignalFired);
    // Every phrase-producing signal is a content signal.
    for (const id of PHRASE_SIGNALS) expect(SIGNAL_CATEGORY[id]).toBe(CATEGORY_CONTENT);
  });
});

const flagIds = (input, options) => score(input, options).redFlags.map((f) => f.id);

describe("edge cases (design: Testing Strategy)", () => {
  it("Node.js is not an attachment", () => {
    expect(flagIds("I work with Node.js daily")).not.toContain("suspicious-attachment");
  });
  it("a pure Cyrillic hostname is not a homograph", () => {
    expect(flagIds("visit галактибанк.example")).not.toContain("homograph-punycode");
  });
  it("risky-tld accepts a trailing slash but needs the TLD to be last", () => {
    expect(flagIds("http://bad.xyz/login")).toContain("risky-tld");
    expect(flagIds("bad.xyz.example")).not.toContain("risky-tld");
  });
  it("raw-ip-url terminators and validation", () => {
    expect(flagIds("http://203.0.113.5 click here")).toContain("raw-ip-url");
    expect(flagIds("http://1.2.3.4.evil.example")).not.toContain("raw-ip-url");
    expect(flagIds("http://999.1.1.1/")).not.toContain("raw-ip-url");
    expect(flagIds("http://[2001:db8::1]/")).toContain("raw-ip-url");
  });
  it("homograph-punycode on punycode and Cyrillic look-alikes", () => {
    expect(flagIds("visit xn--galctibnk-r8a.example")).toContain("homograph-punycode");
    expect(flagIds("visit gаlactibank.example")).toContain("homograph-punycode");
  });
  it("typosquatting variants", () => {
    expect(flagIds("https://galact1bank.example/login")).toContain("typosquatting");
    expect(flagIds("http://galactibank.xyz")).toContain("typosquatting");
    expect(flagIds("https://galactibank-verify.example")).toContain("typosquatting");
  });
  it("the legitimate domain and its subdomains produce no flags", () => {
    expect(flagIds("visit galactibank.example")).toEqual([]);
    expect(flagIds("https://login.galactibank.example")).toEqual([]);
  });
  it("display-name-mismatch", () => {
    expect(flagIds("From: Galactibank Support <noreply@phish.invalid>")).toContain("display-name-mismatch");
  });
  it("auth headers: folded dkim, DKIM-Signature alone, Received-SPF softfail", () => {
    expect(flagIds("Authentication-Results: mx.example.test;\n dkim=fail header.d=phish.invalid")).toContain(
      "dkim-fail",
    );
    expect(flagIds("DKIM-Signature: v=1; a=rsa-sha256; d=phish.invalid; b=abc")).toEqual([]);
    expect(flagIds("Received-SPF: softfail (mx.example.test)")).toContain("spf-fail");
  });
  it("several urgency phrases give one flag (weight once) but several cursed phrases", () => {
    const result = score("Act now! Limited time offer. This expires today.");
    expect(result.redFlags.map((f) => f.id)).toEqual(["urgency-en"]);
    expect(result.riskScore).toBe(15);
    expect(result.cursedPhrases.length).toBe(3);
  });
  it("lowercase pin is not a credential request", () => {
    expect(flagIds("please pin this post")).not.toContain("credential-request");
  });
  it("input validation", () => {
    expect(() => score(123)).toThrow(TypeError);
    expect(() => score("x".repeat(4001))).toThrow(RangeError);
    expect(() => score("hi", { l3Score: 1.5 })).toThrow(RangeError);
    expect(() => score("hi", null)).not.toThrow();
  });
  it("l3Score boundaries and verdict boundaries", () => {
    expect(score("hi", { l3Score: 0 }).riskScore).toBe(0);
    expect(score("hi", { l3Score: 100 }).riskScore).toBe(45);
    expect(score("hi", { l3Score: 67 })).toMatchObject({ riskScore: 30, verdict: "pookie" });
    expect(score("hi", { l3Score: 69 })).toMatchObject({ riskScore: 31, verdict: "skeptical" });
    expect(score("Act now: http://203.0.113.5/x", { l3Score: 92 })).toMatchObject({
      riskScore: 69,
      verdict: "skeptical",
    });
    expect(score("Act now: http://203.0.113.5/x", { l3Score: 94 })).toMatchObject({
      riskScore: 70,
      verdict: "poltergeist",
    });
  });
  it("brand replacement", () => {
    const brands = [{ name: "zorbbank", domains: ["zorbbank.example"] }];
    expect(flagIds("http://zorbbank.example/x", { brands })).not.toContain("typosquatting");
    expect(flagIds("http://z0rbbank.example/x", { brands })).toContain("typosquatting");
  });
});
