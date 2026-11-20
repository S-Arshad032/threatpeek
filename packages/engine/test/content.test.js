import { describe, it, expect } from "vitest";
import { detectContent } from "../src/detectors/content.js";
import { EXPLANATION_TEMPLATES, URGENCY_EN_PHRASES, URGENCY_BN_PHRASES, MAX_CURSED_PHRASES } from "../src/config.js";

const ids = (input) => detectContent(input).flags.map((f) => f.id);

describe("detectContent: urgency", () => {
  it("emits one urgency-en flag but a cursed phrase per distinct phrase", () => {
    const { flags, cursedPhrases } = detectContent(
      "Act now! Your account will be suspended. Verify immediately or lose access.",
    );
    expect(flags.map((f) => f.id)).toEqual(["urgency-en"]);
    expect(flags[0].evidence).toBe("Act now");
    expect(cursedPhrases.map((p) => p.text)).toEqual(["Act now", "account will be suspended", "Verify immediately"]);
  });

  it("matches every configured English phrase, across flexible whitespace", () => {
    for (const phrase of URGENCY_EN_PHRASES) {
      expect(ids(`Notice: ${phrase.toUpperCase().replace(/ /g, "  ")}!`)).toEqual(["urgency-en"]);
    }
  });

  it("matches every configured Bangla phrase", () => {
    for (const phrase of URGENCY_BN_PHRASES) {
      expect(ids(`বার্তা: ${phrase}।`)).toEqual(["urgency-bn"]);
    }
  });

  it("matches Bangla phrases whatever the nukta encoding", () => {
    const precomposed = "এখনই সাড়া দিন".normalize("NFC").replace("ড়", "ড়");
    expect(ids(precomposed)).toEqual(["urgency-bn"]);
    expect(ids("এখনই সাড়া দিন".normalize("NFD"))).toEqual(["urgency-bn"]);
  });
});

describe("detectContent: credential-request", () => {
  it("fires on password, login and uppercase OTP/PIN", () => {
    expect(ids("enter your password")).toEqual(["credential-request"]);
    expect(ids("please log in")).toEqual(["credential-request"]);
    expect(ids("Send the OTP")).toEqual(["credential-request"]);
    expect(ids("Your PIN please")).toEqual(["credential-request"]);
    expect(ids("আপনার ওটিপি দিন")).toEqual(["credential-request"]);
  });
  it("does not fire on the ordinary word pin", () => {
    expect(ids("please pin this post")).toEqual([]);
  });
  it("uses the earliest match as evidence", () => {
    const { flags } = detectContent("Reply with your OTP and password");
    expect(flags[0].evidence).toBe("OTP");
  });
});

describe("detectContent: suspicious-attachment", () => {
  it("fires on a dangerous file name", () => {
    const { flags, cursedPhrases } = detectContent("Please open invoice.exe to see your order.");
    expect(flags.map((f) => f.id)).toEqual(["suspicious-attachment"]);
    expect(flags[0].evidence).toBe("invoice.exe");
    expect(cursedPhrases).toEqual([]);
  });
  it("skips allowlisted JS library names", () => {
    expect(ids("I work with Node.js daily")).toEqual([]);
    expect(ids("I use React.js and Vue.js")).toEqual([]);
  });
  it("does not fire on a hostname or URL path", () => {
    expect(ids("blog.bat.example")).toEqual([]);
    expect(ids("load https://cdn.example/app.js now")).toEqual([]);
  });
});

describe("detectContent: cursed phrases", () => {
  it("de-duplicates by lowercase text and caps the list", () => {
    const { cursedPhrases } = detectContent("password PASSWORD Password");
    expect(cursedPhrases).toHaveLength(1);
    const many = Array.from({ length: 30 }, (_, i) => `act${"  ".repeat(i % 5)} now${" ".repeat(i)}`).join(". ");
    expect(detectContent(many).cursedPhrases.length).toBeLessThanOrEqual(MAX_CURSED_PHRASES);
  });

  it("returns an empty list when no phrase signal fires", () => {
    expect(detectContent("Hi, lunch at 1pm tomorrow?").cursedPhrases).toEqual([]);
  });
});

describe("detectContent: explanations and reasons", () => {
  const inputs = [
    "Act now or lose access",
    `${URGENCY_BN_PHRASES[0]} OTP পাঠান।`,
    "Please send your password.",
    "Please open invoice.exe to see your order.",
  ];
  it("every flag has a non-empty explanation and every cursed phrase a non-empty reason", () => {
    for (const input of inputs) {
      const { flags, cursedPhrases } = detectContent(input);
      expect(flags.length).toBeGreaterThan(0);
      for (const f of flags) {
        expect(f.explanation.length).toBeGreaterThan(0);
        expect(f.explanation).toBe(EXPLANATION_TEMPLATES[f.id].replace("{e}", f.evidence));
      }
      for (const p of cursedPhrases) {
        expect(p.text.length).toBeGreaterThan(0);
        expect(p.reason.trim().length).toBeGreaterThan(0);
        expect(input).toContain(p.text);
      }
    }
  });
});
