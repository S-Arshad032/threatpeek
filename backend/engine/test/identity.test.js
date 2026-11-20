import { describe, it, expect } from "vitest";
import { detectIdentity } from "../src/detectors/identity.js";
import { DEFAULT_BRANDS } from "../src/brands.js";
import { EXPLANATION_TEMPLATES } from "../src/config.js";

const ids = (input) => detectIdentity(input, DEFAULT_BRANDS).flags.map((f) => f.id);

describe("detectIdentity: typosquatting", () => {
  it("fires on a look-alike spelling", () => {
    expect(ids("https://galact1bank.example/login")).toContain("typosquatting");
  });
  it("fires on the exact brand label on a wrong domain", () => {
    expect(ids("http://galactibank.xyz")).toContain("typosquatting");
  });
  it("fires when the brand name is inside the label", () => {
    expect(ids("https://galactibank-verify.example")).toContain("typosquatting");
  });
  it("does not fire on the legitimate domain or its subdomains", () => {
    expect(ids("https://login.galactibank.example")).toEqual([]);
    expect(ids("visit galactibank.example")).toEqual([]);
  });
  it("uses the first matching hostname as evidence", () => {
    const [flag] = detectIdentity("see vau1tpay.example and galact1bank.example", DEFAULT_BRANDS).flags;
    expect(flag.evidence).toBe("vau1tpay.example");
  });
});

describe("detectIdentity: homograph-punycode", () => {
  it("fires on a Cyrillic look-alike letter", () => {
    expect(ids("visit gаlactibank.example")).toContain("homograph-punycode");
  });
  it("does not fire on a pure Bangla hostname", () => {
    expect(ids("visit গালাক্তিব্যাংক.example")).not.toContain("homograph-punycode");
  });
  it("fires on punycode", () => {
    expect(ids("visit xn--galctibnk-r8a.example")).toContain("homograph-punycode");
  });
});

describe("detectIdentity: display-name-mismatch", () => {
  it("fires when the display name claims a brand the domain does not belong to", () => {
    expect(ids("From: Galactibank Support <noreply@phish.invalid>")).toEqual(["display-name-mismatch"]);
  });
  it("supports quoted display names", () => {
    expect(ids('From: "Galactibank" <alerts@phish.invalid>')).toEqual(["display-name-mismatch"]);
  });
  it("does not fire when the brand sends from its own domain", () => {
    expect(ids("From: Galactibank Support <noreply@mail.galactibank.example>")).toEqual([]);
  });
});

describe("detectIdentity: explanations", () => {
  const inputs = [
    "https://galact1bank.example/login",
    "visit gаlactibank.example",
    "visit xn--galctibnk-r8a.example",
    "From: Galactibank Support <noreply@phish.invalid>",
  ];
  it("every flag has a non-empty explanation built from its template", () => {
    for (const input of inputs) {
      const { flags, cursedPhrases } = detectIdentity(input, DEFAULT_BRANDS);
      expect(flags.length).toBeGreaterThan(0);
      expect(cursedPhrases).toEqual([]);
      for (const f of flags) {
        expect(f.explanation.length).toBeGreaterThan(0);
        expect(f.explanation).toBe(EXPLANATION_TEMPLATES[f.id].replace("{e}", f.evidence));
      }
    }
  });
});
