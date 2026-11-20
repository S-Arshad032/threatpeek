import { describe, it, expect } from "vitest";
import { detectLinks } from "../src/detectors/link.js";
import { EXPLANATION_TEMPLATES } from "../src/config.js";

const ids = (input) => detectLinks(input).flags.map((f) => f.id);

describe("detectLinks: raw-ip-url", () => {
  it("fires on an IPv4 URL followed by a space", () => {
    expect(ids("http://203.0.113.5 click here")).toEqual(["raw-ip-url"]);
  });
  it("fires on an IPv4 URL with a path, port or sentence dot", () => {
    expect(ids("go http://203.0.113.5/verify")).toEqual(["raw-ip-url"]);
    expect(ids("go http://203.0.113.5:8080/x")).toEqual(["raw-ip-url"]);
    expect(ids("go to http://203.0.113.5.")).toEqual(["raw-ip-url"]);
  });
  it("does not fire when the IP is the start of a hostname", () => {
    expect(ids("http://1.2.3.4.evil.example")).not.toContain("raw-ip-url");
  });
  it("does not fire on an invalid octet", () => {
    expect(ids("http://999.1.1.1/")).not.toContain("raw-ip-url");
  });
  it("fires on a bracketed IPv6 URL", () => {
    expect(ids("http://[2001:db8::1]/")).toEqual(["raw-ip-url"]);
  });
  it("does not fire on malformed IPv6", () => {
    expect(ids("http://[2001::db8::1]/")).toEqual([]);
    expect(ids("http://[12345::1]/")).toEqual([]);
  });
});

describe("detectLinks: risky-tld", () => {
  it("fires when the TLD is followed by a path", () => {
    expect(ids("http://bad.xyz/login")).toEqual(["risky-tld"]);
  });
  it("does not fire when the risky label is not the last one", () => {
    expect(ids("bad.xyz.example")).toEqual([]);
  });
  it("fires at the end of a sentence and records the hostname", () => {
    const { flags } = detectLinks("Visit promo.top.");
    expect(flags.map((f) => f.evidence)).toEqual(["promo.top"]);
  });
});

describe("detectLinks: link-text-mismatch", () => {
  it("fires on an HTML anchor whose text and href differ", () => {
    expect(ids('<a href="http://phish.invalid/offer">http://galactibank.example</a>')).toEqual([
      "link-text-mismatch",
    ]);
  });
  it("fires on a Markdown link whose text and href differ", () => {
    expect(ids("[galactibank.example](https://phish.invalid/login)")).toEqual(["link-text-mismatch"]);
  });
  it("does not fire when the text is a subdomain of the same site", () => {
    expect(ids('<a href="https://galactibank.example/a">www.login.galactibank.example</a>')).toEqual([]);
  });
  it("does not fire when the visible text is not a URL", () => {
    expect(ids('<a href="https://phish.invalid/">Click here</a>')).toEqual([]);
  });
});

describe("detectLinks: explanations", () => {
  const inputs = [
    "http://203.0.113.5 click here",
    "http://bad.xyz/login",
    '<a href="http://phish.invalid/offer">http://galactibank.example</a>',
  ];
  it("every flag has a non-empty explanation built from its template", () => {
    for (const input of inputs) {
      const { flags, cursedPhrases } = detectLinks(input);
      expect(flags.length).toBeGreaterThan(0);
      expect(cursedPhrases).toEqual([]);
      for (const f of flags) {
        expect(f.explanation.length).toBeGreaterThan(0);
        expect(f.explanation).toBe(EXPLANATION_TEMPLATES[f.id].replace("{e}", f.evidence));
      }
    }
  });
});
