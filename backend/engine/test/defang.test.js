import { describe, it, expect } from "vitest";
import { normalize, refang } from "../src/util/normalize.js";
import { findLinks } from "../src/util/links.js";
import { detectLinks } from "../src/detectors/link.js";
import { detectIdentity } from "../src/detectors/identity.js";
import { DEFAULT_BRANDS } from "../src/brands.js";
import { score } from "../src/index.js";

// Fixtures use fictional brands and reserved TLDs (.example, .test, .invalid) or risky TLDs only.
const linkIds = (s) => detectLinks(s).flags.map((f) => f.id);

describe("refang", () => {
  it("turns bracketed and spelled-out dots into real dots", () => {
    expect(refang("docs-share-view[.]example/role")).toBe("docs-share-view.example/role");
    expect(refang("evil(.)xyz and evil{.}top")).toBe("evil.xyz and evil.top");
    expect(refang("evil[dot]xyz, evil(dot)tk, evil[ . ]ml")).toBe("evil.xyz, evil.tk, evil.ml");
    expect(refang("Go to evil dot xyz now")).toBe("Go to evil.xyz now");
  });
  it("turns hxxp(s) and [:] back into a scheme", () => {
    expect(refang("hxxps://evil.xyz")).toBe("https://evil.xyz");
    expect(refang("HXXP://evil.xyz")).toBe("HTTP://evil.xyz");
    expect(refang("hxxps[:]//evil[.]xyz")).toBe("https://evil.xyz");
  });
  it("leaves ordinary prose alone", () => {
    for (const s of [
      "connect the dot to it",
      "The dot com bubble burst",
      "a dot com startup",
      "Polka dot dress",
      "Item list (a) and [b]",
    ]) {
      expect(refang(s)).toBe(s);
    }
  });
});

describe("normalize sees refanged links and still maps back", () => {
  it("normalized text has a real link, evidence quotes the original", () => {
    const n = normalize("Open EVIL[.]XYZ/pay");
    expect(n.text).toBe("open evil.xyz/pay");
    const start = n.text.indexOf("evil.xyz");
    expect(n.input.slice(...n.toOriginal(start, start + "evil.xyz".length))).toBe("EVIL[.]XYZ");
  });
  it("hxxp keeps its length and case in the cased text", () => {
    const n = normalize("hXXps://a.test");
    expect(n.text).toBe("https://a.test");
    expect(n.cased).toBe("hTTps://a.test");
  });
});

describe("link and identity detectors see defanged links", () => {
  it("risky-tld fires on a defanged risky ending", () => {
    expect(linkIds("Pay at fine-pay[.]xyz today")).toEqual(["risky-tld", "defanged-link"]);
    expect(linkIds("hxxp://198[.]51[.]100[.]7/login")).toContain("raw-ip-url");
  });
  it("typosquatting fires on a defanged look-alike", () => {
    const flags = detectIdentity("Log in at galact1bank[.]example", DEFAULT_BRANDS).flags;
    expect(flags.map((f) => f.id)).toEqual(["typosquatting"]);
    expect(flags[0].evidence).toBe("galact1bank.example");
  });
  it("defanged-link quotes the whole disguised token", () => {
    const flag = detectLinks("brief: docs-share-view[.]example/role-402.").flags[0];
    expect(flag.id).toBe("defanged-link");
    expect(flag.evidence).toBe("docs-share-view[.]example/role-402.");
    expect(flag.weight).toBe(10);
  });
  it("defanged-link alone stays low", () => {
    expect(score("See notes at wiki[.]example").riskScore).toBeLessThan(30);
  });
});

describe("findLinks", () => {
  it("finds scheme, www and bare links, marks shorteners", () => {
    expect(findLinks("Track: bit.ly/track-pkg-1").map((l) => [l.host, l.shortener])).toEqual([["bit.ly", true]]);
    expect(findLinks("see https://a.example/x and www.b.test").map((l) => l.host)).toEqual(["a.example", "b.test"]);
    expect(findLinks("open evil dot xyz").map((l) => l.host)).toEqual(["evil.xyz"]);
  });
  it("does not treat abbreviations as links", () => {
    expect(findLinks("e.g. Mr.Smith, i.e. no link")).toEqual([]);
  });
});
