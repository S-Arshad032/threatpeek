import { describe, it, expect } from "vitest";
import {
  extractAsciiHostnames,
  extractUnicodeHostnames,
  registrableLabel,
  registrableDomain,
  isLegitimate,
} from "../src/util/hostname.js";
import { MAX_HOSTNAMES_SCANNED } from "../src/config.js";

describe("extractAsciiHostnames", () => {
  it("extracts hostnames from URLs, emails and plain text", () => {
    expect(extractAsciiHostnames("go to https://Login.Galactibank.example/path?x=1")).toEqual([
      "login.galactibank.example",
    ]);
    expect(extractAsciiHostnames("mail user.name@host.example now")).toEqual(["host.example"]);
    expect(extractAsciiHostnames("see a.example, b.test.")).toEqual(["a.example", "b.test"]);
  });

  it("de-duplicates and caps the number of hostnames", () => {
    expect(extractAsciiHostnames("x.example x.example X.EXAMPLE")).toEqual(["x.example"]);
    const many = Array.from({ length: 80 }, (_, i) => `h${i}.example`).join(" ");
    expect(extractAsciiHostnames(many)).toHaveLength(MAX_HOSTNAMES_SCANNED);
  });

  it("does not extract the ASCII tail of a mixed-script hostname", () => {
    // Cyrillic U+0430 in place of the first "a"
    expect(extractAsciiHostnames("visit gаlactibank.example")).toEqual([]);
  });

  it("returns the same result on repeated calls (no shared regex state)", () => {
    const text = "a.example b.example";
    expect(extractAsciiHostnames(text)).toEqual(extractAsciiHostnames(text));
  });
});

describe("extractUnicodeHostnames", () => {
  it("extracts mixed-script and Bangla hostnames", () => {
    expect(extractUnicodeHostnames("visit gаlactibank.example")).toEqual(["gаlactibank.example"]);
    expect(extractUnicodeHostnames("visit গালাক্তিব্যাংক.example")).toEqual(["গালাক্তিব্যাংক.example"]);
  });
});

describe("registrable helpers", () => {
  it("finds the registrable label and domain", () => {
    expect(registrableLabel("login.galactibank.example")).toBe("galactibank");
    expect(registrableLabel("shop.example.com.bd")).toBe("example");
    expect(registrableDomain("shop.example.com.bd")).toBe("example.com.bd");
    expect(registrableDomain("www.phish.invalid")).toBe("phish.invalid");
    expect(registrableLabel("localhost")).toBe("localhost");
  });

  it("checks legitimacy against brand domains, including subdomains", () => {
    const brand = { name: "galactibank", domains: ["galactibank.example"] };
    expect(isLegitimate("galactibank.example", brand)).toBe(true);
    expect(isLegitimate("login.galactibank.example", brand)).toBe(true);
    expect(isLegitimate("evilgalactibank.example", brand)).toBe(false);
    expect(isLegitimate("galactibank.example.invalid", brand)).toBe(false);
  });
});
