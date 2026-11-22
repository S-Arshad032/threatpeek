import { describe, it, expect } from "vitest";
import { normalize } from "../src/util/normalize.js";
import { detectContent } from "../src/detectors/content.js";
import { score } from "../src/index.js";

// Fixtures use fictional brands and reserved TLDs (.example, .test, .invalid) only.
const text = (s) => normalize(s).text;
const ids = (s) => detectContent(s).flags.map((f) => f.id);

describe("normalize: text", () => {
  it("lowercases and applies NFKC", () => {
    expect(text("ACT NOW")).toBe("act now");
    expect(text("ｐａｙ ｉｎ ｂｉｔｃｏｉｎ")).toBe("pay in bitcoin");
    expect(text("ﬁle")).toBe("file");
  });

  it("strips zero-width and control characters", () => {
    expect(text("pass​word")).toBe("password");
    expect(text("act­now﻿")).toBe("actnow");
    expect(text("a\u0007b")).toBe("ab");
  });

  it("collapses whitespace and keeps line breaks as sentence boundaries", () => {
    expect(text("act   \t now")).toBe("act now");
    expect(text("hello \r\n\n world")).toBe("hello\nworld");
  });

  it("maps leetspeak only inside tokens that contain letters", () => {
    expect(text("p@ssw0rd")).toBe("password");
    expect(text("b1tc0in")).toBe("bitcoin");
    expect(text("pa$$w0rd")).toBe("password");
    expect(text("v3rify")).toBe("verify");
    expect(text("s3nd acc0unt")).toBe("send account");
  });

  it("never changes plain numbers, amounts, number+unit or code tokens", () => {
    expect(text("1000000")).toBe("1000000");
    expect(text("$100 and $1 million")).toBe("$100 and $1 million");
    expect(text("$1million")).toBe("$1million");
    expect(text("us$5")).toBe("us$5");
    expect(text("at 10am on the 2nd")).toBe("at 10am on the 2nd");
    expect(text("mp3 room101")).toBe("mp3 room101");
    // Number-first tokens are left alone, so "5end" is a known miss.
    expect(text("5end")).toBe("5end");
  });

  it("collapses 4+ spaced-out single letters", () => {
    expect(text("p a s s w o r d")).toBe("password");
    expect(text("send your P I N S now")).toBe("send your pins now");
    expect(text("a b c")).toBe("a b c"); // only three letters
    expect(text("I am a big cat")).toBe("i am a big cat");
  });

  it("maps every normalized span back to the original text", () => {
    const input = "Enter  your p@ss​w0rd, P L E A S E";
    const n = normalize(input);
    const at = n.text.indexOf("password");
    const [s, e] = n.toOriginal(at, at + "password".length);
    expect(input.slice(s, e)).toBe("p@ss​w0rd");
    const p = n.text.indexOf("please");
    const [ps, pe] = n.toOriginal(p, p + "please".length);
    expect(input.slice(ps, pe)).toBe("P L E A S E");
  });

  it("keeps the case-preserving text aligned with the lowercased text", () => {
    const n = normalize("Send   the PIN​ now");
    expect(n.cased).toBe("Send the PIN now");
    expect(n.cased.length).toBe(n.text.length);
  });
});

describe("normalize: content detector", () => {
  it("catches obfuscated phrases and quotes the original text", () => {
    const { flags, cursedPhrases } = detectContent("Please enter your p@ssw0rd. You won the L O T T E R Y");
    expect(flags.map((f) => f.id)).toEqual(["credential-request", "prize-lottery"]);
    expect(cursedPhrases.map((p) => p.text)).toEqual(["p@ssw0rd", "L O T T E R Y"]);
  });

  it("sees through zero-width characters and fullwidth letters", () => {
    expect(ids("Pay with b​itcoin today")).toEqual(["unusual-payment-method"]);
    expect(ids("ＹＯＵ ＨＡＶＥ ＷＯＮ")).toEqual(["prize-lottery"]);
  });

  it("keeps PIN/OTP case-sensitive", () => {
    expect(ids("please pin this post")).toEqual([]);
    expect(ids("Reply with your PIN")).toContain("credential-request");
  });

  it("cursed phrases are always substrings of the original input", () => {
    const input = "C​ongratulations!! You w0n $1 million. Send the f​ee in B1TCOIN.";
    for (const p of score(input).cursedPhrases) expect(input).toContain(p.text);
  });
});
