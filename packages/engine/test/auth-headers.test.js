import { describe, it, expect } from "vitest";
import { detectAuthHeaders } from "../src/detectors/auth-headers.js";
import { EXPLANATION_TEMPLATES } from "../src/config.js";

const ids = (input) => detectAuthHeaders(input).flags.map((f) => f.id);

describe("detectAuthHeaders", () => {
  it("fires spf-fail from Authentication-Results", () => {
    const { flags } = detectAuthHeaders("Authentication-Results: mx.example.test; spf=fail smtp.mailfrom=a.invalid");
    expect(flags.map((f) => f.id)).toEqual(["spf-fail"]);
    expect(flags[0].evidence).toBe("spf=fail");
  });

  it("fires dkim-fail when it is on a folded second line", () => {
    const input = "Authentication-Results: mx.example.test;\r\n\tdkim=fail header.d=phish.invalid\r\n\r\nBody";
    expect(ids(input)).toEqual(["dkim-fail"]);
  });

  it("never fires on a DKIM-Signature header alone", () => {
    expect(ids("DKIM-Signature: v=1; a=rsa-sha256; d=phish.invalid; dkim=fail; b=abc")).toEqual([]);
  });

  it("fires spf-fail from Received-SPF: softfail", () => {
    expect(ids("Received-SPF: softfail (mx.example.test: domain does not designate sender)")).toEqual(["spf-fail"]);
  });

  it("fires dmarc-fail on permerror", () => {
    expect(ids("Authentication-Results: mx.example.test; dmarc=permerror")).toEqual(["dmarc-fail"]);
  });

  it("emits each signal once, in a fixed order", () => {
    const input = [
      "Authentication-Results: a.example.test; dmarc=fail; dkim=fail; spf=softfail",
      "Authentication-Results: b.example.test; spf=fail",
    ].join("\n");
    expect(ids(input)).toEqual(["spf-fail", "dkim-fail", "dmarc-fail"]);
  });

  it("does not fire on passing results or outside result headers", () => {
    expect(ids("Authentication-Results: mx.example.test; spf=pass dkim=pass dmarc=pass")).toEqual([]);
    expect(ids("The report said spf=fail yesterday.")).toEqual([]);
  });

  it("every flag has a non-empty explanation built from its template", () => {
    const { flags, cursedPhrases } = detectAuthHeaders(
      "Authentication-Results: mx.example.test; spf=fail; dkim=fail; dmarc=fail",
    );
    expect(flags).toHaveLength(3);
    expect(cursedPhrases).toEqual([]);
    for (const f of flags) {
      expect(f.explanation.length).toBeGreaterThan(0);
      expect(f.explanation).toBe(EXPLANATION_TEMPLATES[f.id].replace("{e}", f.evidence));
    }
  });
});
