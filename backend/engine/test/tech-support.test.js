import { describe, it, expect } from "vitest";
import { score } from "../src/index.js";
import { loadSet } from "../benchmark/lib.js";
import { FLOOR_TECH_SUPPORT } from "../src/config.js";

// tech-support-scam (floor 4.28) and the named-tool path of remote-access-request. Every scam
// message is written for this file: fictional names, no wording from any benchmark set.
const ids = (input) => score(input).redFlags.map((f) => f.id);

describe("tech-support-scam", () => {
  it.each([
    // with a phone number, no link
    "SYSTEM WARNING: 3 viruses were found on this laptop and your saved card passwords are at risk. Call the Orbitins certified helpdesk at +1 555 0182 now.",
    // with a phone number and an error code
    "Nexamail Security: Error 0x80070bad. Spyware detected on your phone. Contact our technical team on 0800 555 0133 before you restart.",
    // no phone number: install a named remote tool
    "Your computer has been infected with ransomware. Please download TeamViewer and send us the ID so our engineer can clean it for free.",
    // no phone number, a link, and a remote session
    "Malware alert for your Galactibank login! To stop the attack, open a remote session with our agent at help.galactibank-fix.example/start",
  ])("scores at least 60: %s", (text) => {
    expect(ids(text)).toContain("tech-support-scam");
    expect(score(text).riskScore).toBeGreaterThanOrEqual(FLOOR_TECH_SUPPORT);
  });

  it.each([
    "Your antivirus scan completed. No threats found.",
    "Microsoft Defender updated its virus definitions.",
    "We detected a sign-in from a new device. If this was you, ignore this message.",
    "Security tip: never install remote access software for strangers who call you.",
    "Our support team is available at 16221 for any questions.",
    "If you think your account is at risk, contact our support team at 16221.",
  ])("legitimate notice stays below 30: %s", (text) => {
    expect(ids(text)).not.toContain("tech-support-scam");
    expect(score(text).riskScore).toBeLessThan(30);
  });

  it("needs both the scare and the hook", () => {
    expect(ids("Warning: 4 viruses found on your device.")).not.toContain("tech-support-scam"); // no hook
    expect(ids("Call our support desk to upgrade your plan.")).not.toContain("tech-support-scam"); // no scare
  });

  it("now scores the two known fake virus alerts (dev-s19, h4-s08) at 50 or more", () => {
    const known = [...loadSet("dev"), ...loadSet("heldout4")].filter((m) => ["dev-s19", "h4-s08"].includes(m.id));
    expect(known).toHaveLength(2);
    for (const m of known) {
      expect(ids(m.text)).toContain("tech-support-scam");
      expect(score(m.text).riskScore).toBeGreaterThanOrEqual(50);
    }
  });
});

describe("remote-access-request with a named tool", () => {
  it("fires when a remote-control tool is named with an install/open/allow instruction", () => {
    for (const text of [
      "Install AnyDesk so we can fix it",
      "Please open TeamViewer and read me the ID",
      "Allow UltraViewer when the prompt appears",
      "Download Quick Assist from the store",
    ]) {
      expect(ids(text)).toContain("remote-access-request");
    }
  });

  it("does not fire on a mention or a warning", () => {
    expect(ids("We use TeamViewer in the office")).not.toContain("remote-access-request");
    expect(ids("Never install AnyDesk for a stranger")).not.toContain("remote-access-request");
  });
});
