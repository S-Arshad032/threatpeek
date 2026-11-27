import { describe, it, expect } from "vitest";
import { score } from "../src/index.js";

// Round 3: credential-request needs a real request, and the unfamiliar-link-pressure signal.
// Every message is written for this file: fictional names and made-up domains, wording that does
// not come from any benchmark set.
const ids = (input) => score(input).redFlags.map((f) => f.id);

describe("credential-request: a notice is not a request", () => {
  it.each([
    "Orbitins Bank: the password for your account was changed on 3 March at 09:12. If you did not make this change, please contact our helpline at 16000 right away.",
    "Your Nexamail password was reset successfully.",
    "A new PIN was created for your Galactibank debit card.",
    "Your OTP is 482913. It expires in 5 minutes.",
    "Do not share your password or PIN with anyone, including our staff.",
    "If you did not make this change, contact us at 16000.",
    "We have sent a one-time password to your registered number.",
    "Unusual sign-in: we noticed a login from a new device in Lisbon. If this was you, no action is needed.",
    "Malware may expose your saved passwords. Keep your antivirus updated.",
  ])("does not fire: %s", (text) => {
    expect(ids(text)).not.toContain("credential-request");
    expect(score(text).riskScore).toBeLessThan(30);
  });

  it("urgency alone (no link, no request) stays below 30", () => {
    const texts = [
      "Please call our branch right away about your card delivery.",
      "Your parcel is ready. Collect it from the front desk immediately.",
      "Meeting moved to 3 PM, please confirm right away.",
    ];
    for (const text of texts) {
      expect(ids(text).filter((id) => id !== "urgency-en")).toEqual([]);
      expect(score(text).riskScore).toBeLessThan(30);
    }
    expect(texts.some((text) => ids(text).includes("urgency-en"))).toBe(true);
  });

  it("real requests addressed to the reader still fire", () => {
    for (const text of [
      "Enter your PIN on the next page to continue",
      "Reply to this message with your one-time passcode",
      "Please read out the PIN shown in your banking app",
      "Read back the OTP we just sent so we can cancel the transfer",
      "Your PIN please",
      "Log in here to keep your account active",
      "Re-validate your mailbox now or it will be closed",
    ]) {
      expect(ids(text)).toContain("credential-request");
    }
    expect(score("Send us your password and otp").riskScore).toBe(50);
  });
});
