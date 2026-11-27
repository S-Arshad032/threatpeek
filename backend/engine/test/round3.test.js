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

describe("unfamiliar-link-pressure", () => {
  // Written with "[.]"; each is also tested with normal dots, the way real messages write links.
  const SCAMS = [
    "Lumen Mobile: your SIM will be deactivated within 12 hours under the new ID rules. Re-verify at lumen-sim-check[.]net",
    "Harbor Trust: online banking access is restricted until you finish the KYC update. Visit harbor-kyc-desk[.]com today.",
    "You qualify for the Northfield Study Grant. Pay the 30 USD processing fee at northfield-grant[.]org before midnight.",
    "Your page Mira Bakes will be unpublished for a policy breach. File an appeal at page-review-desk[.]co/ticket",
  ];
  const plain = (text) => text.replaceAll("[.]", ".");

  it.each(SCAMS.flatMap((s) => [[s], [plain(s)]]))("scores 50 or more, defanged or not: %s", (text) => {
    expect(ids(text)).toContain("unfamiliar-link-pressure");
    expect(score(text).riskScore).toBeGreaterThanOrEqual(50);
  });

  it("the normal-dot versions do not depend on defanged-link", () => {
    for (const text of SCAMS.map(plain)) expect(ids(text)).not.toContain("defanged-link");
  });

  it("counts a shortener, a raw IP and a risky TLD as unfamiliar", () => {
    expect(ids("Your parcel fee is unpaid. Pay today: https://bit.ly/3xYzAbc")).toContain("unfamiliar-link-pressure");
    expect(ids("Your wallet is frozen. Verify at http://203.0.113.7/wallet")).toContain("unfamiliar-link-pressure");
    expect(ids("Claim your refund before midnight at quickrefund.top")).toContain("unfamiliar-link-pressure");
  });

  it("alone it sets the score to 50, never above 60", () => {
    const text = "Pay the fee at quick-cash-desk.com";
    expect(ids(text)).toEqual(["unfamiliar-link-pressure"]);
    expect(score(text).riskScore).toBe(50);
  });

  it("needs both an unfamiliar link and pressure", () => {
    expect(ids("Read the menu at north-end-coffee.com")).not.toContain("unfamiliar-link-pressure"); // no pressure
    expect(ids("Your account is suspended. Call us.")).not.toContain("unfamiliar-link-pressure"); // no link
    expect(ids("Pay the invoice at northendcoffee.com")).not.toContain("unfamiliar-link-pressure"); // plain domain
    // a pressure word that is only part of the domain does not count
    expect(ids("See the new menu at cafe-verify-pay.com")).not.toContain("unfamiliar-link-pressure");
  });

  it("never fires on a well-known real domain", () => {
    for (const text of [
      "Your Instagram account is restricted. Appeal at https://help.instagram.com/appeal-form-now",
      "Your PayPal payment is due today: https://www.paypal.com/pay",
      "Verify your bKash number today at https://www.bkash.com/verify",
      "Settle your Nagad bill today at https://nagad.com.bd/pay",
    ]) {
      expect(ids(text)).not.toContain("unfamiliar-link-pressure");
    }
  });

  it.each([
    "Your order has shipped. Track it at https://www.amazon.com/orders within 24 hours of delivery.",
    "Your electricity bill is due on the 10th. Pay in the official app.",
    "Interview confirmed for Monday at 10:30. Details: https://careers.examplecorp.com/interview",
    "Reminder: your appointment is tomorrow at 5 PM. Reply C to confirm.",
    "Your Visa card ending 4821 was used at a store. If this was not you, call 16221.",
  ])("required negative stays below 30: %s", (text) => {
    expect(ids(text)).not.toContain("unfamiliar-link-pressure");
    expect(score(text).riskScore).toBeLessThan(30);
  });
});
