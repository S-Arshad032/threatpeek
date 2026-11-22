import { describe, it, expect } from "vitest";
import { detectContent } from "../src/detectors/content.js";
import { score } from "../src/index.js";
import { MAX_INPUT_LENGTH, VERDICT_POOKIE_MAX } from "../src/config.js";

// Rules added while tuning on the benchmark dev set. Fixtures use fictional brands and reserved
// TLDs (.example, .test, .invalid) only, and are worded differently from the benchmark messages.
const ids = (input) => detectContent(input).flags.map((f) => f.id);
const evidenceOf = (input, id) => detectContent(input).flags.find((f) => f.id === id)?.evidence;

describe("financial-info-request: word order (a)", () => {
  it("fires when the card term comes first and the request verb follows in the same sentence", () => {
    expect(ids("Card number and CVV: send them now")).toEqual(["financial-info-request"]);
    expect(evidenceOf("Your bank account and routing number, please submit both today", "financial-info-request")).toBe(
      "bank account and routing number, please submit",
    );
  });
  it("needs the verb within the proximity window and never crosses a sentence end", () => {
    expect(ids("Thanks for paying by credit card")).toEqual([]);
    expect(ids("We charged your credit card. Send us your feedback!")).toEqual([]);
    expect(ids(`Your credit card ${"was used at the corner cafe and ".repeat(3)}then we confirm`)).toEqual([]);
    expect(score("Thanks for paying by credit card").riskScore).toBe(0);
  });
});

describe("negation only when it governs the verb (b)", () => {
  it("suppresses a directly governed request", () => {
    expect(ids("We will never ask you to share your card number")).toEqual([]);
    expect(ids("Do not share your PIN")).toEqual([]);
    expect(ids("Never send your bank details to anyone")).toEqual([]);
    expect(ids("We will never ask you to share your card number, PIN or password.")).toEqual([]);
  });
  it("does not suppress a request the negation does not govern", () => {
    expect(ids("Do not delay, enter your card number")).toEqual(["financial-info-request"]);
    expect(ids("Don't wait: send your bank details today")).toEqual(["financial-info-request"]);
    expect(ids("Never share your password. Now confirm your password here.")).toEqual(["credential-request"]);
  });
});

describe("unusual-payment-method floor needs pressure or an instruction (c)", () => {
  it("a gift card mentioned on its own stays low", () => {
    const r = score("Buy a gift card for your mom");
    expect(r.redFlags.map((f) => f.id)).toEqual(["unusual-payment-method"]);
    expect(r.riskScore).toBeLessThanOrEqual(VERDICT_POOKIE_MAX);
  });
  it("an explicit hand-over instruction lifts it to the floor", () => {
    expect(score("Purchase three store gift cards and send me photos of the backs").riskScore).toBe(40);
    expect(score("Pay the amount in bitcoin to this wallet").riskScore).toBe(40);
  });
  it("urgency or secrecy lifts it to the floor", () => {
    expect(score("Settle the balance in crypto within 6 hours").riskScore).toBeGreaterThanOrEqual(40);
    expect(score("Pick up two gift cards and keep this between us").riskScore).toBe(40);
  });
  it("a hand-over phrase after a governing negation is not an instruction", () => {
    expect(score("Get a gift card, but never send it to us").riskScore).toBe(20);
  });
});

describe("urgency-en phrase families", () => {
  it.each([
    "Your mailbox has been temporarily locked",
    "We have suspended your wallet",
    "Respond within 48 hours",
    "Your laptop has been hacked",
    "To avoid legal action, act today",
    "Only 5 seats remaining",
    "Please call our desk immediately",
    "Final notice for your parcel",
  ])("%s", (input) => {
    expect(ids(input)).toContain("urgency-en");
  });
  it("does not fire on ordinary scheduling", () => {
    expect(ids("We will reply within two weeks")).toEqual([]);
    expect(ids("Delivery takes 3-5 business days")).toEqual([]);
  });
});

describe("prize-lottery and advance-fee-scheme families", () => {
  it("fires on promises of guaranteed or easy money", () => {
    expect(ids("Our fund offers guaranteed profit every month")).toEqual(["prize-lottery"]);
    expect(ids("Members see 150% returns")).toEqual(["prize-lottery"]);
    expect(ids("A prize of $2,000,000 awaits")).toEqual(["prize-lottery"]);
    expect(ids("Savings earn 4% interest")).toEqual([]);
    expect(ids("You have 1,000,000 reasons to smile")).toEqual([]);
  });
  it("fires on a fee presented as a condition", () => {
    for (const input of [
      "There is an unpaid import charge on your item",
      "A small admin fee is required",
      "Simply cover the $3.50 transport fee and it is yours",
      "Send the registration deposit upfront to unlock your account",
      "The duty must be paid before the goods are released",
    ]) {
      expect(ids(input)).toContain("advance-fee-scheme");
    }
  });
  it("does not fire on an ordinary fee", () => {
    expect(ids("Delivery fee: $3.99. Total $21.40.")).toEqual([]);
    expect(ids("Send the delivery fee through your mobile wallet")).toEqual(["unusual-payment-method"]);
  });
});

describe("new signals", () => {
  it("code-sharing-request: asks you to pass on a code sent to you", () => {
    expect(ids("Text us the 4-digit code from the SMS")).toEqual(["code-sharing-request"]);
    expect(ids("A confirmation code is on its way to you. Please send it back to me.")).toEqual(["code-sharing-request"]);
    expect(ids("Never share your verification code with anyone")).toEqual([]);
    expect(ids("Enter the verification code on the website")).toEqual([]);
    expect(ids("Send the OTP")).toEqual(["credential-request"]); // OTP alone stays a credential request
    expect(score("Reply with the security code we texted you").riskScore).toBe(50);
  });
  it("mistaken-payment: money 'sent by mistake' and a request to return it", () => {
    expect(ids("I mistakenly transferred $90 to you, please send the money back")).toEqual(["mistaken-payment"]);
    expect(score("Your account was overpaid. Kindly refund the difference today.").riskScore).toBeGreaterThanOrEqual(40);
    expect(ids("I sent you $20 for lunch, thanks!")).toEqual([]);
    expect(ids("The shop refunded it by mistake")).toEqual([]);
  });
  it("remote-access-request: install a remote tool or hand over the device", () => {
    expect(ids("Download the remote desktop app so we can help")).toEqual(["remote-access-request"]);
    expect(ids("Grant our engineer remote access to your computer")).toEqual(["remote-access-request"]);
    expect(ids("Install the new calendar app from the store")).toEqual([]);
  });
});

describe("decimal points are not sentence ends", () => {
  it("keeps a price inside the proximity window", () => {
    expect(ids("Pay $4.99 in bitcoin")).toEqual(["unusual-payment-method"]);
    expect(ids("Pay now. Bitcoin is accepted")).not.toContain("unusual-payment-method");
  });
});

describe("cursed phrases quote the original text", () => {
  it("for every new rule", () => {
    const input =
      "URGENT: your acc0unt has been locked. I accidentally sent you $40, s e n d it back. " +
      "Install the remote support tool. Forward the verification code to us within 2 hours.";
    const r = score(input);
    expect(r.cursedPhrases.length).toBeGreaterThan(0);
    for (const p of r.cursedPhrases) expect(input).toContain(p.text);
  });
});

describe("new regexes stay fast on adversarial input", () => {
  const fill = (unit) => unit.repeat(Math.floor(MAX_INPUT_LENGTH / unit.length));
  it.each([
    "within ",
    "unpaid ",
    "fee ",
    "fee before ",
    "just pay ",
    "sent by ",
    "accidentally sent ",
    "code ",
    "send it ",
    "never ask you to ",
    "do not share ",
    "$1,000,",
    "4.9",
    "p a s ",
    "install remote ",
    "account is ",
    "send me ",
    "card number ",
    "@0$1 ",
  ])("%j repeated", (unit) => {
    const input = fill(unit);
    const start = performance.now();
    expect(() => score(input)).not.toThrow();
    expect(performance.now() - start).toBeLessThan(500);
  });
});
