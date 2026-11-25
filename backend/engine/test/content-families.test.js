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

describe("direct password and OTP requests", () => {
  it("(a) code-sharing-request: a secret code in a list after a hand-over verb and a recipient", () => {
    expect(ids("Send us your password and otp")).toEqual(["credential-request", "code-sharing-request"]);
    expect(ids("Text me your username, PIN and 2FA code")).toEqual(["credential-request", "code-sharing-request"]);
    expect(ids("Forward our team the passcode or the OTP")).toEqual(["credential-request", "code-sharing-request"]);
    expect(ids("Please send your OTP to this number")).toEqual(["credential-request", "code-sharing-request"]);
    expect(ids("Reply with your PIN and the code we texted you")).toEqual(["credential-request", "code-sharing-request"]);
    expect(ids("Read me the code I just sent")).toEqual(["code-sharing-request"]);
    expect(score("Send us your password and otp").riskScore).toBe(50); // floor 4.14
  });
  it("(a) needs a hand-over context: no recipient, a new clause, or a sentence end in between", () => {
    expect(ids("Send the OTP")).toEqual(["credential-request"]);
    expect(ids("Tell us if you did not get your OTP")).toEqual(["credential-request"]);
    expect(ids("Send us a note. Your OTP arrives soon")).toEqual(["credential-request"]);
    expect(ids("Send us the pin for the map")).toEqual([]);
    expect(ids("please pin this post and send us a photo")).toEqual([]);
  });
  it("(b) floor 4.16: an instruction to hand over a password, PIN, passcode, login or security answer", () => {
    expect(score("Send us your password").riskScore).toBe(45);
    expect(score("Kindly email us your login details and password").riskScore).toBe(45);
    expect(score("Hi Sam, tell me your security answer").riskScore).toBe(45);
    expect(score("You need to give our agent your card PIN").riskScore).toBeGreaterThanOrEqual(45);
    expect(score("Send us your password").verdict).toBe("skeptical");
  });
  it("(b) not an instruction, or not the secret itself: no floor", () => {
    expect(score("If you share your password, change it").riskScore).toBe(20);
    expect(score("We sent your password reset link").riskScore).toBe(20);
    expect(score("Forgot it? Send a new password from the sign-in page.").riskScore).toBe(20);
    expect(score("Share your password manager tips with the team").riskScore).toBe(20);
    expect(score("Tell us if you forgot your password").riskScore).toBe(20);
  });
  it("(c) a request verb governed by a negation never fires", () => {
    expect(score("Never share your password with anyone").riskScore).toBe(0);
    expect(score("We will never ask you to send us your OTP").riskScore).toBe(0);
    expect(score("Do not share it with anyone").riskScore).toBe(0);
    expect(score("Never email your password or PIN to anyone").riskScore).toBe(0);
    expect(score("You must not send us your password").riskScore).toBeLessThanOrEqual(VERDICT_POOKIE_MAX);
  });
  it("a code being delivered is not a request", () => {
    expect(score("Your OTP is 482913. Do not share it with anyone.").riskScore).toBe(0);
    expect(score("Your one-time password is 559031.").riskScore).toBe(0);
    expect(ids("Your OTP is 4821. Please send it to us now")).toEqual(["code-sharing-request"]);
  });
});
