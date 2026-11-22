import { describe, it, expect } from "vitest";
import { detectContent } from "../src/detectors/content.js";
import { score } from "../src/index.js";
import {
  EXPLANATION_TEMPLATES,
  URGENCY_EN_PHRASES,
  PRIZE_PHRASES,
  ADVANCE_FEE_PHRASES,
  SECRECY_PHRASES,
  MAX_CURSED_PHRASES,
  VERDICT_POOKIE_MAX,
} from "../src/config.js";

// Fixtures use fictional brands and reserved TLDs (.example, .test, .invalid) only.
const ids = (input) => detectContent(input).flags.map((f) => f.id);
const evidenceOf = (input, id) => detectContent(input).flags.find((f) => f.id === id)?.evidence;

describe("detectContent: urgency", () => {
  it("emits one urgency-en flag but a cursed phrase per distinct phrase", () => {
    const { flags, cursedPhrases } = detectContent(
      "Act now! Your account will be suspended. Verify immediately or lose access.",
    );
    expect(flags.map((f) => f.id)).toEqual(["urgency-en"]);
    expect(flags[0].evidence).toBe("Act now");
    expect(cursedPhrases.map((p) => p.text)).toEqual(["Act now", "account will be suspended", "Verify immediately"]);
  });

  it("matches every configured English phrase, across flexible whitespace", () => {
    for (const phrase of URGENCY_EN_PHRASES) {
      expect(ids(`Notice: ${phrase.toUpperCase().replace(/ /g, "  ")}!`)).toEqual(["urgency-en"]);
    }
  });
});

describe("detectContent: credential-request", () => {
  it("fires on password, login and uppercase OTP/PIN", () => {
    expect(ids("enter your password")).toEqual(["credential-request"]);
    expect(ids("please log in")).toEqual(["credential-request"]);
    expect(ids("Send the OTP")).toEqual(["credential-request"]);
    expect(ids("Your PIN please")).toEqual(["credential-request"]);
  });
  it("does not fire on a credential word that is part of a hostname", () => {
    expect(ids("https://login.galactibank.example")).toEqual([]);
    expect(ids("see galactibank-login.example")).toEqual([]);
    expect(ids("Please login.")).toEqual(["credential-request"]);
    expect(ids("go to https://galactibank.example/login now")).toEqual(["credential-request"]);
  });
  it("does not fire on the ordinary word pin", () => {
    expect(ids("please pin this post")).toEqual([]);
  });
  it("uses the earliest match as evidence", () => {
    const { flags } = detectContent("Reply with your OTP and password");
    expect(flags[0].evidence).toBe("OTP");
  });
});

describe("detectContent: suspicious-attachment", () => {
  it("fires on a dangerous file name", () => {
    const { flags, cursedPhrases } = detectContent("Please open invoice.exe to see your order.");
    expect(flags.map((f) => f.id)).toEqual(["suspicious-attachment"]);
    expect(flags[0].evidence).toBe("invoice.exe");
    expect(cursedPhrases).toEqual([]);
  });
  it("skips allowlisted JS library names", () => {
    expect(ids("I work with Node.js daily")).toEqual([]);
    expect(ids("I use React.js and Vue.js")).toEqual([]);
  });
  it("does not fire on a hostname or URL path", () => {
    expect(ids("blog.bat.example")).toEqual([]);
    expect(ids("load https://cdn.example/app.js now")).toEqual([]);
  });
});

describe("detectContent: prize-lottery", () => {
  it("matches every configured prize phrase", () => {
    for (const phrase of PRIZE_PHRASES) {
      expect(ids(`Hello! ${phrase.toUpperCase()} today`)).toEqual(["prize-lottery"]);
    }
  });
  it("accepts the typographic apostrophe", () => {
    expect(ids("You’ve won a cruise")).toEqual(["prize-lottery"]);
  });
  it("fires on congratulations followed by a prize word", () => {
    expect(evidenceOf("Congratulations, you were selected for our reward draw", "prize-lottery")).toBe(
      "Congratulations",
    );
    expect(ids("Congrats!! Our records show you are a WINNER")).toEqual(["prize-lottery"]);
  });
  it("fires on large money amounts with a currency marker", () => {
    expect(evidenceOf("Receive $1 million today", "prize-lottery")).toBe("$1 million");
    expect(evidenceOf("a grant of USD 2.5 billion", "prize-lottery")).toBe("USD 2.5 billion");
    expect(evidenceOf("collect 5 million dollars", "prize-lottery")).toBe("5 million dollars");
    expect(evidenceOf("€3,000,000 million euro payout", "prize-lottery")).toBe("€3,000,000 million");
  });
  it("does not fire on plain congratulations or a number without a currency", () => {
    expect(ids("Congratulations on your new job!")).toEqual([]);
    expect(ids("Congratulations on the wedding. See you at the party next week!")).toEqual([]);
    expect(ids("The city has 2 million residents")).toEqual([]);
    expect(ids("We won the match 3-1")).toEqual([]);
  });
});

describe("detectContent: advance-fee-scheme", () => {
  it("matches every configured advance-fee phrase", () => {
    for (const phrase of ADVANCE_FEE_PHRASES) {
      expect(ids(`Dear friend, about the ${phrase} we discussed`)).toContain("advance-fee-scheme");
    }
  });
  it("fires on a transfer of a large sum", () => {
    expect(evidenceOf("I seek your help with the transfer of $4.5 million", "advance-fee-scheme")).toBe(
      "transfer of $4.5 million",
    );
    expect(evidenceOf("the transfer of the sum of USD 12 million", "advance-fee-scheme")).toBe(
      "transfer of the sum of USD 12 million",
    );
  });
});

describe("detectContent: financial-info-request", () => {
  it("fires when a request verb comes shortly before a card or bank term", () => {
    expect(evidenceOf("Enter your credit card details to continue", "financial-info-request")).toBe(
      "Enter your credit card",
    );
    expect(ids("Kindly provide your bank account and routing number")).toEqual(["financial-info-request"]);
    expect(ids("Reply with the CVV on the back of your card")).toEqual(["financial-info-request"]);
    expect(ids("Please confirm your SSN so we can release the refund")).toEqual(["financial-info-request"]);
    expect(ids("type   the card number and expiry date below")).toEqual(["financial-info-request"]);
  });
  it("requires the verb and the term to be close and in the same sentence", () => {
    expect(ids("Thanks for paying by credit card")).toEqual([]);
    expect(ids("Please confirm your appointment. We accept every credit card.")).toEqual([]);
    expect(ids(`Please update ${"the details of the meeting room and ".repeat(3)}the credit card`)).toEqual([]);
  });
  it("does not fire on a warning that tells you never to share the details", () => {
    expect(ids("We will never ask you to share your card number by email")).toEqual([]);
    expect(ids("Do not send your bank details to anyone")).toEqual([]);
    expect(ids("Don’t enter your credit card on unknown sites")).toEqual([]);
  });
});

describe("detectContent: unusual-payment-method", () => {
  it("fires when a payment verb comes shortly before a hard-to-trace method", () => {
    expect(evidenceOf("Buy two Google Play gift cards and send me the codes", "unusual-payment-method")).toBe(
      "Buy two Google Play gift cards",
    );
    expect(ids("Pay the fine in Bitcoin today")).toEqual(["unusual-payment-method"]);
    expect(ids("send the money via Western Union or MoneyGram")).toEqual(["unusual-payment-method"]);
    expect(ids("Payment must be made by wire transfer")).toEqual(["unusual-payment-method"]);
    expect(ids("Transfer it as crypto (USDT) now")).toEqual(["unusual-payment-method"]);
    expect(ids("pay with iTunes cards")).toEqual(["unusual-payment-method"]);
  });
  it("counts a mobile wallet only when a fee is involved", () => {
    expect(ids("Send the delivery fee through your mobile wallet")).toEqual(["unusual-payment-method"]);
    expect(ids("Send money to this mobile wallet as a fee")).toEqual(["unusual-payment-method"]);
    expect(ids("You can pay at the shop with your mobile wallet")).toEqual([]);
  });
  it("does not fire without a payment verb or after a negation", () => {
    expect(ids("I received a gift card for my birthday")).toEqual([]);
    expect(ids("Bitcoin prices rose this week")).toEqual([]);
    expect(ids("We will never ask you to pay with gift cards")).toEqual([]);
  });
});

describe("detectContent: secrecy-pressure", () => {
  it("matches every configured secrecy phrase", () => {
    for (const phrase of SECRECY_PHRASES) {
      expect(ids(`Important: ${phrase}.`)).toEqual(["secrecy-pressure"]);
    }
  });
  it("accepts the typographic apostrophe", () => {
    expect(ids("Don’t tell anyone about this")).toEqual(["secrecy-pressure"]);
  });
});

describe("benign messages stay low", () => {
  const BENIGN = [
    "Thanks for paying by credit card",
    "Your order has shipped and will arrive on Tuesday.",
    "Congratulations on your new job!",
    "Galactibank notice: your monthly statement is ready to view in the app. We will never ask you to share your card number or bank details by message.",
    "Reminder: the dentist appointment is at 3pm. Please confirm your attendance.",
    "Your refund of $12.50 has been sent back to your debit card.",
    "The city council approved $2 billion for new parks.",
    "I bought a gift card for Mum's birthday, can you sign the card?",
    "Happy anniversary! Keep up the great work.",
    "Your bank account statement for March is attached as statement.pdf.",
  ];
  it.each(BENIGN)("%s", (input) => {
    const result = score(input);
    expect(result.riskScore).toBeLessThanOrEqual(VERDICT_POOKIE_MAX);
    expect(result.verdict).toBe("pookie");
    for (const id of ["financial-info-request", "unusual-payment-method", "advance-fee-scheme"]) {
      expect(result.redFlags.map((f) => f.id)).not.toContain(id);
    }
  });
});

describe("detectContent: cursed phrases", () => {
  it("de-duplicates by lowercase text and caps the list", () => {
    const { cursedPhrases } = detectContent("password PASSWORD Password");
    expect(cursedPhrases).toHaveLength(1);
    const many = Array.from({ length: 30 }, (_, i) => `act${"  ".repeat(i % 5)} now${" ".repeat(i)}`).join(". ");
    expect(detectContent(many).cursedPhrases.length).toBeLessThanOrEqual(MAX_CURSED_PHRASES);
  });

  it("returns an empty list when no phrase signal fires", () => {
    expect(detectContent("Hi, lunch at 1pm tomorrow?").cursedPhrases).toEqual([]);
  });

  it("adds a cursed phrase for every new scam signal", () => {
    const { cursedPhrases } = detectContent(
      "You have won! Pay the release fee with gift cards, enter your card number and keep this confidential.",
    );
    expect(cursedPhrases.map((p) => p.text)).toEqual([
      "You have won",
      "release fee",
      "enter your card number",
      "Pay the release fee with gift cards",
      "keep this confidential",
    ]);
  });
});

describe("detectContent: explanations and reasons", () => {
  const inputs = [
    "Act now or lose access",
    "Please send your password.",
    "Please open invoice.exe to see your order.",
    "Congratulations! You have won $1 million. Enter your credit card details to get that money.",
    "Your inheritance is waiting. Pay the clearance fee by Western Union. Do not tell anyone.",
  ];
  it("every flag has a non-empty explanation and every cursed phrase a non-empty reason", () => {
    for (const input of inputs) {
      const { flags, cursedPhrases } = detectContent(input);
      expect(flags.length).toBeGreaterThan(0);
      for (const f of flags) {
        expect(f.explanation.length).toBeGreaterThan(0);
        expect(f.explanation).toBe(EXPLANATION_TEMPLATES[f.id].replace("{e}", f.evidence));
      }
      for (const p of cursedPhrases) {
        expect(p.text.length).toBeGreaterThan(0);
        expect(p.reason.trim().length).toBeGreaterThan(0);
        expect(input).toContain(p.text);
      }
    }
  });
});
