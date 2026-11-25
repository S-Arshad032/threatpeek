import { describe, it, expect } from "vitest";
import { score } from "../src/index.js";
import { detectContent } from "../src/detectors/content.js";
import { EXPLANATION_TEMPLATES, CURSED_PHRASE_REASONS } from "../src/config.js";

// Scam families (signals delivery-scam ... recruiter-bait, floors 4.17-4.22).
// The six reference messages are quoted as reported. Paraphrases use fictional names and reserved
// or throwaway domains, and are worded differently from the benchmark sets.
const ids = (input) => score(input).redFlags.map((f) => f.id);

const REFERENCE = [
  {
    signal: "recruiter-bait",
    min: 50,
    text: "Hi, I'm Sarah from TalentBridge. We have an opening matching your web development background. Are you open to a quick chat this week? Here is the job brief: docs-share-view[.]com/role-402",
  },
  {
    signal: "investment-guarantee",
    min: 70,
    text: "Join our VIP crypto signals group and turn $200 into $3,500 in 72 hours with guaranteed futures trades. Limited spots left—DM admin now.",
  },
  {
    signal: "seed-phrase-request",
    min: 70,
    text: "Your wallet connection expired on MetaMask/TrustWallet protocol. Re-sync your 12-word recovery phrase at wallet-restore-node[.]io to prevent asset lock.",
  },
  {
    signal: "official-fine-threat",
    min: 60,
    text: "BRTA/Traffic Notice: An unpaid speed violation fine of 2,500 BDT is linked to your vehicle registration. Settle within 24 hours to avoid legal action: brta-fine-pay[.]org",
  },
  {
    signal: "task-job-scam",
    min: 50,
    text: "Hello! We're hiring part-time TikTok/YouTube video likers. Earn 2,000–6,000 BDT daily working 30–45 mins from home. Reply YES to start your trial task.",
  },
  {
    signal: "delivery-scam",
    min: 50,
    text: "Delivery failed: Your parcel could not be delivered due to incomplete address. Update shipping details within 12 hours: bit.ly/track-pkg-992",
  },
];

const PARAPHRASES = {
  "delivery-scam": [
    "Courier notice: your package is on hold because of an incorrect address. Confirm your delivery address here: hxxps://parcel-fix[.]example/a1",
    "We were unable to deliver your shipment today. Reschedule delivery within 24 hrs at tinyurl.com/redel-55",
    "Your parcel could not be delivered. Please update your shipping details: post-track.example/upd",
  ],
  "seed-phrase-request": [
    "Security alert: your wallet will be frozen. Validate your wallet now at wallet-check[.]example to keep your funds.",
    "Support here. To restore access, please enter your 24-word seed phrase in the form below.",
    "Airdrop pending! Connect your wallet and import your private key at claim-drop.example to receive 500 tokens.",
  ],
  "investment-guarantee": [
    "Our forex VIP channel gives guaranteed profits of 15% daily. Message admin to join.",
    "Grow your $500 into $5,000 in one week with our bitcoin trading bot. Risk-free, limited slots.",
    "Invest 100 USDT and get guaranteed returns: double your money in 48 hours. DM admin now.",
  ],
  "task-job-scam": [
    "Part-time job: rate hotels on our app and earn $40-$120 per day from your phone. WhatsApp us to begin.",
    "Looking for online reviewers! Simple tasks, 20 mins a day, paid 1,500 BDT per task. Text YES to join.",
    "Earn 3000 taka daily by liking YouTube videos at home. Reply 'OK' for your first task.",
  ],
  "official-fine-threat": [
    "Police notice: an outstanding traffic penalty of $85 is recorded against your licence. Pay today at road-fines.example or a warrant will be issued.",
    "Customs: tax of 1,200 BDT is due on your package. Clear the payment within 2 days to avoid prosecution: customs-office[.]xyz",
    "Final notice from the Revenue Office: unpaid income tax penalty. Settle now at hxxp://tax-settle.test to avoid legal action.",
  ],
  "recruiter-bait": [
    "Hello, this is Daniel with NovaHire. We have a remote role that fits your profile. Please review the role details: hire-portal.example/brief/88",
    "Hi! I'm a recruiter at Brightpath Staffing. There's a senior designer opening; the job description is here: jd-viewer.test/x91",
    "My name is Priya from Kestrel Talent. Are you open to a new position? Fill in this short form: forms-hub[.]example/apply",
  ],
};

// Ordinary messages that share words with the families. All must stay below 30.
const NEGATIVES = [
  // Required negatives.
  "Your parcel was delivered today. Thanks for shopping with us.",
  "Your order #4521 has shipped. Track it in our app.",
  "Reminder: your electricity bill of 1,200 BDT is due on the 10th. Pay in the official app.",
  "We are hiring a full-time frontend developer. Apply on our careers page.",
  "Your OTP is 482913. Do not share it with anyone.",
  "Never share your 12-word recovery phrase with anyone.",
  // Near misses per family.
  "Your package is on hold at the depot. Pick it up with your ID before Friday.",
  "Tip: never type your seed phrase into any website. We will never ask you to share your recovery phrase.",
  "You can restore your wallet with your 12-word recovery phrase if you lose your phone.",
  "Past performance does not guarantee future returns. Investing involves risk.",
  "There are no guaranteed returns in crypto trading. Only invest what you can afford to lose.",
  "We're hiring part-time cashiers at $12 per hour. Apply in store.",
  "Watch this video about how to rate products on our app: help.example/video",
  "Your parking ticket of $40 was paid. Thank you. Receipt: city-parking.example/r/77",
  "Hi, I'm Tom from Acme. Thanks for applying to the role. Interview details are in your inbox.",
  "Your order will arrive in 24 hours. Track it at shop.example/track",
  "Polka dot dress back in stock at shop.example",
];

describe("scam families: reference messages", () => {
  it.each(REFERENCE)("$signal reaches $min", ({ signal, min, text }) => {
    const r = score(text);
    expect(r.redFlags.map((f) => f.id)).toContain(signal);
    expect(r.riskScore).toBeGreaterThanOrEqual(min);
  });

  it("the ambiguous new-device sign-in notice is not flagged", () => {
    const r = score(
      "We noticed a sign-in to your account from a new Windows device in Frankfurt, Germany. If this wasn't you, review your recent activity in your account settings.",
    );
    expect(r.redFlags).toEqual([]);
    expect(r.riskScore).toBeLessThan(30);
  });
});

describe("scam families: paraphrases", () => {
  for (const [signal, texts] of Object.entries(PARAPHRASES)) {
    it.each(texts)(`${signal}: %s`, (text) => {
      const r = score(text);
      expect(r.redFlags.map((f) => f.id)).toContain(signal);
      expect(r.riskScore).toBeGreaterThanOrEqual(50);
    });
  }
});

describe("scam families: negatives stay below 30", () => {
  it.each(NEGATIVES)("%s", (text) => {
    expect(score(text).riskScore).toBeLessThan(30);
  });
});

describe("scam families: cue rules", () => {
  it("delivery-scam needs a link", () => {
    expect(ids("Your parcel could not be delivered due to an incomplete address.")).not.toContain("delivery-scam");
  });
  it("delivery-scam weighs more with a URL shortener", () => {
    const flag = (t) => detectContent(t).flags.find((f) => f.id === "delivery-scam");
    expect(flag("Parcel on hold: confirm your address at post.example/a").weight).toBe(25);
    expect(flag("Parcel on hold: confirm your address at bit.ly/a").weight).toBe(30);
  });
  it("seed-phrase-request: a wallet 'fix' needs a link, a direct phrase request does not", () => {
    expect(ids("Please validate your wallet.")).not.toContain("seed-phrase-request");
    expect(ids("Please validate your wallet at wallet-fix.example")).toContain("seed-phrase-request");
    expect(ids("Kindly send your private key to the support team.")).toContain("seed-phrase-request");
  });
  it("investment-guarantee needs a trading context as well as the promise", () => {
    expect(ids("Turn $20 into $50 of store credit with our loyalty card.")).not.toContain("investment-guarantee");
  });
  it("task-job-scam needs simple paid tasks plus another cue, or pay + easy hours + reply", () => {
    expect(ids("Earn $15 per hour, part-time.")).not.toContain("task-job-scam");
    expect(ids("Earn $300 per day, 1-2 hours from home. Reply YES.")).toContain("task-job-scam");
  });
  it("official-fine-threat needs a link and pressure", () => {
    expect(ids("You have an unpaid parking fine. Pay at the city office.")).not.toContain("official-fine-threat");
    expect(ids("You have an unpaid parking fine. Pay at fines.example.")).not.toContain("official-fine-threat");
    expect(ids("You have an unpaid parking fine. Pay today at fines.example.")).toContain("official-fine-threat");
  });
  it("recruiter-bait ignores links on well-known job sites", () => {
    expect(
      ids("Hi, I'm Ana from Corvid Labs. We have an opening for you; job brief: https://www.linkedin.com/jobs/view/1"),
    ).not.toContain("recruiter-bait");
  });
});

describe("urgency-en: time limits", () => {
  const urgency = (t) => detectContent(t).flags.find((f) => f.id === "urgency-en")?.evidence;
  it("counts 'within N hours/days' and 'in N hrs'", () => {
    expect(urgency("Update details within 12 hours")).toBe("within 12 hours");
    expect(urgency("Pay in 24 hrs")).toBe("in 24 hrs");
    expect(urgency("Settle within 2 days")).toBe("within 2 days");
  });
  it("does not count service promises or code lifetimes", () => {
    expect(urgency("Your order arrives in 24 hours")).toBeUndefined();
    expect(urgency("Your code expires in 10 minutes")).toBeUndefined();
    expect(urgency("Refunds are processed within 3 days")).toBeUndefined();
  });
});

describe("scam families: explanations and cursed phrases", () => {
  it("every family flag has a plain-English explanation and quotes the original text", () => {
    for (const { signal, text } of REFERENCE) {
      const r = score(text);
      const flag = r.redFlags.find((f) => f.id === signal);
      expect(flag.explanation).toBe(EXPLANATION_TEMPLATES[signal].replace("{e}", flag.evidence));
      expect(text).toContain(flag.evidence);
      expect(r.cursedPhrases.some((p) => p.reason === CURSED_PHRASE_REASONS[signal])).toBe(true);
    }
  });
});
