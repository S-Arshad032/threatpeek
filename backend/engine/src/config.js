// Central constants for the threat-scoring engine.
// Every number and word list used by the engine lives here. This module imports nothing.

// ---------------------------------------------------------------------------
// Signal weights
// ---------------------------------------------------------------------------
export const W_TYPOSQUATTING = 35;
export const W_HOMOGRAPH_PUNYCODE = 35;
export const W_RAW_IP_URL = 35;
export const W_RISKY_TLD = 15;
export const W_DISPLAY_NAME_MISMATCH = 25;
export const W_LINK_TEXT_MISMATCH = 35;
export const W_URGENCY_EN = 15;
export const W_CREDENTIAL_REQUEST = 20;
export const W_SUSPICIOUS_ATTACHMENT = 20;
export const W_SPF_FAIL = 20;
export const W_DKIM_FAIL = 20;
export const W_DMARC_FAIL = 15;
export const W_PRIZE_LOTTERY = 25;
export const W_ADVANCE_FEE_SCHEME = 25;
export const W_FINANCIAL_INFO_REQUEST = 30;
export const W_UNUSUAL_PAYMENT_METHOD = 20;
export const W_SECRECY_PRESSURE = 10;
export const W_CODE_SHARING_REQUEST = 30;
export const W_MISTAKEN_PAYMENT = 25;
export const W_REMOTE_ACCESS_REQUEST = 25;
export const W_DEFANGED_LINK = 10;
export const W_DELIVERY_SCAM = 25;
export const W_DELIVERY_SCAM_SHORTENER = 30; // the same signal when the link is a URL shortener
export const W_SEED_PHRASE_REQUEST = 35;
export const W_INVESTMENT_GUARANTEE = 25;
export const W_TASK_JOB_SCAM = 25;
export const W_OFFICIAL_FINE_THREAT = 25;
export const W_RECRUITER_BAIT = 20;
export const W_LOOKALIKE_LURE_DOMAIN = 20;
export const W_LOOKALIKE_LURE_DOMAIN_STRONG = 30; // the same signal on a risky TLD or a defanged link
export const W_UTILITY_DISCONNECTION_THREAT = 25;
export const W_PAYMENT_FAILED_LURE = 25;
export const W_ACCOUNT_SECURITY_LURE = 25;
export const W_UNFAMILIAR_LINK_PRESSURE = 25; // round 3: an unfamiliar link + pressure language

// ---------------------------------------------------------------------------
// Category caps
// ---------------------------------------------------------------------------
export const CAP_IDENTITY_AUTH = 40;
export const CAP_LINK = 35;
export const CAP_CONTENT = 45;

// ---------------------------------------------------------------------------
// Verdict thresholds (inclusive upper bounds)
// ---------------------------------------------------------------------------
export const VERDICT_POOKIE_MAX = 30;
export const VERDICT_SKEPTICAL_MAX = 69;

// ---------------------------------------------------------------------------
// Hard floors
// ---------------------------------------------------------------------------
export const FLOOR_TYPOSQUAT_CRED = 70;
export const FLOOR_RAWIP_CRED = 70;
export const FLOOR_AUTH_DISPLAY = 60;
export const FLOOR_CRED_URGENCY = 55;
export const FLOOR_ATTACHMENT = 40;
export const FLOOR_PRIZE_PAYMENT = 70; // (prize-lottery or advance-fee-scheme) + (financial-info-request or unusual-payment-method)
export const FLOOR_FINANCIAL_INFO = 50;
export const FLOOR_UNUSUAL_PAYMENT = 40; // unusual-payment-method + a pressure signal or an explicit "send/pay ... to" instruction
export const FLOOR_CODE_SHARING = 50; // code-sharing-request alone
export const FLOOR_MISTAKEN_PAYMENT = 40; // mistaken-payment alone
// 4.16: the message tells the reader to hand over a password, PIN, passcode, login or security
// answer ("Send us your password", "You must email us your login password"). Not a signal: the
// content detector reports it as context.secretRequest. Lifts the score into "skeptical".
export const FLOOR_SECRET_REQUEST = 45;
// Scam families. Each floor sits on a compound signal (several cues in one message), never on a
// single word, so one weak cue alone never lifts a message above 50.
export const FLOOR_DELIVERY_SCAM = 50; // 4.17: parcel context + failed/held/"update delivery details" + a link
export const FLOOR_SEED_PHRASE = 70; // 4.18: a request for a wallet recovery phrase or private key
export const FLOOR_INVESTMENT = 55; // 4.19: guaranteed/multiplied returns + a trading or signals context
export const FLOOR_INVESTMENT_PRESSURE = 70; // 4.19: the same + urgency-en or unusual-payment-method
export const FLOOR_TASK_JOB = 50; // 4.20: paid "like videos" / trial-task job bait
export const FLOOR_OFFICIAL_FINE = 60; // 4.21: fine/tax/police + pay + deadline or legal threat + a link
export const FLOOR_RECRUITER_BAIT = 50; // 4.22: unsolicited recruiter + role + a doc/brief on an unfamiliar link
// Round 2.
export const FLOOR_UTILITY_DISCONNECTION = 50; // 4.23: utility + disconnection + unpaid bill + a link or "pay now"
export const FLOOR_PAYMENT_FAILED = 50; // 4.24: failed payment + "update payment details" + a suspicious link or a threat
export const FLOOR_ACCOUNT_SECURITY = 50; // 4.25: sign-in alert + "cancel/secure" + a lookalike link
export const FLOOR_JOB_FEE = 60; // 4.26: a job/hiring context + an upfront onboarding/registration/training fee
export const FLOOR_UNFAMILIAR_LINK_PRESSURE = 50; // 4.27: an unfamiliar link + a deadline, threat, fee or verify ask

// ---------------------------------------------------------------------------
// Blend coefficients
// ---------------------------------------------------------------------------
export const BLEND_L1_WEIGHT = 0.55;
export const BLEND_L3_WEIGHT = 0.45;
export const BLEND_L1_FLOOR_FACTOR = 0.8;
export const BLEND_L2_FLOOR = 90;

// Score range
export const SCORE_MIN = 0;
export const SCORE_MAX = 100;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------
export const MAX_INPUT_LENGTH = 4000;
export const MAX_HOSTNAMES_SCANNED = 50;
export const MAX_CURSED_PHRASES = 20;
export const MAX_EVIDENCE_LENGTH = 200; // e.g. the trimmed From: line

// ---------------------------------------------------------------------------
// Content proximity windows (characters). Every gap is a bounded character class.
// ---------------------------------------------------------------------------
export const REQUEST_PROXIMITY_CHARS = 60; // request/payment verb -> card term or payment method, same sentence
export const PRIZE_PROXIMITY_CHARS = 60; // "congratulations" -> won/winner/prize...
// A negation only suppresses a request verb it directly governs: "never share", "do not send",
// "will never ask you to share". At most this many helper words may sit between the two.
export const NEGATION_GOVERNED_MAX_WORDS = 4;
export const FEE_PROXIMITY_CHARS = 40; // fee word -> "to release", "upfront", "before ... released"
export const FEE_STATUS_PROXIMITY_CHARS = 30; // "unpaid customs charge", "fee ... is required"
export const IMMEDIACY_PROXIMITY_CHARS = 40; // "call ... immediately"
export const DEADLINE_DIGITS_MAX = 3; // "within 24 hours"
export const SCARCITY_DIGITS_MAX = 3; // "only 20 places left"
export const MISTAKE_PROXIMITY_CHARS = 200; // "sent ... by mistake" -> "send it back", across sentences
export const CODE_PRONOUN_PROXIMITY_CHARS = 100; // "a code ... Please forward it to us", across sentences
export const MONEY_DIGITS_MAX = 15; // digits, commas and dots after the first digit of an amount
export const MONEY_SPACE_MAX = 3; // spaces between a currency marker, the number and "million"

// ---------------------------------------------------------------------------
// Text normalization (content detector only; link and identity detectors read the raw text)
// ---------------------------------------------------------------------------
// Leetspeak symbols mapped inside a token that also contains letters ("p@ssw0rd" -> "password").
// "1" maps to "i" ("w1n", "pr1ze", "b1tcoin"); plain numbers and amounts are never changed.
export const LEET_MAP = Object.freeze({ "@": "a", "0": "o", "1": "i", "$": "s", "3": "e", "5": "s" });
// "p a s s w o r d": at least this many single letters separated by single spaces become one word.
export const SPACED_LETTERS_MIN = 4;

// ---------------------------------------------------------------------------
// Benchmark (backend/engine/benchmark). Not used by score(); the regression test reads them.
// ---------------------------------------------------------------------------
export const BENCHMARK_DETECTED_MIN_SCORE = VERDICT_POOKIE_MAX + 1; // a scam scored "skeptical" or higher
export const BENCHMARK_STRONG_MIN_SCORE = VERDICT_SKEPTICAL_MAX + 1; // a scam scored "poltergeist"
export const BENCHMARK_MIN_DETECTION_RATE = 0.7; // dev set: share of scams detected
export const BENCHMARK_MAX_FALSE_ALARM_RATE = 0.1; // dev set: share of benign messages scored >= 31

// ---------------------------------------------------------------------------
// Typosquatting tuning
// ---------------------------------------------------------------------------
export const TYPO_SHORT_NAME_MAX_LEN = 6; // brand names this long or shorter use the short distance
export const TYPO_MAX_DISTANCE_SHORT = 1;
export const TYPO_MAX_DISTANCE_LONG = 2;
export const TYPO_MIN_FUZZY_LEN = 4; // brand names shorter than this are matched exactly only
export const TYPO_CONTAINS_MIN_LEN = 6; // "label contains brand name" rule needs a name this long

// IP address validation
export const IPV4_OCTET_MAX = 255;
export const IPV6_MIN_COLONS = 2;
export const IPV6_MAX_GROUPS = 8;
export const IPV6_MAX_GROUP_HEX_DIGITS = 4;

// ---------------------------------------------------------------------------
// Signal ids and categories
// ---------------------------------------------------------------------------
export const CATEGORY_IDENTITY_AUTH = "identity-auth";
export const CATEGORY_LINK = "link";
export const CATEGORY_CONTENT = "content";

export const SIGNAL_CATEGORY = Object.freeze({
  "typosquatting": CATEGORY_IDENTITY_AUTH,
  "homograph-punycode": CATEGORY_IDENTITY_AUTH,
  "display-name-mismatch": CATEGORY_IDENTITY_AUTH,
  "spf-fail": CATEGORY_IDENTITY_AUTH,
  "dkim-fail": CATEGORY_IDENTITY_AUTH,
  "dmarc-fail": CATEGORY_IDENTITY_AUTH,
  "raw-ip-url": CATEGORY_LINK,
  "risky-tld": CATEGORY_LINK,
  "link-text-mismatch": CATEGORY_LINK,
  "urgency-en": CATEGORY_CONTENT,
  "credential-request": CATEGORY_CONTENT,
  "suspicious-attachment": CATEGORY_CONTENT,
  "prize-lottery": CATEGORY_CONTENT,
  "advance-fee-scheme": CATEGORY_CONTENT,
  "financial-info-request": CATEGORY_CONTENT,
  "unusual-payment-method": CATEGORY_CONTENT,
  "secrecy-pressure": CATEGORY_CONTENT,
  "code-sharing-request": CATEGORY_CONTENT,
  "mistaken-payment": CATEGORY_CONTENT,
  "remote-access-request": CATEGORY_CONTENT,
  "defanged-link": CATEGORY_LINK,
  "delivery-scam": CATEGORY_CONTENT,
  "seed-phrase-request": CATEGORY_CONTENT,
  "investment-guarantee": CATEGORY_CONTENT,
  "task-job-scam": CATEGORY_CONTENT,
  "official-fine-threat": CATEGORY_CONTENT,
  "recruiter-bait": CATEGORY_CONTENT,
  "lookalike-lure-domain": CATEGORY_LINK,
  "utility-disconnection-threat": CATEGORY_CONTENT,
  "payment-failed-lure": CATEGORY_CONTENT,
  "account-security-lure": CATEGORY_CONTENT,
  "unfamiliar-link-pressure": CATEGORY_CONTENT,
});

export const CATEGORY_CAPS = Object.freeze({
  [CATEGORY_IDENTITY_AUTH]: CAP_IDENTITY_AUTH,
  [CATEGORY_LINK]: CAP_LINK,
  [CATEGORY_CONTENT]: CAP_CONTENT,
});

export const ALL_SIGNAL_IDS = Object.freeze(Object.keys(SIGNAL_CATEGORY));

// ---------------------------------------------------------------------------
// Word lists
// ---------------------------------------------------------------------------
// Requirement 2.6, extended in round 2 with endings common on throwaway lure domains.
export const RISKY_TLDS = Object.freeze([
  "xyz", "top", "click", "tk", "ml", "ga", "cf", "support", "online", "info", "site", "icu",
]);
export const DANGEROUS_EXTENSIONS = Object.freeze(["exe", "scr", "vbs", "bat", "cmd", "js", "lnk", "iso", "img"]);
export const JS_LIBRARY_ALLOWLIST = Object.freeze(["node", "react", "vue", "next", "nuxt", "express", "angular", "d3", "three"]);
export const SECOND_LEVEL_LABELS = Object.freeze(["com", "co", "org", "net", "gov", "edu", "ac"]); // used with 2-letter country TLDs, e.g. com.bd, co.uk
export const COUNTRY_TLD_LENGTH = 2;

// Defanged links ("evil[.]com", "evil dot com", "hxxps://"). " dot " only counts before one of
// these endings, so ordinary prose ("connect the dot") is left alone.
// Also the endings that make a bare "name.ending" count as a link for the content signals.
export const LINK_TLDS = Object.freeze([
  ...RISKY_TLDS,
  "com", "net", "org", "io", "info", "biz", "co", "me", "app", "site", "online", "live", "link",
  "shop", "store", "club", "vip", "pro", "cc", "ly", "gl", "gd", "to", "id", "at", "us", "uk",
  "in", "bd", "pk", "ru", "cn", "work", "support", "help", "page", "tech", "cloud",
  "example", "test", "invalid",
]);
// URL shorteners hide the real destination.
export const SHORTENER_DOMAINS = Object.freeze([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at",
  "tiny.cc", "rebrand.ly", "s.id", "t.ly", "buff.ly", "v.gd", "shorte.st", "bitly.com",
]);
// The spaced form "evil dot com" only counts before these endings (no English words such as
// "to", "in", "me", "us"), and never right after an article ("the dot com bubble").
export const SPACED_DOT_TLDS = Object.freeze([
  ...RISKY_TLDS, "com", "net", "org", "io", "info", "biz", "site", "online", "ly", "bd", "ru", "cn",
  "example", "test", "invalid",
]);
export const SPACED_DOT_NOT_AFTER = Object.freeze(["the", "a", "an", "of", "and", "or", "big", "old", "new", "first"]);
export const MAX_DEFANG_EVIDENCE_CHARS = 100; // characters kept on each side of a "[.]" in the evidence

export const URGENCY_EN_PHRASES = Object.freeze([
  "act now",
  "verify immediately",
  "account will be suspended",
  "account has been suspended",
  "account suspended",
  "confirm your details",
  "limited time",
  "expires today",
  "click here immediately",
  "immediate action required",
]);

// More urgency wording, matched in addition to URGENCY_EN_PHRASES (same signal, same weight).
export const URGENCY_EXTRA_PHRASES = Object.freeze([
  "urgent",
  "urgently",
  "final notice",
  "final warning",
  "pay now",
  "security breach",
  "virus detected",
  "viruses detected",
  "infected with",
  "or it will be returned",
  "or it will be deleted",
  "or it will be closed",
  "limited spots",
  "limited slots",
  "spots left",
  "slots left",
]);
// "to avoid arrest", "to avoid legal action", "to avoid permanent closure" ...
export const URGENCY_AVOID_THREATS = Object.freeze([
  "arrest",
  "a warrant",
  "legal action",
  "prosecution",
  "penalties",
  "suspension",
  "deactivation",
  "closure",
  "permanent closure",
  "losing",
]);
// "your account is temporarily locked", "access has been restricted", "we have frozen your account".
export const LOCKABLE_THINGS = Object.freeze(["account", "card", "access", "mailbox", "profile", "wallet"]);
export const LOCKED_WORDS = Object.freeze(["locked", "suspended", "frozen", "restricted", "blocked", "disabled", "deactivated"]);
export const LOCK_STATE_VERBS = Object.freeze(["is", "was", "has been", "have been", "will be", "is now", "is temporarily", "has been temporarily"]);
// "your computer has been infected", "device is compromised".
export const DEVICE_WORDS = Object.freeze(["computer", "device", "pc", "laptop", "phone", "system"]);
export const COMPROMISED_WORDS = Object.freeze(["infected", "hacked", "compromised"]);
// "within 24 hours", "within 30 minutes".
export const DEADLINE_UNITS = Object.freeze(["hours", "hour", "hrs", "minutes", "mins"]);
// Time limits added for the scam families: "within 2 days", "within 12 hr", "in 24 hrs".
// "in N ..." only counts for hours ("Your code expires in 10 minutes" is ordinary), and neither
// form counts after words that describe a service promise ("arrives in 24 hours",
// "processed within 3 days").
export const DEADLINE_EXTRA_UNITS = Object.freeze(["hr", "days", "day"]);
export const IN_DEADLINE_UNITS = Object.freeze(["hours", "hour", "hrs", "hr"]);
export const DEADLINE_NOT_AFTER = Object.freeze([
  "expire", "expires", "expiring", "valid", "arrive", "arrives", "arriving", "delivered", "processed",
  "refunded", "credited", "shipped", "ready", "back to you", "dispatched",
]);
// "only 20 places left".
export const SCARCITY_UNITS = Object.freeze(["spots", "places", "slots", "seats"]);
// "call ... immediately", "reply ... right away".
export const IMMEDIACY_VERBS = Object.freeze(["call", "contact", "reply", "respond", "act", "verify", "update", "confirm", "pay"]);
export const IMMEDIACY_WORDS = Object.freeze(["immediately", "right away", "asap"]);

// Prize and lottery bait. Matched as whole phrases, case-insensitive, flexible whitespace.
export const PRIZE_PHRASES = Object.freeze([
  "you have won",
  "you've won",
  "you are the winner",
  "you're the winner",
  "lucky winner",
  "claim your prize",
  "lottery",
  "jackpot",
  "free gift",
  "claim your free",
  "claim your reward",
  "you have been chosen",
  "guaranteed returns",
  "guaranteed return",
  "guaranteed profit",
  "guaranteed profits",
  "guaranteed income",
  "guaranteed loan",
  "guaranteed approval",
  "zero risk",
  "risk-free",
  "double your money",
  "no experience needed",
  "no experience required",
]);
// "400% returns", "30% profit".
export const RETURN_WORDS = Object.freeze(["returns", "return", "profit", "profits", "gains"]);
export const PERCENT_DIGITS_MIN = 2; // "5% interest" is ordinary; "400% returns" is not
export const PERCENT_DIGITS_MAX = 4;
// "$1,000,000" or "USD 15,500,000" written out in digits: at least this many ",000" groups.
export const LARGE_AMOUNT_THOUSANDS_GROUPS = 2;
// "congratulations" only counts when one of PRIZE_WORDS follows within PRIZE_PROXIMITY_CHARS.
export const CONGRATS_WORDS = Object.freeze(["congratulations", "congrats"]);
export const PRIZE_WORDS = Object.freeze(["won", "winner", "selected", "prize", "lottery", "jackpot"]);

// Money amounts: a currency marker plus million/billion ("$1 million", "USD 2.5 billion", "5 million dollars").
export const CURRENCY_SYMBOLS = Object.freeze(["$", "£", "€"]);
export const CURRENCY_CODES = Object.freeze(["us$", "usd", "gbp", "eur"]);
export const CURRENCY_WORDS = Object.freeze(["dollars", "pounds", "euros"]);
export const LARGE_AMOUNT_WORDS = Object.freeze(["million", "billion"]);

// Advance-fee (inheritance, "pay a fee to receive money") wording. "transfer of <money amount>"
// is matched as well, using the money pattern above.
export const ADVANCE_FEE_PHRASES = Object.freeze([
  "inheritance",
  "unclaimed funds",
  "unclaimed fund",
  "unclaimed money",
  "beneficiary",
  "processing fee",
  "release fee",
  "clearance fee",
  "pay a small fee to receive",
  "next of kin",
  "dormant account",
  "unclaimed deposit",
  "unclaimed estate",
  "unclaimed assets",
  "release the funds",
  "funds are released",
  "funds will be released",
  "redelivery fee",
  "customs fee",
  "customs charge",
  "clearance charge",
  "release charge",
  "activation fee",
  "upfront fee",
]);
// A fee presented as a condition for getting something: "unpaid customs charge", "just pay a
// small fee", "insurance deposit upfront to activate your loan", "cost of $650 before the funds
// are released". Same signal as the advance-fee phrases above.
export const ADVANCE_FEE_TERMS = Object.freeze(["fee", "fees", "charge", "charges", "cost", "deposit", "duty"]);
export const FEE_STATUS_BEFORE = Object.freeze(["unpaid", "outstanding", "overdue"]);
export const FEE_STATUS_AFTER = Object.freeze(["required", "outstanding", "pending", "unpaid"]);
export const FEE_MINIMIZERS = Object.freeze(["just", "only", "simply"]);
export const FEE_PAY_VERBS = Object.freeze(["pay", "cover", "send", "settle"]);
export const FEE_PURPOSES = Object.freeze([
  "receive",
  "release",
  "redeliver",
  "reschedule",
  "unlock",
  "activate",
  "claim",
  "process",
  "dispatch",
]);
export const FEE_ADVANCE_WORDS = Object.freeze(["upfront", "up front", "in advance"]);
export const RELEASE_WORDS = Object.freeze(["released", "delivered", "dispatched", "processed", "activated", "transferred"]);

// financial-info-request: a request verb followed, within REQUEST_PROXIMITY_CHARS in the same
// sentence, by a card or bank term, and not shortly after a negation ("never share your card number").
export const FINANCIAL_REQUEST_VERBS = Object.freeze([
  "enter",
  "provide",
  "send",
  "share",
  "confirm",
  "verify",
  "update",
  "reply with",
  "give",
  "submit",
  "type",
]);
export const FINANCIAL_INFO_TERMS = Object.freeze([
  "credit card",
  "debit card",
  "card number",
  "card details",
  "cvv",
  "cvc",
  "expiry date",
  "expiration date",
  "bank account",
  "bank details",
  "account number",
  "routing number",
  "ssn",
  "social security",
]);
export const NEGATION_WORDS = Object.freeze(["never", "not", "don't", "won't", "can't", "cannot"]);
// Words allowed between a negation and the verb it governs ("will never ASK YOU TO share").
export const NEGATION_HELPER_WORDS = Object.freeze([
  "ever",
  "ask",
  "asks",
  "asked",
  "request",
  "requests",
  "need",
  "needs",
  "require",
  "requires",
  "you",
  "to",
  "will",
  "would",
  "we",
  "be",
]);

// unusual-payment-method: a payment verb followed, within REQUEST_PROXIMITY_CHARS in the same
// sentence, by a hard-to-trace payment method. A mobile wallet only counts when a fee is mentioned.
export const PAYMENT_VERBS = Object.freeze([
  "pay",
  "paying",
  "payment",
  "send",
  "sending",
  "transfer",
  "buy",
  "buying",
  "purchase",
  "pick up",
  "get",
  "deposit",
  "settle",
  "return",
]);
export const PAYMENT_METHODS = Object.freeze([
  "gift card",
  "giftcard",
  "itunes card",
  "itunes gift card",
  "google play card",
  "google play gift card",
  "bitcoin",
  "btc",
  "crypto",
  "cryptocurrency",
  "usdt",
  "wire transfer",
  "western union",
  "moneygram",
  "usdc",
  "ethereum",
]);
// "wire the money to my agent": wiring money is itself a hard-to-trace method.
export const WIRE_OBJECTS = Object.freeze(["money", "funds", "payment", "amount"]);
// An explicit instruction to send the payment somewhere ("send it to me", "pay to this account",
// "send me the codes"). With unusual-payment-method it lifts the score to FLOOR_UNUSUAL_PAYMENT.
export const INSTRUCTION_VERBS = Object.freeze(["send", "pay", "transfer", "wire", "deposit"]);
export const INSTRUCTION_TARGETS = Object.freeze([
  "me",
  "us",
  "my",
  "our",
  "this",
  "the following",
  "the name",
  "the account",
  "the wallet",
  "the address",
]);
export const INSTRUCTION_PROXIMITY_CHARS = 40;
export const HAND_OVER_VERBS = Object.freeze(["send", "give", "read", "text"]);
export const HAND_OVER_OBJECTS = Object.freeze(["code", "codes", "number", "numbers", "pin", "pins", "picture", "pictures", "photo", "photos"]);
export const MOBILE_WALLET_TERMS = Object.freeze(["mobile wallet", "mobile money", "e-wallet", "ewallet"]);
export const FEE_WORDS = Object.freeze(["fee", "fees"]);

export const SECRECY_PHRASES = Object.freeze([
  "do not tell anyone",
  "don't tell anyone",
  "do not tell anybody",
  "don't tell anybody",
  "keep this confidential",
  "keep this secret",
  "keep this between us",
  "keep it confidential",
  "keep it secret",
  "do not share this with anyone",
  "don't share this with anyone",
  "do not discuss this with anyone",
]);
// "do not discuss this with your family", "don't tell your kids", "don't tell Mom and Dad".
export const SECRECY_NEGATIONS = Object.freeze(["do not", "don't", "please don't", "please do not"]);
export const SECRECY_VERBS = Object.freeze(["tell", "discuss this with", "discuss it with", "mention this to", "mention it to"]);
export const SECRECY_PEOPLE = Object.freeze([
  "your family",
  "your kids",
  "your children",
  "your parents",
  "your bank",
  "your husband",
  "your wife",
  "your partner",
  "your friends",
  "family",
  "mom",
  "dad",
  "mum",
]);

// code-sharing-request: a request to pass on a code that was sent to you (one-time passcode theft).
export const CODE_SHARE_VERBS = Object.freeze(["reply with", "send", "share", "forward", "tell", "give", "read", "text"]);
export const CODE_TERMS = Object.freeze([
  "verification code",
  "security code",
  "confirmation code",
  "login code",
  "sign-in code",
  "access code",
  "sms code",
  "one-time code",
  "one time code",
  "one-time password",
  "one time password",
  "one-time passcode",
  "passcode",
]); // "OTP" alone stays a credential-request (case-sensitive), so "Send the OTP" is not double-counted
export const CODE_DIGIT_LENGTH_MAX = 2; // "6-digit code"
export const CODE_PRONOUNS = Object.freeze(["it", "this", "that", "them"]);
export const CODE_RECIPIENTS = Object.freeze(["us", "me"]);
// "the code we texted you", "the code I just sent to you": a code that was sent to the reader.
export const CODE_SENDERS = Object.freeze(["we", "i"]);
export const CODE_SENT_VERBS = Object.freeze(["texted", "sent", "messaged", "emailed"]);

// code-sharing-request, secret-code family. Secrets that only count with a hand-over context
// (a recipient or "reply with"), so "Send the OTP" alone stays a plain credential-request:
//   "Send us your password and otp", "give us your login password, PIN and the 2FA code",
//   "Please send your OTP to this number", "Reply with your PIN".
export const SECRET_CODE_TERMS = Object.freeze([
  "otp",
  "otp code",
  "2fa code",
  "2-step code",
  "two-factor code",
  "authentication code",
  "authenticator code",
  ...CODE_TERMS,
]);
// "pin" is an ordinary word ("pin this post"); it is a secret only after one of these words
// ("your PIN", "card pin", "password, PIN and ...") or before "code"/"number".
export const PIN_OWNERS = Object.freeze(["your", "account", "card", "banking", "atm", "and", "or"]);
export const PIN_SUFFIXES = Object.freeze(["code", "number"]);
// Verbs that hand something over. "reply with"/"respond with" already point back at the sender.
export const SECRET_HAND_OVER_VERBS = Object.freeze([
  "send",
  "share",
  "give",
  "tell",
  "provide",
  "forward",
  "read out",
  "read",
  "text",
  "email",
]);
export const SELF_ADDRESSED_VERBS = Object.freeze(["reply with", "respond with"]);
// Who receives it: "send US ...", "... to THIS NUMBER".
export const SECRET_RECIPIENTS = Object.freeze([
  "us",
  "me",
  "them",
  "him",
  "her",
  "our team",
  "our agent",
  "our officer",
  "our staff",
  "the agent",
  "the officer",
  "this number",
  "this email",
  "this address",
]);
export const SECRET_RECIPIENT_PROXIMITY_CHARS = 30; // "your OTP" -> "to this number"
// Verb -> secret gap, counted in words (about REQUEST_PROXIMITY_CHARS characters), same sentence;
// commas are allowed so a list such as "your password, PIN and OTP" stays one gap.
export const SECRET_GAP_WORDS_MAX = 8;
// A gap that starts a new clause is not "verb -> object": "Tell us IF you did not get your OTP".
export const GAP_STOP_WORDS = Object.freeze([
  "if",
  "whether",
  "when",
  "how",
  "why",
  "what",
  "where",
  "about",
  "after",
  "before",
  "once",
  "unless",
  "because",
]);

// A code being delivered ("Your OTP is 482913", "one-time password: 5590") is not a request.
// Credential words inside such a notice do not fire credential-request.
export const DELIVERED_CODE_TERMS = Object.freeze([...SECRET_CODE_TERMS, "pin", "code"]);
export const DELIVERED_CODE_DIGITS_MIN = 4;
export const DELIVERED_CODE_DIGITS_MAX = 10;

// credential-request (round 3): a bare credential word (password, PIN, OTP, username, one-time
// code) only counts when a request verb addressed to the reader comes before it in the same
// sentence, within CREDENTIAL_REQUEST_PROXIMITY_CHARS: "Send us your password", "read out the PIN".
// A notice ("Your password was changed", "a new OTP was sent", "your passwords are at risk") has
// no such verb and does not fire.
export const CREDENTIAL_REQUEST_PROXIMITY_CHARS = 80;
export const CREDENTIAL_REQUEST_VERBS = Object.freeze([
  "enter",
  "re-enter",
  "provide",
  "send",
  "share",
  "confirm",
  "verify",
  "update",
  "submit",
  "type",
  "input",
  "key in",
  "fill in",
  "give",
  "tell",
  "reply",
  "read out",
  "read back",
  "read me",
  "text",
  "email",
  "forward",
  "disclose",
  "validate",
]);
// "log in" / "sign in" is an instruction ("Log in here to keep your account"), except when it is a
// noun: after one of these words ("a login from a new device", "unusual sign in") or before one
// of the words after it ("login attempt", "sign in activity").
export const LOGIN_NOUN_BEFORE = Object.freeze([
  "a",
  "an",
  "the",
  "new",
  "unusual",
  "recent",
  "suspicious",
  "successful",
  "failed",
  "unrecognized",
  "unknown",
  "last",
]);
export const LOGIN_NOUN_AFTER = Object.freeze([
  "activity",
  "attempt",
  "attempts",
  "alert",
  "alerts",
  "from",
  "detected",
  "notification",
  "notifications",
  "was",
  "history",
]);

// Floor 4.16 (context.secretRequest): an instruction to the reader to hand over a secret.
// Instruction = the verb opens a sentence or clause (after optional "please", "kindly"...), or
// follows "you must / you need to / we need you to".
export const SECRET_REQUEST_VERBS = Object.freeze([
  "send",
  "share",
  "give",
  "tell",
  "reply with",
  "read out",
  "email",
  "text",
  "forward",
]);
export const SECRET_REQUEST_TERMS = Object.freeze([
  "password",
  "passwords",
  "passcode",
  "login details",
  "login credentials",
  "login information",
  "login info",
  "log-in details",
  "sign-in details",
  "security answer",
  "security answers",
  "security question answer",
  "memorable answer",
  "memorable word",
]); // plus "pin" with the PIN_OWNERS / PIN_SUFFIXES rule above
// "password reset link", "password manager": the word names something else, not the secret.
export const PASSWORD_NOT_SECRET_AFTER = Object.freeze([
  "reset",
  "hint",
  "hints",
  "manager",
  "managers",
  "change",
  "strength",
  "tips",
  "policy",
  "requirements",
  "link",
]);
export const PASSWORD_NOT_SECRET_BEFORE = Object.freeze(["new", "temporary", "strong"]); // "Send me a new password"
export const INSTRUCTION_LEAD_INS = Object.freeze([
  "please",
  "kindly",
  "just",
  "simply",
  "now",
  "so",
  "then",
  "and",
  "also",
  "quickly",
]);
export const INSTRUCTION_LEAD_INS_MAX = 2;
export const INSTRUCTION_MODALS = Object.freeze([
  "you must",
  "you need to",
  "you have to",
  "you should",
  "you are required to",
  "we need you to",
  "i need you to",
  "we want you to",
  "i want you to",
]);
// Words between the verb (and its recipient) and the secret: "send us YOUR LOGIN password".
export const SECRET_REQUEST_GAP_WORDS = 5;

// mistaken-payment: "I sent you money by mistake, please send it back".
export const MISTAKE_ADVERBS = Object.freeze(["accidentally", "mistakenly", "wrongly"]);
export const MISTAKE_PHRASES = Object.freeze(["by mistake", "by accident", "in error", "accidentally", "mistakenly"]);
export const MONEY_MOVED_VERBS = Object.freeze(["sent", "transferred", "paid", "credited", "deposited"]);
export const MISTAKE_CLAIMS = Object.freeze(["duplicate payment", "overpaid", "overpayment"]);
export const RETURN_REQUESTS = Object.freeze([
  "send it back",
  "send the money back",
  "send back",
  "return it",
  "return the money",
  "return the excess",
  "return the amount",
  "return the difference",
  "refund it",
  "refund the",
  "pay it back",
  "transfer it back",
  "transfer it to",
]);

// remote-access-request: "install the remote support tool", "give the agent access to your PC".
export const INSTALL_VERBS = Object.freeze(["install", "download", "run", "open"]);
export const REMOTE_TOOL_WORDS = Object.freeze(["remote", "screen-sharing", "screen sharing"]);
export const TOOL_WORDS = Object.freeze(["tool", "app", "application", "software", "program"]);
export const ACCESS_TARGETS = Object.freeze(["computer", "pc", "device", "laptop", "phone", "screen"]);

// ---------------------------------------------------------------------------
// Scam families (content detector). Each signal needs several cues in the same message; a single
// word never fires it. Phrases are matched on the normalized text, whole words only.
// ---------------------------------------------------------------------------
// delivery-scam: a parcel context + a failure or "update your delivery details" + a link.
export const DELIVERY_CONTEXT_WORDS = Object.freeze([
  "parcel", "parcels", "package", "packages", "courier", "shipment", "shipments", "delivery",
  "deliveries", "consignment", "shipping", "tracking", "redelivery",
]);
export const DELIVERY_ITEMS = Object.freeze(["parcel", "package", "shipment", "delivery", "consignment", "item", "order"]);
export const DELIVERY_FAILED_STATES = Object.freeze([
  "failed", "unsuccessful", "on hold", "held", "suspended", "undeliverable",
]);
export const DELIVERY_NOT_DELIVERED = Object.freeze([
  "could not be delivered", "couldn't be delivered", "cannot be delivered", "can't be delivered",
  "was not delivered", "wasn't delivered", "has not been delivered", "unable to deliver",
  "could not deliver", "couldn't deliver", "failed to deliver", "delivery attempt failed",
  "returned to sender", "return to sender",
]);
export const DELIVERY_ADDRESS_PROBLEMS = Object.freeze([
  "incomplete", "incorrect", "invalid", "wrong", "missing", "unconfirmed", "insufficient", "unclear",
]);
export const DELIVERY_UPDATE_VERBS = Object.freeze(["update", "confirm", "verify", "correct", "reschedule", "re-schedule", "complete"]);
export const DELIVERY_DETAILS = Object.freeze([
  "shipping details", "shipping information", "shipping info", "shipping address",
  "delivery details", "delivery information", "delivery info", "delivery address", "delivery",
  "redelivery", "address details", "address", "shipping",
]);

// seed-phrase-request: a request verb + a wallet secret ("Re-sync your 12-word recovery phrase").
export const SEED_REQUEST_VERBS = Object.freeze([
  "enter", "re-enter", "sync", "re-sync", "resync", "validate", "verify", "confirm", "submit",
  "provide", "share", "send", "type", "input", "import", "restore", "paste", "update", "upload",
  "give", "reply with", "connect",
]);
// "you can restore your wallet with your seed phrase" explains, it does not ask.
export const SEED_NOT_AFTER = Object.freeze(["can", "could", "cannot", "can't", "will", "won't", "able to"]);
export const SEED_TERMS = Object.freeze([
  "recovery phrase", "seed phrase", "secret phrase", "secret recovery phrase", "mnemonic phrase",
  "mnemonic", "backup phrase", "wallet phrase", "passphrase", "private key", "private keys",
  "seed words", "recovery words", "secret words", "recovery seed", "wallet seed",
]);
export const SEED_WORD_COUNTS = Object.freeze(["12", "18", "24", "twelve", "eighteen", "twenty-four"]);
// "Validate your wallet at <link>": wallet "fixing" always ends at a page that asks for the phrase.
export const WALLET_FIX_VERBS = Object.freeze([
  "re-sync", "resync", "sync", "validate", "rectify", "restore", "reactivate", "unlock", "recover",
  "verify", "connect", "reconnect", "migrate",
]);
export const WALLET_WORDS = Object.freeze(["wallet", "wallets", "metamask", "trustwallet", "trust wallet"]);

// investment-guarantee: a promise of big or certain returns + a trading/signals context.
export const INVESTMENT_PROMISE_PHRASES = Object.freeze([
  "guaranteed returns", "guaranteed return", "guaranteed profit", "guaranteed profits",
  "guaranteed income", "guaranteed trades", "guaranteed trade", "guaranteed gains",
  "guaranteed payout", "guaranteed payouts", "guaranteed wins", "guaranteed signals",
  "100% guaranteed", "100% profit", "risk-free", "risk free", "zero risk",
  "double your money", "double your investment", "double your crypto", "double your bitcoin",
]);
export const GUARANTEE_WORDS = Object.freeze(["guaranteed", "guarantee", "assured"]);
// "does not guarantee future returns", "there are no guaranteed returns" are warnings.
export const PROMISE_NEGATIONS = Object.freeze([
  "no", "not", "never", "without", "don't", "doesn't", "can't", "cannot", "won't", "nothing is",
]);
export const INVESTMENT_RESULT_WORDS = Object.freeze([
  "returns", "return", "profit", "profits", "trades", "trade", "gains", "payout", "payouts", "wins",
  "income", "earnings", "signals",
]);
export const MULTIPLY_VERBS = Object.freeze(["turn", "grow", "flip", "convert", "multiply"]);
export const RETURN_PERIODS = Object.freeze(["daily", "per day", "a day", "weekly", "per week", "a week", "every day"]);
export const INVESTMENT_CONTEXT_PHRASES = Object.freeze([
  "signals group", "signal group", "trading signals", "crypto signals", "vip group", "vip channel",
  "vip signals", "vip crypto", "crypto", "cryptocurrency", "bitcoin", "btc", "usdt", "forex",
  "futures", "binary options", "trading", "invest", "investment", "investing",
  "mining pool", "dm admin", "message admin", "contact admin", "inbox admin", "account manager",
]);
// Money with a currency marker on either side: "$200", "3,500 BDT", "5000 taka", "38k USDT".
// (English-only: the taka sign is in the Bengali block, so it is written as BDT/tk/taka.)
export const MONEY_SYMBOLS = Object.freeze(["$", "£", "€", "₹"]);
export const MONEY_CODES = Object.freeze([
  "usd", "usdt", "bdt", "tk", "taka", "inr", "rs", "dollars", "euros", "pounds", "btc", "eth",
]);
export const AMOUNT_DIGITS_MAX = 12; // digits, commas and dots after the first digit

// task-job-scam: paid "like videos" / "rate products" tasks, trial tasks, "reply YES".
export const TASK_PAY_VERBS = Object.freeze(["earn", "earning", "make", "get", "receive", "paid", "income of", "salary of"]);
export const TASK_PAY_PERIODS = Object.freeze([
  "per day", "a day", "daily", "each day", "every day", "per hour", "an hour", "hourly",
  "per task", "each task", "a task", "per order", "per video", "per like", "per review",
  "per week", "a week", "weekly",
]);
export const TASK_EASY_PHRASES = Object.freeze([
  "work from home", "working from home", "from home", "from your phone", "from your mobile",
  "part-time", "part time", "no experience", "flexible hours", "spare time", "free time",
  "a few minutes", "few minutes a day",
]);
export const TASK_TIME_UNITS = Object.freeze(["mins", "min", "minutes", "hours", "hour", "hrs", "hr"]);
// "like", "follow" and "watch" alone are too common ("an app like this", "watch this video").
export const TASK_ACTIONS = Object.freeze([
  "likes", "liking", "subscribe to", "subscribing to", "rate", "rating", "review", "reviewing",
  "boost", "boosting",
]);
export const TASK_OBJECTS = Object.freeze([
  "videos", "video", "posts", "post", "products", "product", "hotels", "hotel", "apps", "app",
  "channels", "channel", "pages", "page", "reels", "songs", "movies", "restaurants",
]);
export const TASK_WORKER_PHRASES = Object.freeze([
  "video likers", "video liker", "youtube likers", "tiktok likers", "likers", "product reviewers",
  "app reviewers", "online reviewers", "trial task", "trial tasks", "simple tasks", "simple task",
  "online tasks", "daily tasks", "easy tasks", "first task", "task-based", "commission per task",
  "prepaid task", "prepaid tasks",
]);
// "Reply YES", "text 'OK'", "respond with START" (quotes allowed), or a move to a chat app.
export const TASK_REPLY_VERBS = Object.freeze(["reply", "text", "send", "respond with", "reply with", "type"]);
export const TASK_REPLY_WORDS = Object.freeze(["yes", "y", "ok", "interested", "start", "job"]);
export const TASK_CHAT_PHRASES = Object.freeze([
  "whatsapp us", "message us on whatsapp", "contact us on whatsapp", "contact us on telegram",
  "add us on telegram", "add me on whatsapp", "add me on telegram", "join our telegram", "dm us", "dm me",
]);

// official-fine-threat: authority/fine + pay + (deadline or legal threat) + a link.
export const FINE_TERMS = Object.freeze([
  "fine", "fines", "violation", "violations", "penalty", "penalties", "traffic", "tax", "taxes",
  "customs", "police", "brta", "btrc", "court", "toll", "tolls", "challan", "e-challan",
  "citation", "summons", "parking ticket", "traffic ticket", "speeding", "nbr", "income tax",
  "dmv", "vehicle registration",
]);
export const FINE_PAY_VERBS = Object.freeze(["pay", "settle", "clear", "payment"]);
export const FINE_LEGAL_THREATS = Object.freeze([
  "legal action", "legal proceedings", "arrest", "warrant", "prosecution", "court case",
  "license suspension", "licence suspension", "license will be suspended", "licence will be suspended",
  "vehicle will be seized", "seizure", "additional penalties", "additional charges", "late fees",
  "blacklisted", "case will be filed",
]);
export const FINE_DEADLINE_WORDS = Object.freeze(["today", "immediately", "by tomorrow", "by midnight", "tonight", "asap"]);

// recruiter-bait: unsolicited recruiter + a job + a doc/brief/form on an unfamiliar link.
export const RECRUITER_INTROS = Object.freeze(["i'm", "i am", "this is", "my name is", "it's"]);
export const RECRUITER_INTRO_LINKS = Object.freeze(["from", "at", "with", "of", "representing"]);
export const RECRUITER_TITLES = Object.freeze([
  "recruiter", "recruiting", "talent acquisition", "talent partner", "talent team", "hiring manager",
  "hiring team", "hr team", "hr manager", "headhunter", "staffing", "recruitment",
]);
export const JOB_WORDS = Object.freeze([
  "opening", "openings", "role", "roles", "position", "positions", "vacancy", "vacancies", "job",
  "opportunity", "opportunities", "hiring",
]);
export const JOB_DOC_WORDS = Object.freeze([
  "brief", "job brief", "job description", "jd", "doc", "docs", "document", "portfolio", "form",
  "application form", "assessment", "test task", "offer letter", "role details", "questionnaire",
]);
// Path or hostname parts that carry the same meaning: "docs-share-view.com/role-402".
export const JOB_DOC_LINK_PARTS = Object.freeze([
  "doc", "docs", "brief", "form", "forms", "role", "job", "jobs", "career", "careers", "portfolio", "apply", "hiring", "cv",
]);
// Job sites people expect a recruiter to use; a link there is not "unfamiliar".
export const RECRUITER_TRUSTED_DOMAINS = Object.freeze([
  "linkedin.com", "indeed.com", "glassdoor.com", "bdjobs.com", "wellfound.com", "lever.co",
  "greenhouse.io", "workable.com", "myworkdayjobs.com",
]);

// lookalike-lure-domain: a registrable label made of 2+ hyphen-joined lure words
// ("secure-login-help", "billing-update-verify"). Only the label just before the public suffix
// counts, so a subdomain of a real company ("billing-help.example.com") is left alone.
export const LURE_WORDS = Object.freeze([
  "verify", "verification", "secure", "security", "login", "signin", "update", "billing", "payment",
  "pay", "account", "support", "help", "portal", "check", "restore", "sync", "claim", "refund", "track",
  "tracking", "parcel", "wallet", "utility", "tax", "fine", "confirm", "recovery", "recover", "unlock",
  "auth", "reset", "card", "bill", "delivery", "redelivery", "customs", "session", "alert",
  // round 3: official-sounding words seen in fee, grant and re-registration lures
  "kyc", "sim", "nid", "tin", "vfs", "visa", "grant", "badge", "loan", "scholarship", "appeal", "relief",
  "reg", "booking", "bd",
]);
export const LURE_WORDS_MIN = 2;
// Ordinary domains that happen to match the lure-word pattern (registrable domain, lowercase).
// The default brands' domains are skipped as well (detectors/link.js).
export const LOOKALIKE_SAFE_DOMAINS = Object.freeze([]);

// unfamiliar-link-pressure (round 3): a link whose registrable domain is unfamiliar (a shortener,
// a raw IP, a risky TLD, a label with UNFAMILIAR_MIN_HYPHENS hyphens, or a hyphenated label with a
// lure word) AND pressure language in the text (a deadline, a threat to an account or service, a
// fee or payment ask, or a verify/claim ask). Well-known real domains never count.
export const UNFAMILIAR_MIN_HYPHENS = 2; // "foo-bar-baz.com"
export const UNFAMILIAR_SAFE_DOMAINS = Object.freeze([
  "google.com", "microsoft.com", "linkedin.com", "facebook.com", "instagram.com", "apple.com",
  "amazon.com", "paypal.com", "bkash.com", "nagad.com.bd", "grameenphone.com", "robi.com.bd",
  "example.com", "example.org",
]);
export const PRESSURE_DEADLINE_PHRASES = Object.freeze([
  "today", "tonight", "before midnight", "by midnight", "expires", "expire", "expiring", "expiry",
  "final notice", "last chance",
]);
export const PRESSURE_DEADLINE_UNITS = Object.freeze(["hours", "hour", "hrs", "hr", "minutes", "minute", "mins", "min", "days", "day"]);
export const PRESSURE_THREAT_WORDS = Object.freeze([
  "restricted", "restriction", "suspended", "suspension", "deactivated", "deactivation", "unpublished",
  "blocked", "frozen", "legal action", "penalty", "penalties",
]);
export const PRESSURE_ASK_WORDS = Object.freeze([
  "fee", "fees", "pay", "deposit", "settle", "verify", "re-verify", "appeal", "claim",
  "update your details", "nid",
]);

// utility-disconnection-threat: utility + disconnection + unpaid bill + a link or "pay now".
export const UTILITY_WORDS = Object.freeze([
  "electricity", "electric", "power", "gas", "water", "internet", "broadband", "wifi", "wi-fi",
  "line", "connection", "meter", "supply",
]);
export const DISCONNECT_PHRASES = Object.freeze([
  "disconnection", "disconnected", "disconnect", "cut off", "cut-off", "cutoff", "shut off",
  "shutoff", "switched off", "terminated", "termination",
]);
// "suspended" only counts with a time word right after it ("suspended tonight").
export const DISCONNECT_SOFT_WORDS = Object.freeze(["suspended", "stopped", "blocked"]);
export const DISCONNECT_TIME_WORDS = Object.freeze(["tonight", "today", "within", "in", "by"]);
export const UNPAID_WORDS = Object.freeze(["unpaid", "overdue", "outstanding", "pending", "non-payment", "nonpayment"]);
export const BILL_WORDS = Object.freeze(["bill", "bills", "dues", "balance", "payment", "amount", "charges", "invoice"]);
// "Clear dues now", "pay now", "pay immediately": a direct order to pay right away.
export const PAY_NOW_VERBS = Object.freeze(["pay", "clear", "settle", "recharge"]);
export const PAY_NOW_WORDS = Object.freeze(["now", "immediately", "today", "tonight", "right away", "asap"]);
export const PAY_NOW_GAP_WORDS = 3; // "clear your dues now", "pay the bill immediately"

// payment-failed-lure: a failed payment + "update your payment details".
export const PAYMENT_SUBJECTS = Object.freeze([
  "payment", "billing", "subscription", "renewal", "transaction", "charge", "auto-renewal", "autopay",
]);
export const PAYMENT_FAILED_STATES = Object.freeze([
  "failed", "was declined", "has been declined", "declined", "was unsuccessful", "unsuccessful",
  "could not be processed", "couldn't be processed", "did not go through", "didn't go through",
  "was rejected", "has failed", "bounced",
]);
export const CARD_FAILED_STATES = Object.freeze(["declined", "expired", "rejected"]);
export const PAYMENT_UPDATE_VERBS = Object.freeze([
  "update", "verify", "re-enter", "reenter", "confirm", "re-confirm", "reconfirm", "re-add", "replace", "fix",
]);
export const PAYMENT_DETAIL_WORDS = Object.freeze([
  "payment method", "payment methods", "payment details", "payment information", "payment info",
  "billing details", "billing information", "billing info", "billing method", "billing address",
  "card details", "card information", "card info", "payment card", "card",
]);
// "or your account will be deleted", "account will be permanently closed".
export const ACCOUNT_THREAT_THINGS = Object.freeze(["account", "subscription", "membership", "service", "profile", "plan"]);
export const ACCOUNT_THREAT_STATES = Object.freeze([
  "deleted", "suspended", "closed", "cancelled", "canceled", "terminated", "deactivated", "removed", "locked",
]);

// account-security-lure: a sign-in alert + an order to cancel/secure it + a lookalike link.
export const LOGIN_ACTORS = Object.freeze([
  "someone", "somebody", "an unknown person", "an unknown user", "an unknown device", "a stranger",
]);
export const LOGIN_VERBS = Object.freeze([
  "logged in", "logged into", "signed in", "signed into", "accessed", "tried to log in",
  "tried to sign in", "attempted to log in", "attempted to sign in",
]);
export const LOGIN_ODD_WORDS = Object.freeze([
  "unusual", "suspicious", "unrecognized", "unrecognised", "unknown", "unauthorized", "unauthorised", "strange",
]);
export const LOGIN_EVENTS = Object.freeze([
  "sign-in", "sign in", "signin", "login", "log-in", "log in", "activity", "access", "session",
  "sessions", "device", "login attempt", "sign-in attempt",
]);
export const SECURE_VERBS = Object.freeze([
  "cancel", "secure", "verify", "review", "terminate", "end", "block", "stop", "revoke", "confirm",
  "deny", "report", "lock", "protect", "sign out", "log out",
]);
export const SECURE_OBJECTS = Object.freeze([
  "session", "sessions", "login", "sign-in", "sign in", "access", "account", "device", "activity",
  "request", "attempt",
]);

// Job fee (advance-fee-scheme, floor 4.26): a fee asked before starting a job.
export const JOB_FEE_KINDS = Object.freeze([
  "onboarding", "registration", "training", "verification", "joining", "enrollment", "enrolment",
  "application", "security", "background check", "uniform", "kit", "placement", "refundable",
]);
export const JOB_FEE_WORDS = Object.freeze(["fee", "fees", "deposit", "charge", "charges", "payment", "cost"]);
export const JOB_SLOT_VERBS = Object.freeze(["lock", "secure", "reserve", "hold", "book"]);
export const JOB_SLOT_WORDS = Object.freeze(["slot", "seat", "spot", "position", "place", "offer", "role"]);
// "There is no registration fee", "we never charge an onboarding fee".
export const JOB_FEE_NEGATIONS = Object.freeze(["no", "zero", "without", "free", "never charge", "never charge a", "never charge an", "not charge", "no hidden"]);
// The job context: JOB_WORDS and RECRUITER_TITLES plus these.
export const JOB_CONTEXT_EXTRA = Object.freeze([
  "hire", "hired", "hiring", "recruit", "onboarding", "interview", "salary", "job offer",
  "employment", "internship", "shortlisted",
]);

// task-job-scam, remote-work path: remote/data-entry/review work + daily/weekly pay + "no
// experience" + contact through a chat app.
export const REMOTE_WORK_PHRASES = Object.freeze([
  "remote", "data entry", "data-entry", "typing job", "typing jobs", "product review", "product reviews",
  "online job", "online jobs", "online work", "home-based", "home based", "work from home", "from home",
]);
export const REMOTE_PAY_PERIODS = Object.freeze([
  "daily", "per day", "a day", "each day", "every day", "weekly", "per week", "a week", "each week",
]);
export const REMOTE_PAY_VERBS = Object.freeze([
  "earn", "earning", "make", "get", "receive", "paid", "paying", "pays", "income of", "salary of", "salary",
]);
export const NO_EXPERIENCE_WORDS = Object.freeze(["experience", "skills", "qualification", "qualifications", "degree"]);
export const NO_EXPERIENCE_FILLERS = Object.freeze(["prior", "previous", "special", "work", "relevant", "formal"]);
export const CHAT_APPS = Object.freeze(["telegram", "whatsapp", "signal", "wechat", "viber", "imo"]);
export const CHAT_CONTACT_VERBS = Object.freeze([
  "message", "contact", "text", "dm", "reach", "chat with", "add", "join", "ping", "inbox", "write to", "talk to",
]);
export const CHAT_PROXIMITY_CHARS = 30; // "message our HR team on Telegram"

// ---------------------------------------------------------------------------
// Plain-English explanations (design: "Plain-English Explanations" table).
// "{e}" is replaced by the flag's evidence.
// ---------------------------------------------------------------------------
export const EVIDENCE_PLACEHOLDER = "{e}";

export const EXPLANATION_TEMPLATES = Object.freeze({
  "typosquatting":
    'The web address "{e}" looks almost like a well-known company\'s address but is spelled slightly differently. Scammers use look-alike addresses to make a fake site look real.',
  "homograph-punycode":
    'The web address "{e}" uses unusual characters that imitate normal letters. Scammers use them to make a fake address look genuine.',
  "display-name-mismatch":
    "The sender's name claims to be a company, but the email address it came from belongs to someone else. Scammers pretend to be companies this way.",
  "spf-fail":
    "The email failed the check that confirms the sender is allowed to use that address. This often means the sender is faking who they are.",
  "dkim-fail":
    "The email's tamper-proof stamp did not check out, so the message may have been faked or changed on the way to you.",
  "dmarc-fail":
    "The sender's own safety rules say this message should not be trusted, which suggests it is not really from them.",
  "raw-ip-url":
    'The link "{e}" goes to a string of numbers instead of a normal website name. Real companies almost never do this, and scammers use it to hide where the link leads.',
  "risky-tld":
    'The link "{e}" ends in an address ending that is often used by throwaway scam websites. This alone is not proof, but be careful.',
  "link-text-mismatch":
    "The link shows one website but actually opens a different one ({e}). Scammers do this to hide the real destination.",
  "urgency-en":
    'The message pressures you to act quickly ("{e}"). Scammers rush people so they do not stop to check.',
  "credential-request":
    'The message asks for a password, PIN or one-time code ("{e}"). Real companies do not ask for these in messages.',
  "suspicious-attachment":
    'The message mentions a file called "{e}", a type of file that can install harmful programs. Do not open it unless you are sure who sent it.',
  "prize-lottery":
    'The message says you have won a prize or a large sum of money, or promises guaranteed or easy money ("{e}"). Scammers promise prizes and big returns so you hand over money or personal details. You cannot win a draw you never entered.',
  "advance-fee-scheme":
    'The message talks about an inheritance, unclaimed money, or a fee you must pay first to receive money, a parcel, a loan or a job ("{e}"). This is a well-known scam: you pay the fee and the promised thing never arrives.',
  "financial-info-request":
    'The message asks you to give your card or bank details ("{e}"). Real banks and shops do not ask for these in a message, and anyone who has them can take your money.',
  "unusual-payment-method":
    'The message asks you to pay with gift cards, cryptocurrency or a money-transfer service ("{e}"). Scammers ask for these because the money is hard to trace and almost never comes back.',
  "secrecy-pressure":
    'The message tells you to keep it secret ("{e}"). Scammers do this so nobody you trust can warn you.',
  "code-sharing-request":
    'The message asks you to pass on a code that was sent to you ("{e}"). That code is the key to your account: whoever has it can sign in as you or approve payments.',
  "mistaken-payment":
    'The message says money was sent to you by mistake and asks you to send it back ("{e}"). This is a common trick: the first payment is fake or gets reversed, and the money you send is lost.',
  "remote-access-request":
    'The message asks you to install a remote-control program or give someone access to your device ("{e}"). Whoever controls your device can see your screen, your passwords and your bank.',
  "delivery-scam":
    'The message says a parcel could not be delivered or asks you to update delivery details through a link ("{e}"). This is one of the most common text scams: the link leads to a fake page that takes your card details or a "redelivery fee".',
  "seed-phrase-request":
    'The message asks for your wallet recovery phrase or private key ("{e}"). Anyone who has those words owns your crypto. No wallet, exchange or support team ever needs them.',
  "investment-guarantee":
    'The message promises guaranteed or multiplied returns from trading or a "signals" group ("{e}"). Real investments never guarantee profit; these groups take your deposit and disappear.',
  "task-job-scam":
    'The message offers easy pay for simple online tasks such as liking videos or rating products ("{e}"). These "jobs" pay a little at first, then ask you to deposit money to unlock bigger tasks, and the money is gone.',
  "official-fine-threat":
    'The message claims you owe a fine, tax or penalty and must pay through a link quickly or face legal action ("{e}"). Government offices do not collect fines through links in text messages. Check on the official website or app yourself.',
  "recruiter-bait":
    'A stranger offers you a job and sends a "brief" or form on an unfamiliar link ("{e}"). Fake recruiters use these links to steal logins or install harmful files. Check the company and the recruiter yourself first.',
  "lookalike-lure-domain":
    'The web address "{e}" is stitched together from words like "secure", "verify", "billing" or "pay". Real companies use their own name as their address; throwaway scam sites use words like these to look official.',
  "utility-disconnection-threat":
    'The message threatens to cut off your electricity, gas, water or internet over an unpaid bill and pushes you to pay right away ("{e}"). Utility companies do not collect bills through links in text messages. Check your bill in the official app or office.',
  "payment-failed-lure":
    'The message says a payment failed and asks you to re-enter your card or billing details through a strange link or under a deadline ("{e}"). Fake "payment failed" pages are built to steal card details. Open the service\'s own app or website yourself instead.',
  "unfamiliar-link-pressure":
    'The message pushes you to act through a link to an unfamiliar website ("{e}"): a deadline, a threat to your account or service, or a request to pay, verify or claim something. Real banks, telecoms, governments and embassies send you to their own well-known website or app. Do not open the link; go to the official site yourself.',
  "account-security-lure":
    'The message warns about a strange sign-in and asks you to cancel or secure it through a link that is not the company\'s real address ("{e}"). The link leads to a fake sign-in page that steals your password. Check your account in the official app.',
  "defanged-link":
    'The link "{e}" is written in a disguised way (for example "[.]" or "dot" instead of a dot). Scammers do this to slip links past spam filters. Treat it like a real link and do not open it.',
});

// Plain-English reasons attached to cursed phrases, keyed by the signal that produced them.
export const CURSED_PHRASE_REASONS = Object.freeze({
  "urgency-en": "This phrase tries to rush you. Scammers rush people so they do not stop to check.",
  "credential-request":
    "This asks for a password, PIN or one-time code. Real companies do not ask for these in messages.",
  "prize-lottery": "This promises a prize, a big sum of money or guaranteed income. Scammers use these as bait.",
  "advance-fee-scheme": "This talks about money or goods waiting for you, or a fee to release them. The fee is the scam.",
  "financial-info-request": "This asks for card or bank details. Real companies do not ask for these in messages.",
  "unusual-payment-method":
    "This asks for payment that is hard to trace or get back, such as gift cards or cryptocurrency.",
  "secrecy-pressure": "This asks you to keep a secret, so nobody can warn you it is a scam.",
  "code-sharing-request": "This asks you to pass on a code sent to you. Never give these codes to anyone.",
  "mistaken-payment": "This claims money was sent to you by mistake and asks for it back. The first payment is usually fake.",
  "remote-access-request": "This asks for control of your device. Never let a stranger connect to it.",
  "delivery-scam": "This is the classic fake delivery problem. Check the parcel in the courier's own app, not through a link.",
  "seed-phrase-request": "This asks for your wallet recovery words. Whoever has them owns your crypto.",
  "investment-guarantee": "This promises certain or multiplied profit. Real investments never guarantee returns.",
  "task-job-scam": "This offers easy money for simple online tasks. These jobs end with you paying them.",
  "official-fine-threat": "This demands a fine or tax through a link, with a threat. Officials do not collect fines this way.",
  "recruiter-bait": "This is an unsolicited job offer with a link to a document. Check the recruiter before opening it.",
  "utility-disconnection-threat": "This threatens to cut off a utility unless you pay now. Check your bill in the official app.",
  "payment-failed-lure": "This claims a payment failed and asks for your card details again. Use the official app instead.",
  "account-security-lure": "This is a sign-in alert that sends you to a fake page. Check your account in the official app.",
  "unfamiliar-link-pressure": "Pressure to act through a link to an unfamiliar website. Go to the official site yourself.",
});
