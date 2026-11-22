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
export const FLOOR_UNUSUAL_PAYMENT = 40;

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
export const NEGATION_WINDOW_CHARS = 30; // "never ... share your card number" is a warning, not a request
export const MONEY_DIGITS_MAX = 15; // digits, commas and dots after the first digit of an amount
export const MONEY_SPACE_MAX = 3; // spaces between a currency marker, the number and "million"

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
export const RISKY_TLDS = Object.freeze(["xyz", "top", "click", "tk", "ml", "ga", "cf"]); // exactly Requirement 2.6
export const DANGEROUS_EXTENSIONS = Object.freeze(["exe", "scr", "vbs", "bat", "cmd", "js", "lnk", "iso", "img"]);
export const JS_LIBRARY_ALLOWLIST = Object.freeze(["node", "react", "vue", "next", "nuxt", "express", "angular", "d3", "three"]);
export const SECOND_LEVEL_LABELS = Object.freeze(["com", "co", "org", "net", "gov", "edu", "ac"]); // used with 2-letter country TLDs, e.g. com.bd, co.uk
export const COUNTRY_TLD_LENGTH = 2;

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
]);
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
]);

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

// unusual-payment-method: a payment verb followed, within REQUEST_PROXIMITY_CHARS in the same
// sentence, by a hard-to-trace payment method. A mobile wallet only counts when a fee is mentioned.
export const PAYMENT_VERBS = Object.freeze(["pay", "paying", "payment", "send", "sending", "transfer", "buy", "buying"]);
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
]);
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
    'The message says you have won a prize or a large sum of money ("{e}"). Scammers promise prizes so you hand over money or personal details. You cannot win a draw you never entered.',
  "advance-fee-scheme":
    'The message talks about an inheritance, unclaimed money or a fee you must pay to receive funds ("{e}"). This is a well-known scam: you pay the fee and the promised money never arrives.',
  "financial-info-request":
    'The message asks you to give your card or bank details ("{e}"). Real banks and shops do not ask for these in a message, and anyone who has them can take your money.',
  "unusual-payment-method":
    'The message asks you to pay with gift cards, cryptocurrency or a money-transfer service ("{e}"). Scammers ask for these because the money is hard to trace and almost never comes back.',
  "secrecy-pressure":
    'The message tells you to keep it secret ("{e}"). Scammers do this so nobody you trust can warn you.',
});

// Plain-English reasons attached to cursed phrases, keyed by the signal that produced them.
export const CURSED_PHRASE_REASONS = Object.freeze({
  "urgency-en": "This phrase tries to rush you. Scammers rush people so they do not stop to check.",
  "credential-request":
    "This asks for a password, PIN or one-time code. Real companies do not ask for these in messages.",
  "prize-lottery": "This promises a prize or a big sum of money. Scammers use fake prizes as bait.",
  "advance-fee-scheme": "This talks about money waiting for you or a fee to release it. The fee is the scam.",
  "financial-info-request": "This asks for card or bank details. Real companies do not ask for these in messages.",
  "unusual-payment-method":
    "This asks for payment that is hard to trace or get back, such as gift cards or cryptocurrency.",
  "secrecy-pressure": "This asks you to keep a secret, so nobody can warn you it is a scam.",
});
