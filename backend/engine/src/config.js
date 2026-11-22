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
});
