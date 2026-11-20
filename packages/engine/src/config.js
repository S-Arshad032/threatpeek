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
export const W_URGENCY_BN = 15;
export const W_CREDENTIAL_REQUEST = 20;
export const W_SUSPICIOUS_ATTACHMENT = 20;
export const W_SPF_FAIL = 20;
export const W_DKIM_FAIL = 20;
export const W_DMARC_FAIL = 15;

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
  "urgency-bn": CATEGORY_CONTENT,
  "credential-request": CATEGORY_CONTENT,
  "suspicious-attachment": CATEGORY_CONTENT,
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

export const URGENCY_BN_PHRASES = Object.freeze([
  "আপনার অ্যাকাউন্ট স্থগিত হবে",
  "এখনই যাচাই করুন",
  "অবিলম্বে যাচাই",
  "এখনই সাড়া দিন",
  "অ্যাকাউন্ট বন্ধ হয়ে যাবে",
]);

// Bangla credential terms: password, OTP, PIN number.
export const CREDENTIAL_BN_TERMS = Object.freeze(["পাসওয়ার্ড", "ওটিপি", "পিন নম্বর"]);

// ---------------------------------------------------------------------------
// Plain-English explanations (design: "Plain-English Explanations" table).
// "{e}" is replaced by the flag's evidence.
// ---------------------------------------------------------------------------
export const EVIDENCE_PLACEHOLDER = "{e}";

const URGENCY_EXPLANATION =
  'The message pressures you to act quickly ("{e}"). Scammers rush people so they do not stop to check.';

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
  "urgency-en": URGENCY_EXPLANATION,
  "urgency-bn": URGENCY_EXPLANATION,
  "credential-request":
    'The message asks for a password, PIN or one-time code ("{e}"). Real companies do not ask for these in messages.',
  "suspicious-attachment":
    'The message mentions a file called "{e}", a type of file that can install harmful programs. Do not open it unless you are sure who sent it.',
});

// Plain-English reasons attached to cursed phrases, keyed by the signal that produced them.
const URGENCY_REASON = "This phrase tries to rush you. Scammers rush people so they do not stop to check.";

export const CURSED_PHRASE_REASONS = Object.freeze({
  "urgency-en": URGENCY_REASON,
  "urgency-bn": URGENCY_REASON,
  "credential-request":
    "This asks for a password, PIN or one-time code. Real companies do not ask for these in messages.",
});
