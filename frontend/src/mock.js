// Sample results with EXACTLY the shape returned by score() from @threatpeek/engine.
// Each one is real engine output (copied from running score() on the `input` noted above it),
// so scores, verdicts, flags, explanation wording and cursed phrases all agree with each other.
//
// Result fields:
//   riskScore      integer 0-100. Estimated risk, never a guarantee.
//   verdict        "pookie" (0-30) | "skeptical" (31-69) | "poltergeist" (70-100).
//   redFlags       array of { id, weight, evidence, explanation }, in detector order, one per signal id.
//                    id           signal id, e.g. "risky-tld", "credential-request", "typosquatting".
//                    weight       points this signal adds before category caps and blending.
//                    evidence     text copied from the input (UNTRUSTED: render as plain text only).
//                    explanation  plain-English sentence for the user; may quote the evidence.
//   cursedPhrases  array of { text, reason } (max 20). text is copied from the input (UNTRUSTED),
//                  reason is a plain-English sentence. Only urgency and credential signals add phrases.
//   confidence     "full" when an AI score (l3Score) was used, otherwise "limited".
//
// All three samples were scored with an AI score, so confidence is "full".

// input: "Hi! Our bake sale is this Saturday. Limited time: cookies are half price before noon. See you there!"
// options: { l3Score: 5 }
export const pookie = Object.freeze({
  riskScore: 12,
  verdict: 'pookie',
  redFlags: [
    {
      id: 'urgency-en',
      weight: 15,
      evidence: 'Limited time',
      explanation:
        'The message pressures you to act quickly ("Limited time"). Scammers rush people so they do not stop to check.',
    },
  ],
  cursedPhrases: [
    {
      text: 'Limited time',
      reason: 'This phrase tries to rush you. Scammers rush people so they do not stop to check.',
    },
  ],
  confidence: 'full',
})

// input: "Your parcel is on hold. Log in at http://parcel-help.xyz/track to reschedule delivery."
// options: { l3Score: 73 }
export const skeptical = Object.freeze({
  riskScore: 52,
  verdict: 'skeptical',
  redFlags: [
    {
      id: 'risky-tld',
      weight: 15,
      evidence: 'parcel-help.xyz',
      explanation:
        'The link "parcel-help.xyz" ends in an address ending that is often used by throwaway scam websites. This alone is not proof, but be careful.',
    },
    {
      id: 'credential-request',
      weight: 20,
      evidence: 'Log in',
      explanation:
        'The message asks for a password, PIN or one-time code ("Log in"). Real companies do not ask for these in messages.',
    },
  ],
  cursedPhrases: [
    {
      text: 'Log in',
      reason: 'This asks for a password, PIN or one-time code. Real companies do not ask for these in messages.',
    },
  ],
  confidence: 'full',
})

// input: "URGENT from Galactibank: your account will be suspended. Verify immediately at
//         http://galactibank.xyz/login and enter your password and OTP."
// options: { l3Score: 99 }
export const poltergeist = Object.freeze({
  riskScore: 91,
  verdict: 'poltergeist',
  redFlags: [
    {
      id: 'typosquatting',
      weight: 35,
      evidence: 'galactibank.xyz',
      explanation:
        'The web address "galactibank.xyz" looks almost like a well-known company\'s address but is spelled slightly differently. Scammers use look-alike addresses to make a fake site look real.',
    },
    {
      id: 'risky-tld',
      weight: 15,
      evidence: 'galactibank.xyz',
      explanation:
        'The link "galactibank.xyz" ends in an address ending that is often used by throwaway scam websites. This alone is not proof, but be careful.',
    },
    {
      id: 'urgency-en',
      weight: 15,
      evidence: 'account will be suspended',
      explanation:
        'The message pressures you to act quickly ("account will be suspended"). Scammers rush people so they do not stop to check.',
    },
    {
      id: 'credential-request',
      weight: 20,
      evidence: 'login',
      explanation:
        'The message asks for a password, PIN or one-time code ("login"). Real companies do not ask for these in messages.',
    },
  ],
  cursedPhrases: [
    {
      text: 'account will be suspended',
      reason: 'This phrase tries to rush you. Scammers rush people so they do not stop to check.',
    },
    {
      text: 'Verify immediately',
      reason: 'This phrase tries to rush you. Scammers rush people so they do not stop to check.',
    },
    {
      text: 'login',
      reason: 'This asks for a password, PIN or one-time code. Real companies do not ask for these in messages.',
    },
    {
      text: 'password',
      reason: 'This asks for a password, PIN or one-time code. Real companies do not ask for these in messages.',
    },
    {
      text: 'OTP',
      reason: 'This asks for a password, PIN or one-time code. Real companies do not ask for these in messages.',
    },
  ],
  confidence: 'full',
})
