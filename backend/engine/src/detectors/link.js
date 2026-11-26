// Link detector: raw-ip-url, risky-tld, link-text-mismatch, defanged-link, lookalike-lure-domain.
// All Link category.
// Produces no cursed phrases. Defanged links ("evil[.]com", "hxxps://") are refanged first, so
// every check sees them as ordinary links.

import {
  W_RAW_IP_URL,
  W_RISKY_TLD,
  W_LINK_TEXT_MISMATCH,
  W_DEFANGED_LINK,
  W_LOOKALIKE_LURE_DOMAIN,
  W_LOOKALIKE_LURE_DOMAIN_STRONG,
  MAX_DEFANG_EVIDENCE_CHARS,
  RISKY_TLDS,
  IPV4_OCTET_MAX,
  IPV6_MIN_COLONS,
  IPV6_MAX_GROUPS,
  IPV6_MAX_GROUP_HEX_DIGITS,
} from "../config.js";
import { registrableDomain } from "../util/hostname.js";
import { makeRedFlag } from "../util/flag.js";
import { refang, findDefang } from "../util/normalize.js";
import { findLinks } from "../util/links.js";
import { isLureDomain, hasRiskyTld } from "../util/lure.js";
import { DEFAULT_BRANDS } from "../brands.js";

// A trailing sentence dot is allowed, but not a dot that starts another hostname label.
const IPV4_URL_RE = /https?:\/\/((?:\d{1,3}\.){3}\d{1,3})(?=\.?(?:[\s"'<>)\],;:\/?#]|$))/gi;
const IPV6_URL_RE = /https?:\/\/\[([0-9a-f:.]{2,45})\]/gi;

const RISKY_TLD_RE = new RegExp(
  String.raw`(?<![\p{L}\p{N}\p{M}_.-])(?:[a-z0-9-]{1,63}\.){1,10}(?:${RISKY_TLDS.join("|")})(?![\p{L}\p{N}\p{M}_-]|\.[a-z0-9-])`,
  "giu",
);

const HTML_ANCHOR_RE = /<a\s[^>]{0,500}?href\s*=\s*["']([^"']{1,2048})["'][^>]{0,500}>([^<]{1,500})<\/a>/gi;
const MARKDOWN_LINK_RE = /\[([^\]\n]{1,500})\]\((https?:\/\/[^)\s]{1,2048})\)/gi;
const LOOKS_LIKE_URL_RE = /^(?:https?:\/\/)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:[\/:?#]\S*)?$/i;
const HOSTNAME_RE = /^[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){1,10}$/;
const SCHEME_RE = /^[a-z][a-z0-9+.-]{0,20}:\/\//i;
const HEX_GROUP_RE = /^[0-9a-f]*$/i;
const WWW_PREFIX = "www.";

// ---------------------------------------------------------------------------
// raw-ip-url
// ---------------------------------------------------------------------------
function isValidIpv4(addr) {
  const octets = addr.split(".");
  return octets.length === 4 && octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= IPV4_OCTET_MAX);
}

function isValidIpv6(addr) {
  const colons = addr.split(":").length - 1;
  if (colons < IPV6_MIN_COLONS) return false;
  const doubleColons = addr.split("::").length - 1;
  if (doubleColons > 1 || addr.includes(":::")) return false;

  const groups = addr.split(":");
  let groupCount = 0;
  for (let i = 0; i < groups.length; i++) {
    const g = groups[i];
    if (g.includes(".")) {
      // An embedded IPv4 address is only allowed as the final group and counts as two groups.
      if (i !== groups.length - 1 || !isValidIpv4(g)) return false;
      groupCount += 2;
    } else {
      if (g.length > IPV6_MAX_GROUP_HEX_DIGITS || !HEX_GROUP_RE.test(g)) return false;
      if (g.length > 0) groupCount += 1;
    }
  }
  if (groupCount > IPV6_MAX_GROUPS) return false;
  return doubleColons === 1 || groupCount === IPV6_MAX_GROUPS;
}

function detectRawIp(input) {
  for (const m of input.matchAll(IPV4_URL_RE)) {
    if (isValidIpv4(m[1])) return makeRedFlag("raw-ip-url", W_RAW_IP_URL, m[0]);
  }
  for (const m of input.matchAll(IPV6_URL_RE)) {
    if (isValidIpv6(m[1])) return makeRedFlag("raw-ip-url", W_RAW_IP_URL, m[0]);
  }
  return null;
}

// ---------------------------------------------------------------------------
// risky-tld
// ---------------------------------------------------------------------------
function detectRiskyTld(input) {
  for (const m of input.matchAll(RISKY_TLD_RE)) {
    return makeRedFlag("risky-tld", W_RISKY_TLD, m[0].toLowerCase());
  }
  return null;
}

// ---------------------------------------------------------------------------
// link-text-mismatch
// ---------------------------------------------------------------------------
/** Extracts a lowercase hostname (without "www.") from a URL or bare hostname, or null. */
function hostOf(urlish) {
  let rest = urlish.trim().replace(SCHEME_RE, "");
  const end = rest.search(/[\/?#]/);
  if (end !== -1) rest = rest.slice(0, end);
  const at = rest.lastIndexOf("@");
  if (at !== -1) rest = rest.slice(at + 1);
  rest = rest.replace(/:\d{0,5}$/, "").toLowerCase();
  if (rest.startsWith(WWW_PREFIX)) rest = rest.slice(WWW_PREFIX.length);
  return HOSTNAME_RE.test(rest) ? rest : null;
}

function* links(input) {
  for (const m of input.matchAll(HTML_ANCHOR_RE)) yield { href: m[1], text: m[2] };
  for (const m of input.matchAll(MARKDOWN_LINK_RE)) yield { href: m[2], text: m[1] };
}

function detectLinkTextMismatch(input) {
  for (const { href, text } of links(input)) {
    const shown = text.trim();
    if (!LOOKS_LIKE_URL_RE.test(shown)) continue;
    const textHost = hostOf(shown);
    const hrefHost = hostOf(href);
    if (!textHost || !hrefHost) continue;
    if (registrableDomain(textHost) !== registrableDomain(hrefHost)) {
      return makeRedFlag("link-text-mismatch", W_LINK_TEXT_MISMATCH, `text: ${shown} -> href: ${href.trim()}`);
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// defanged-link
// ---------------------------------------------------------------------------
/** The whitespace-free token around the first defanged piece ("docs-share-view[.]com/role-402"). */
function detectDefanged(input) {
  const hit = findDefang(input);
  if (hit === null) return null;
  let start = hit.index;
  let end = hit.index + hit.length;
  // A spaced-out "evil dot com" keeps the words on both sides.
  const isTokenChar = (ch) => ch !== undefined && !/[\s"'<>]/.test(ch);
  while (start > 0 && hit.index - start < MAX_DEFANG_EVIDENCE_CHARS && isTokenChar(input[start - 1])) start--;
  while (end < input.length && end - hit.index - hit.length < MAX_DEFANG_EVIDENCE_CHARS && isTokenChar(input[end])) end++;
  return makeRedFlag("defanged-link", W_DEFANGED_LINK, input.slice(start, end));
}

// ---------------------------------------------------------------------------
// lookalike-lure-domain
// ---------------------------------------------------------------------------
/** The first link whose domain is made of lure words; stronger on a risky TLD or when defanged. */
function detectLookalike(input, brands) {
  const lure = findLinks(input).find((l) => isLureDomain(l.host, brands));
  if (!lure) return null;
  const strong = hasRiskyTld(lure.host) || findDefang(input) !== null;
  return makeRedFlag("lookalike-lure-domain", strong ? W_LOOKALIKE_LURE_DOMAIN_STRONG : W_LOOKALIKE_LURE_DOMAIN, lure.host);
}

/**
 * @param {string} input
 * @param {ReadonlyArray<{ name: string, domains: ReadonlyArray<string> }>} [brands]
 */
export function detectLinks(input, brands = DEFAULT_BRANDS) {
  const text = refang(input);
  const flags = [
    detectRawIp(text),
    detectRiskyTld(text),
    detectLinkTextMismatch(text),
    detectDefanged(input),
    detectLookalike(input, brands),
  ].filter(Boolean);
  return { flags, cursedPhrases: [] };
}
