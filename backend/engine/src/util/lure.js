// Lookalike lure domains: a registrable label made of hyphen-joined "official sounding" words,
// such as "secure-login-help.example" or "billing-update-verify.example". Shared by the link
// detector (signal lookalike-lure-domain) and the content families that need "a lookalike link".

import {
  LURE_WORDS,
  LURE_WORDS_MIN,
  LOOKALIKE_SAFE_DOMAINS,
  RISKY_TLDS,
  UNFAMILIAR_MIN_HYPHENS,
  UNFAMILIAR_SAFE_DOMAINS,
} from "../config.js";
import { registrableDomain, registrableLabel } from "./hostname.js";

/**
 * True when the host's registrable label has LURE_WORDS_MIN or more hyphen-joined lure words and
 * the domain is not one of the given brands' domains or a listed safe domain.
 * @param {string} host lowercase hostname without "www."
 * @param {ReadonlyArray<{ domains: ReadonlyArray<string> }>} brands
 */
export function isLureDomain(host, brands) {
  const label = registrableLabel(host);
  if (!label.includes("-")) return false;
  const lures = label.split("-").filter((part) => LURE_WORDS.includes(part));
  if (lures.length < LURE_WORDS_MIN) return false;
  const domain = registrableDomain(host);
  if (LOOKALIKE_SAFE_DOMAINS.includes(domain)) return false;
  return !brands.some((b) => b.domains.some((d) => d.toLowerCase() === domain));
}

/**
 * True when a link's registrable domain is unfamiliar: a URL shortener, a raw IP, a risky TLD, a
 * registrable label with UNFAMILIAR_MIN_HYPHENS or more hyphens, or a hyphenated label with a lure
 * word. Well-known real domains (UNFAMILIAR_SAFE_DOMAINS) and the brands' domains never are.
 * @param {{ host: string, shortener: boolean }} link
 * @param {ReadonlyArray<{ domains: ReadonlyArray<string> }>} brands
 */
export function isUnfamiliarDomain(link, brands) {
  const { host } = link;
  if (link.shortener || /^[\d.]+$/.test(host)) return true;
  const domain = registrableDomain(host);
  if (UNFAMILIAR_SAFE_DOMAINS.includes(domain)) return false;
  if (brands.some((b) => b.domains.some((d) => d.toLowerCase() === domain))) return false;
  if (hasRiskyTld(host)) return true;
  const parts = registrableLabel(host).split("-");
  return parts.length > UNFAMILIAR_MIN_HYPHENS || (parts.length > 1 && parts.some((p) => LURE_WORDS.includes(p)));
}

/** True when the host ends in one of RISKY_TLDS. */
export function hasRiskyTld(host) {
  return RISKY_TLDS.includes(host.slice(host.lastIndexOf(".") + 1));
}
