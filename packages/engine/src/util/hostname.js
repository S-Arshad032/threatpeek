// Hostname extraction and domain helpers.
// All regexes are bounded (no nested unbounded quantifiers). Global regexes are only ever
// used through String.prototype.matchAll, which clones them, so no lastIndex state is shared.

import { MAX_HOSTNAMES_SCANNED, SECOND_LEVEL_LABELS, COUNTRY_TLD_LENGTH } from "../config.js";

// ASCII hostname: 1-10 labels followed by an alphabetic TLD. Unicode-aware lookarounds stop
// a hostname being pulled out of the middle of a word (e.g. the tail of a Cyrillic spoof)
// and stop "user.name@host" yielding "user.name".
const ASCII_HOSTNAME_RE =
  /(?<![\p{L}\p{N}\p{M}_.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,10}[a-z]{2,24})(?![\p{L}\p{N}\p{M}_@-])/giu;

// Unicode hostname (for homograph checks). \p{M} lets scripts with vowel signs form labels.
const UNICODE_HOSTNAME_RE =
  /(?<![\p{L}\p{N}\p{M}_.-])((?:[\p{L}\p{N}](?:[\p{L}\p{N}\p{M}-]{0,61}[\p{L}\p{N}\p{M}])?\.){1,10}[\p{L}\p{M}]{2,24})(?![\p{L}\p{N}\p{M}_@-])/gu;

function collect(text, re) {
  const seen = new Set();
  const out = [];
  for (const m of text.matchAll(re)) {
    const host = m[1].toLowerCase();
    if (seen.has(host)) continue;
    seen.add(host);
    out.push(host);
    if (out.length >= MAX_HOSTNAMES_SCANNED) break;
  }
  return out;
}

/** Lowercased, de-duplicated ASCII hostnames in order of appearance (max MAX_HOSTNAMES_SCANNED). */
export function extractAsciiHostnames(text) {
  return collect(text, ASCII_HOSTNAME_RE);
}

/** Lowercased, de-duplicated hostnames that may contain any letters (max MAX_HOSTNAMES_SCANNED). */
export function extractUnicodeHostnames(text) {
  return collect(text, UNICODE_HOSTNAME_RE);
}

/** Index of the registrable label within the host's labels. */
function registrableIndex(labels) {
  const n = labels.length;
  if (n < 2) return 0;
  const last = labels[n - 1];
  if (n >= 3 && last.length === COUNTRY_TLD_LENGTH && SECOND_LEVEL_LABELS.includes(labels[n - 2])) {
    return n - 3;
  }
  return n - 2;
}

/**
 * The label just before the public suffix.
 * "login.galactibank.example" -> "galactibank"; "shop.example.com.bd" -> "example".
 */
export function registrableLabel(host) {
  const labels = host.toLowerCase().split(".");
  return labels[registrableIndex(labels)];
}

/**
 * Registrable label plus its public suffix.
 * "login.galactibank.example" -> "galactibank.example"; "shop.example.com.bd" -> "example.com.bd".
 */
export function registrableDomain(host) {
  const labels = host.toLowerCase().split(".");
  return labels.slice(registrableIndex(labels)).join(".");
}

/** True when `host` equals, or is a subdomain of, one of the brand's legitimate domains. */
export function isLegitimate(host, brand) {
  const h = host.toLowerCase();
  return brand.domains.some((d) => {
    const domain = d.toLowerCase();
    return h === domain || h.endsWith("." + domain);
  });
}
