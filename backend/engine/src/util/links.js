// Finds links in a message for the content signals ("a delivery notice WITH A LINK").
// Defanged links are refanged first. A link is a URL with a scheme, a "www." host, or a bare
// "name.ending" whose ending is in LINK_TLDS (so "e.g." or "Mr.Smith" are not links).

import { LINK_TLDS, SHORTENER_DOMAINS, MAX_HOSTNAMES_SCANNED } from "../config.js";
import { refang } from "./normalize.js";

const TLDS = [...LINK_TLDS].sort((a, b) => b.length - a.length).join("|");
const LINK_RE = new RegExp(
  String.raw`(?<![\p{L}\p{N}_@.-])(?:https?:\/\/)?` +
    String.raw`((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,10}(?:${TLDS}))(?![\p{L}\p{N}_-]|\.[a-z0-9])` +
    String.raw`(?:[\/?#][^\s"'<>]{0,200})?` +
    String.raw`|https?:\/\/([^\s\/"'<>]{1,253})[^\s"'<>]{0,200}`,
  "giu",
);

/**
 * @param {string} input raw message
 * @returns {Array<{ text: string, host: string, shortener: boolean }>} links in order (max MAX_HOSTNAMES_SCANNED)
 */
export function findLinks(input) {
  const out = [];
  for (const m of refang(input).matchAll(LINK_RE)) {
    let host = (m[1] ?? m[2]).toLowerCase();
    if (host.startsWith("www.")) host = host.slice(4);
    out.push({ text: m[0], host, shortener: SHORTENER_DOMAINS.includes(host) });
    if (out.length >= MAX_HOSTNAMES_SCANNED) break;
  }
  return out;
}
