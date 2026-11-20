// Classifies IP address literals for the SSRF guard. Fails closed: anything that is not a
// valid canonical IPv4 or IPv6 address counts as blocked.
import { isIPv4, isIPv6 } from "node:net";
import { BLOCKED_IPV4_CIDRS, BLOCKED_IPV6_CIDRS } from "../config.js";

/** "a.b.c.d" -> BigInt (32 bit). Caller guarantees isIPv4(ip). */
function ipv4ToBigInt(ip) {
  return ip.split(".").reduce((acc, part) => (acc << 8n) | BigInt(Number(part)), 0n);
}

/** IPv6 text (no zone, no brackets) -> BigInt (128 bit). Caller guarantees isIPv6(ip). */
function ipv6ToBigInt(ip) {
  let text = ip.toLowerCase();
  // Replace an embedded IPv4 tail (e.g. ::ffff:127.0.0.1) by two hex groups.
  const v4Match = text.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4Match) {
    const v4 = ipv4ToBigInt(v4Match[1]);
    const hi = ((v4 >> 16n) & 0xffffn).toString(16);
    const lo = (v4 & 0xffffn).toString(16);
    text = text.slice(0, -v4Match[1].length) + `${hi}:${lo}`;
  }
  const [head, tail] = text.split("::");
  const headGroups = head ? head.split(":") : [];
  const tailGroups = tail !== undefined && tail !== "" ? tail.split(":") : [];
  const missing = 8 - headGroups.length - tailGroups.length;
  const groups = tail === undefined ? headGroups : [...headGroups, ...Array(missing).fill("0"), ...tailGroups];
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n);
}

function makeMatcher(cidrs, bits, toBigInt) {
  const total = BigInt(bits);
  return cidrs.map(([network, prefix]) => {
    const p = BigInt(prefix);
    const mask = p === 0n ? 0n : ((1n << p) - 1n) << (total - p);
    return { net: toBigInt(network) & mask, mask };
  });
}

const V4_RULES = makeMatcher(BLOCKED_IPV4_CIDRS, 32, ipv4ToBigInt);
const V6_RULES = makeMatcher(BLOCKED_IPV6_CIDRS, 128, ipv6ToBigInt);

const MAPPED_PREFIX = 0xffffn << 32n; // ::ffff:0:0/96 (IPv4-mapped)
const NAT64_PREFIX = 0x0064ff9bn << 96n; // 64:ff9b::/96 (NAT64 well-known prefix)
const LOW_32 = 0xffffffffn;
const HIGH_96 = ~LOW_32 & ((1n << 128n) - 1n);

function v4Blocked(n) {
  return V4_RULES.some(({ net, mask }) => (n & mask) === net);
}

/**
 * True when the address must not be contacted.
 * Accepts plain IPv4 ("1.2.3.4"), IPv6 ("::1"), bracketed IPv6 ("[::1]") and zone ids ("fe80::1%eth0").
 * @param {string} ip
 * @returns {boolean}
 */
export function isBlockedAddress(ip) {
  if (typeof ip !== "string") return true;
  let text = ip.trim();
  if (text.startsWith("[") && text.endsWith("]")) text = text.slice(1, -1);

  if (isIPv4(text)) return v4Blocked(ipv4ToBigInt(text));

  const zone = text.indexOf("%");
  if (zone !== -1) text = text.slice(0, zone);
  if (!isIPv6(text)) return true;

  const n = ipv6ToBigInt(text);
  const high = n & HIGH_96;
  // IPv4-mapped and NAT64 addresses are judged by the embedded IPv4 address.
  if (high === MAPPED_PREFIX || high === NAT64_PREFIX) return v4Blocked(n & LOW_32);
  // Deprecated IPv4-compatible range ::/96 (includes :: and ::1): never public.
  if (high === 0n) return true;
  return V6_RULES.some(({ net, mask }) => (n & mask) === net);
}
