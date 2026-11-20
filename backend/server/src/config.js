// All server constants in one place. No side effects.

// Same value as MAX_INPUT_LENGTH in backend/engine/src/config.js (the engine's index does not export it).
export const MAX_INPUT_LENGTH = 4000;

export const BODY_LIMIT = "16kb";
export const USER_AGENT = "ThreatPeek/0.1";

// Rate limits (per IP).
export const RATE_WINDOW_MS = 60_000;
export const RATE_LIMIT_API = 30;
export const RATE_LIMIT_ANALYZE = 10;

// Timeouts for external calls.
export const UNWRAP_TOTAL_TIMEOUT_MS = 10_000;
export const SAFEBROWSING_TIMEOUT_MS = 5_000;
export const OPENROUTER_TIMEOUT_MS = 15_000;

// Unwrap.
export const UNWRAP_MAX_HOPS = 5;
export const ALLOWED_PROTOCOLS = Object.freeze(["http:", "https:"]);
// URL.port is "" when the port is the scheme default (80 for http, 443 for https).
export const ALLOWED_PORTS = Object.freeze(["", "80", "443"]);

// Safe Browsing.
export const SAFEBROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find";
export const SAFEBROWSING_MAX_URLS = 10;
export const SAFEBROWSING_CACHE_TTL_MS = 60 * 60 * 1000;
export const SAFEBROWSING_CACHE_MAX = 500;

// AI (L3).
export const OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions";
export const AI_DAILY_LIMIT_DEFAULT = 40;
export const AI_MAX_TOKENS = 60;
export const AI_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
export const AI_CACHE_MAX = 500;

export const DEFAULT_PORT = 3001;
export const DEFAULT_ALLOWED_ORIGINS = "http://localhost:5173";

// Blocked address ranges for the SSRF guard, as [network, prefixLength].
export const BLOCKED_IPV4_CIDRS = Object.freeze([
  ["0.0.0.0", 8], // "this" network
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // CGNAT
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local, incl. cloud metadata 169.254.169.254
  ["172.16.0.0", 12], // private
  ["192.168.0.0", 16], // private
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved, incl. broadcast 255.255.255.255
]);

export const BLOCKED_IPV6_CIDRS = Object.freeze([
  ["::", 128], // unspecified
  ["::1", 128], // loopback
  ["fc00::", 7], // unique-local
  ["fe80::", 10], // link-local
  ["ff00::", 8], // multicast
]);
