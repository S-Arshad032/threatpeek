// Reads and validates environment variables. The only side effect is reading the given source.
import { isIP } from "node:net";
import { z } from "zod";
import { AI_DAILY_LIMIT_DEFAULT, DEFAULT_ALLOWED_ORIGINS, DEFAULT_PORT, TRUST_PROXY_MAX_HOPS } from "./config.js";

// Empty or whitespace-only strings count as "not set".
const optionalString = z
  .string()
  .optional()
  .transform((v) => (v === undefined || v.trim() === "" ? undefined : v.trim()));

// Invalid numbers fall back to the safe default instead of crashing the server.
const intWithDefault = (def, min, max) =>
  z
    .preprocess(
      (v) => (v === undefined || (typeof v === "string" && v.trim() === "") ? def : Number(v)),
      z.number().int().min(min).max(max),
    )
    .catch(def);

// Named subnets understood by Express's "trust proxy" setting.
const TRUST_PROXY_PRESETS = new Set(["loopback", "linklocal", "uniquelocal"]);

/** One entry of a trust list: a preset name, an IP, or an IP/prefix subnet. */
function isTrustEntry(entry) {
  if (TRUST_PROXY_PRESETS.has(entry)) return true;
  const [addr, prefix, extra] = entry.split("/");
  const family = isIP(addr);
  if (!family || extra !== undefined) return false;
  if (prefix === undefined) return true;
  const max = family === 4 ? 32 : 128;
  return /^\d{1,3}$/.test(prefix) && Number(prefix) <= max;
}

/**
 * TRUST_PROXY -> value for app.set("trust proxy", ...).
 * Unset, "false", "0" or anything invalid -> false (do not trust X-Forwarded-For; the safe default).
 * "1".."10" -> number of proxy hops in front of the app.
 * A comma-separated list of IPs, subnets or presets -> that list.
 * "true" is refused on purpose: it trusts every hop, so clients could fake their IP and dodge rate limits.
 */
export function parseTrustProxy(value) {
  const v = value?.trim().toLowerCase();
  if (!v || v === "false") return false;
  if (/^\d+$/.test(v)) {
    const hops = Number(v);
    return hops >= 1 && hops <= TRUST_PROXY_MAX_HOPS ? hops : false;
  }
  const entries = v.split(",").map((e) => e.trim()).filter(Boolean);
  return entries.length > 0 && entries.every(isTrustEntry) ? entries.join(", ") : false;
}

const schema = z.object({
  NODE_ENV: optionalString.transform((v) => v ?? "development"),
  PORT: intWithDefault(DEFAULT_PORT, 1, 65535),
  ALLOWED_ORIGINS: optionalString.transform((v) =>
    (v ?? DEFAULT_ALLOWED_ORIGINS)
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  ),
  GOOGLE_SAFE_BROWSING_KEY: optionalString,
  AI_ENABLED: optionalString.transform((v) => v === "true"),
  OPENROUTER_API_KEY: optionalString,
  OPENROUTER_MODEL: optionalString,
  AI_DAILY_LIMIT: intWithDefault(AI_DAILY_LIMIT_DEFAULT, 0, 100_000),
  TRUST_PROXY: z.string().optional().transform(parseTrustProxy),
  STATIC_DIR: optionalString,
});

/**
 * @param {Record<string, string | undefined>} source usually process.env
 */
export function loadEnv(source = process.env) {
  const env = schema.parse({
    NODE_ENV: source.NODE_ENV,
    PORT: source.PORT,
    ALLOWED_ORIGINS: source.ALLOWED_ORIGINS,
    GOOGLE_SAFE_BROWSING_KEY: source.GOOGLE_SAFE_BROWSING_KEY,
    AI_ENABLED: source.AI_ENABLED,
    OPENROUTER_API_KEY: source.OPENROUTER_API_KEY,
    OPENROUTER_MODEL: source.OPENROUTER_MODEL,
    AI_DAILY_LIMIT: source.AI_DAILY_LIMIT,
    TRUST_PROXY: source.TRUST_PROXY,
    STATIC_DIR: source.STATIC_DIR,
  });
  return Object.freeze({
    ...env,
    ALLOWED_ORIGINS: Object.freeze(env.ALLOWED_ORIGINS),
    aiActive: env.AI_ENABLED && Boolean(env.OPENROUTER_API_KEY) && Boolean(env.OPENROUTER_MODEL),
    // Static hosting of the built frontend: always in production, or whenever STATIC_DIR is set.
    serveStatic: env.NODE_ENV === "production" || env.STATIC_DIR !== undefined,
  });
}
