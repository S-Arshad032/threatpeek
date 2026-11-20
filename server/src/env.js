// Reads and validates environment variables. The only side effect is reading the given source.
import { z } from "zod";
import { AI_DAILY_LIMIT_DEFAULT, DEFAULT_ALLOWED_ORIGINS, DEFAULT_PORT } from "./config.js";

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
  });
  return Object.freeze({
    ...env,
    ALLOWED_ORIGINS: Object.freeze(env.ALLOWED_ORIGINS),
    aiActive: env.AI_ENABLED && Boolean(env.OPENROUTER_API_KEY) && Boolean(env.OPENROUTER_MODEL),
  });
}
