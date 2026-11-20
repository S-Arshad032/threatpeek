// POST /api/analyze: optional AI (L3) score. Always HTTP 200 with l3Score null on any failure.
import { createHash } from "node:crypto";
import { Router } from "express";
import { z } from "zod";
import { AI_CACHE_MAX, AI_CACHE_TTL_MS, MAX_INPUT_LENGTH, OPENROUTER_TIMEOUT_MS } from "../config.js";
import { parseBody } from "../lib/http.js";
import { DailyBudget } from "../lib/limits.js";
import { LRUCache } from "../lib/lru.js";
import { callModel } from "../lib/openrouter.js";

const bodySchema = z.object({ text: z.string().min(1).max(MAX_INPUT_LENGTH) });

/** Cache key: SHA-256 of NFC-normalized text with collapsed whitespace. */
export function cacheKey(text) {
  const normalized = text.normalize("NFC").replace(/\s+/g, " ").trim();
  return createHash("sha256").update(normalized, "utf8").digest("hex");
}

/**
 * @param {{ env: object, fetchImpl?: Function, now?: () => number, timeoutMs?: number }} deps
 */
export function createAnalyzer({ env, fetchImpl = fetch, now = Date.now, timeoutMs = OPENROUTER_TIMEOUT_MS }) {
  const cache = new LRUCache({ max: AI_CACHE_MAX, ttlMs: AI_CACHE_TTL_MS, now });
  const budget = new DailyBudget({ limit: env.AI_DAILY_LIMIT, now });
  const DISABLED = Object.freeze({ l3Score: null, cached: false });

  /** @param {string} text */
  async function analyze(text) {
    if (!env.aiActive) return DISABLED;
    const key = cacheKey(text);
    const hit = cache.get(key);
    if (hit !== undefined) return { l3Score: hit, cached: true };
    if (!budget.tryConsume()) return DISABLED;

    const { score, status } = await callModel({
      text,
      apiKey: env.OPENROUTER_API_KEY,
      model: env.OPENROUTER_MODEL,
      fetchImpl,
      timeoutMs,
    });
    if (score === null) {
      // Log only the status, never the text, the key or the model output.
      console.warn(`analyze: no score (upstream ${status})`);
      return DISABLED;
    }
    cache.set(key, score);
    return { l3Score: score, cached: false };
  }

  return { analyze, cache, budget };
}

export function createAnalyzeRouter(deps, { limiter } = {}) {
  const analyzer = createAnalyzer(deps);
  const router = Router();
  const handlers = limiter ? [limiter] : [];
  router.post("/analyze", ...handlers, async (req, res) => {
    const body = parseBody(bodySchema, req, res);
    if (!body) return;
    res.json(await analyzer.analyze(body.text));
  });
  return router;
}
