// POST /api/safebrowsing: Google Safe Browsing Lookup API v4 (threatMatches:find).
// Degrades silently: no key, HTTP error, bad answer or timeout -> { hit: false, checked: false }.
//
// Google's terms: a warning may only be shown while the cached match is still valid, so a hit is
// cached for min(1 h, cacheDuration from Google). A miss is cached for 1 h.
import { Router } from "express";
import { z } from "zod";
import {
  MAX_INPUT_LENGTH,
  SAFEBROWSING_CACHE_MAX,
  SAFEBROWSING_CACHE_TTL_MS,
  SAFEBROWSING_ENDPOINT,
  SAFEBROWSING_MAX_URLS,
  SAFEBROWSING_TIMEOUT_MS,
  USER_AGENT,
} from "../config.js";
import { parseBody } from "../lib/http.js";
import { LRUCache } from "../lib/lru.js";

const httpUrl = z
  .string()
  .trim()
  .min(1)
  .max(MAX_INPUT_LENGTH)
  .refine((s) => {
    try {
      const { protocol } = new URL(s);
      return protocol === "http:" || protocol === "https:";
    } catch {
      return false;
    }
  });

const bodySchema = z.object({ urls: z.array(httpUrl).min(1).max(SAFEBROWSING_MAX_URLS) });

const responseSchema = z.object({
  matches: z
    .array(
      z.object({
        threat: z.object({ url: z.string() }),
        cacheDuration: z.string().optional(),
      }),
    )
    .optional(),
});

/** "300.000s" -> 300000 ms; anything else -> undefined */
function parseDuration(text) {
  const m = /^(\d+(?:\.\d+)?)s$/.exec(text ?? "");
  return m ? Math.round(Number(m[1]) * 1000) : undefined;
}

function buildRequestBody(urls) {
  return {
    client: { clientId: "threatpeek", clientVersion: "0.1.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: urls.map((url) => ({ url })),
    },
  };
}

/**
 * @param {{ env: { GOOGLE_SAFE_BROWSING_KEY?: string }, fetchImpl?: Function, now?: () => number, timeoutMs?: number }} deps
 */
export function createSafeBrowsingChecker({ env, fetchImpl = fetch, now = Date.now, timeoutMs = SAFEBROWSING_TIMEOUT_MS }) {
  const cache = new LRUCache({ max: SAFEBROWSING_CACHE_MAX, ttlMs: SAFEBROWSING_CACHE_TTL_MS, now });
  const NOT_CHECKED = Object.freeze({ hit: false, checked: false });

  /** @param {string[]} input */
  async function check(input) {
    const urls = [...new Set(input)];
    const cached = urls.map((u) => cache.get(u));
    if (cached.some((v) => v === true)) return { hit: true, checked: true };
    const missing = urls.filter((_, i) => cached[i] === undefined);
    if (missing.length === 0) return { hit: false, checked: true };

    const key = env.GOOGLE_SAFE_BROWSING_KEY;
    if (!key) return NOT_CHECKED;

    let data;
    try {
      // The key stays in the query string of this server-side request only; it is never logged.
      const res = await fetchImpl(`${SAFEBROWSING_ENDPOINT}?key=${encodeURIComponent(key)}`, {
        method: "POST",
        headers: { "content-type": "application/json", "user-agent": USER_AGENT },
        body: JSON.stringify(buildRequestBody(missing)),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) {
        console.warn(`safebrowsing: upstream status ${res.status}`);
        return NOT_CHECKED;
      }
      const parsed = responseSchema.safeParse(await res.json());
      if (!parsed.success) return NOT_CHECKED;
      data = parsed.data;
    } catch {
      return NOT_CHECKED;
    }

    const hits = new Map();
    for (const m of data.matches ?? []) {
      const ttl = parseDuration(m.cacheDuration);
      hits.set(m.threat.url, Math.min(hits.get(m.threat.url) ?? Infinity, ttl ?? SAFEBROWSING_CACHE_TTL_MS));
    }
    for (const u of missing) {
      if (hits.has(u)) cache.set(u, true, hits.get(u));
      else cache.set(u, false);
    }
    return { hit: hits.size > 0, checked: true };
  }

  return { check, cache };
}

export function createSafeBrowsingRouter(deps) {
  const checker = createSafeBrowsingChecker(deps);
  const router = Router();
  router.post("/safebrowsing", async (req, res) => {
    const body = parseBody(bodySchema, req, res);
    if (!body) return;
    res.json(await checker.check(body.urls));
  });
  return router;
}
