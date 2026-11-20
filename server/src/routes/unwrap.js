// POST /api/unwrap: follows redirects manually and returns only the final URL.
import dns from "node:dns";
import { Router } from "express";
import { z } from "zod";
import { MAX_INPUT_LENGTH, UNWRAP_MAX_HOPS, UNWRAP_TOTAL_TIMEOUT_MS } from "../config.js";
import { parseBody, sendError } from "../lib/http.js";
import { SsrfError, assertSafeUrl, fetchHeadersOnly, parseSafeUrl } from "../security/ssrf.js";

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

const bodySchema = z.object({ url: z.string().trim().min(1).max(MAX_INPUT_LENGTH) });

/**
 * Follows a redirect chain. Every hop is checked by assertSafeUrl before it is requested.
 * The first URL failing the SSRF check throws SsrfError; any later failure (blocked hop,
 * timeout, network error, too many hops) ends the chain with truncated: true.
 *
 * `hops` lists every URL that passed the checks and was requested, in order (max UNWRAP_MAX_HOPS).
 *
 * @param {string} input
 * @param {{ fetchImpl?: Function, lookupImpl?: Function, timeoutMs?: number, maxHops?: number }} [deps]
 * @returns {Promise<{ finalUrl: string, hops: string[], truncated: boolean }>}
 */
export async function unwrapUrl(input, deps = {}) {
  const {
    fetchImpl,
    lookupImpl = dns.lookup,
    timeoutMs = UNWRAP_TOTAL_TIMEOUT_MS,
    maxHops = UNWRAP_MAX_HOPS,
  } = deps;

  // Syntax check first, so a blocked scheme/port/credential gives 400 without any network use.
  const start = parseSafeUrl(input);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("unwrap_timeout")), timeoutMs);
  const signal = controller.signal;

  const hops = [];
  let current = start;
  let lastSafe = start.href;
  try {
    for (;;) {
      try {
        current = await assertSafeUrl(current, { lookupImpl, signal });
      } catch (err) {
        if (hops.length === 0 && err instanceof SsrfError) throw err;
        return { finalUrl: lastSafe, hops, truncated: true };
      }
      lastSafe = current.href;
      hops.push(current.href);

      let answer;
      try {
        answer = await fetchHeadersOnly(current, { fetchImpl, lookupImpl, signal });
      } catch {
        return { finalUrl: lastSafe, hops, truncated: true };
      }

      if (!REDIRECT_STATUSES.has(answer.status) || !answer.location) {
        return { finalUrl: lastSafe, hops, truncated: false };
      }
      if (hops.length >= maxHops) {
        return { finalUrl: lastSafe, hops, truncated: true };
      }
      try {
        current = new URL(answer.location, current);
      } catch {
        return { finalUrl: lastSafe, hops, truncated: true };
      }
    }
  } finally {
    clearTimeout(timer);
  }
}

export function createUnwrapRouter(deps = {}) {
  const router = Router();
  router.post("/unwrap", async (req, res) => {
    const body = parseBody(bodySchema, req, res);
    if (!body) return;
    try {
      res.json(await unwrapUrl(body.url, deps));
    } catch (err) {
      if (err instanceof SsrfError) {
        return sendError(res, 400, "blocked_url", "This link cannot be checked: only public http and https addresses on ports 80 and 443 are allowed.");
      }
      throw err;
    }
  });
  return router;
}
