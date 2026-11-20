// Daily call budget (per UTC day) and per-IP rate limiters.
import { rateLimit } from "express-rate-limit";
import { RATE_LIMIT_ANALYZE, RATE_LIMIT_API, RATE_WINDOW_MS } from "../config.js";

const utcDay = (ms) => new Date(ms).toISOString().slice(0, 10);

/** Counts calls per UTC day. tryConsume() is synchronous, so concurrent requests cannot overshoot. */
export class DailyBudget {
  /** @param {{ limit: number, now?: () => number }} opts */
  constructor({ limit, now = Date.now }) {
    this.limit = limit;
    this.now = now;
    this.day = utcDay(now());
    this.used = 0;
  }

  #roll() {
    const today = utcDay(this.now());
    if (today !== this.day) {
      this.day = today;
      this.used = 0;
    }
  }

  get remaining() {
    this.#roll();
    return Math.max(0, this.limit - this.used);
  }

  /** @returns {boolean} true if a call may be made (and counts it) */
  tryConsume() {
    this.#roll();
    if (this.used >= this.limit) return false;
    this.used += 1;
    return true;
  }
}

function limiter(limit) {
  return rateLimit({
    windowMs: RATE_WINDOW_MS,
    limit,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    handler: (_req, res) =>
      res.status(429).json({ error: "rate_limited", message: "Too many requests. Please wait a minute and try again." }),
  });
}

/** Fresh limiter instances (each has its own in-memory store). */
export function createRateLimiters() {
  return { api: limiter(RATE_LIMIT_API), analyze: limiter(RATE_LIMIT_ANALYZE) };
}
