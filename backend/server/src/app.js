// Builds the Express app. Network pieces are injectable so tests never touch the real network.
import dns from "node:dns";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { BODY_LIMIT } from "./config.js";
import { loadEnv } from "./env.js";
import { sendError } from "./lib/http.js";
import { createRateLimiters } from "./lib/limits.js";
import { createAnalyzeRouter } from "./routes/analyze.js";
import { createSafeBrowsingRouter } from "./routes/safebrowsing.js";
import { createUnwrapRouter } from "./routes/unwrap.js";

const DEFAULT_CLIENT_DIST = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../frontend/dist");

/** CORS: only origins listed in ALLOWED_ORIGINS get CORS headers. Others get none (browser blocks them). */
function cors(allowedOrigins) {
  const allowed = new Set(allowedOrigins);
  return (req, res, next) => {
    const origin = req.headers.origin;
    res.vary("Origin");
    const ok = typeof origin === "string" && allowed.has(origin);
    if (ok) {
      res.setHeader("Access-Control-Allow-Origin", origin);
    }
    if (req.method === "OPTIONS") {
      if (ok) {
        res.setHeader("Access-Control-Allow-Methods", "GET, POST");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type");
        res.setHeader("Access-Control-Max-Age", "600");
      }
      return res.status(204).end();
    }
    next();
  };
}

function securityHeaders(_req, res, next) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  next();
}

/**
 * @param {{
 *   env?: ReturnType<typeof loadEnv>,
 *   fetchImpl?: Function,      // used for Safe Browsing, OpenRouter and unwrap hops
 *   lookupImpl?: Function,     // callback-style dns.lookup used by the SSRF guard
 *   now?: () => number,
 *   clientDist?: string,       // static files served when NODE_ENV=production
 * }} [deps]
 */
export function createApp({ env = loadEnv({}), fetchImpl, lookupImpl = dns.lookup, now = Date.now, clientDist = DEFAULT_CLIENT_DIST } = {}) {
  const app = express();
  app.disable("x-powered-by");
  app.use(securityHeaders);

  const limiters = createRateLimiters();
  const apiFetch = fetchImpl ?? fetch;

  const api = express.Router();
  api.use(cors(env.ALLOWED_ORIGINS));
  api.use(limiters.api);
  api.use(express.json({ limit: BODY_LIMIT }));
  api.get("/health", (_req, res) => res.json({ ok: true }));
  // Unwrap uses undici's fetch with the SSRF-safe agent unless a fake is injected.
  api.use(createUnwrapRouter({ fetchImpl, lookupImpl }));
  api.use(createSafeBrowsingRouter({ env, fetchImpl: apiFetch, now }));
  api.use(createAnalyzeRouter({ env, fetchImpl: apiFetch, now }, { limiter: limiters.analyze }));
  api.use((_req, res) => sendError(res, 404, "not_found", "This API route does not exist."));
  app.use("/api", api);

  if (env.NODE_ENV === "production") {
    if (existsSync(path.join(clientDist, "index.html"))) {
      app.use(express.static(clientDist, { index: "index.html" }));
      app.use((req, res, next) => {
        if (req.method !== "GET" && req.method !== "HEAD") return next();
        res.sendFile(path.join(clientDist, "index.html"));
      });
    } else {
      console.warn("static: frontend/dist/index.html not found, serving the API only");
    }
  }

  app.use((_req, res) => sendError(res, 404, "not_found", "Nothing here."));

  // JSON error handler: plain English, no stack traces, no echo of the input.
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    if (res.headersSent) return;
    if (err?.type === "entity.too.large") {
      return sendError(res, 413, "payload_too_large", "The request is too large. The limit is 16 kB.");
    }
    if (err?.type === "entity.parse.failed") {
      return sendError(res, 400, "invalid_json", "The request body is not valid JSON.");
    }
    if (err?.type === "charset.unsupported" || err?.type === "encoding.unsupported") {
      return sendError(res, 415, "unsupported_encoding", "The request uses an unsupported encoding.");
    }
    if (typeof err?.status === "number" && err.status >= 400 && err.status < 500) {
      return sendError(res, err.status, "bad_request", "The request could not be processed.");
    }
    console.error(`internal error: ${err?.name ?? "unknown"}`);
    return sendError(res, 500, "internal_error", "Something went wrong on the server. Please try again later.");
  });

  return app;
}
