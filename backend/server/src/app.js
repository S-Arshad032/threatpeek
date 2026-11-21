// Builds the Express app. Network pieces are injectable so tests never touch the real network.
import dns from "node:dns";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { BODY_LIMIT, CONTENT_SECURITY_POLICY, DEFAULT_STATIC_DIR, HSTS_MAX_AGE_SECONDS } from "./config.js";
import { loadEnv } from "./env.js";
import { sendError } from "./lib/http.js";
import { createRateLimiters } from "./lib/limits.js";
import { createAnalyzeRouter } from "./routes/analyze.js";
import { createSafeBrowsingRouter } from "./routes/safebrowsing.js";
import { createUnwrapRouter } from "./routes/unwrap.js";

// backend/server/ : base for a relative STATIC_DIR.
const SERVER_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** Absolute path of the built frontend: STATIC_DIR (absolute, or relative to backend/server/) or the default. */
export function resolveStaticDir(staticDir) {
  return path.resolve(SERVER_ROOT, staticDir ?? DEFAULT_STATIC_DIR);
}

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

/** Security headers on every response (API, static files and the SPA fallback). */
function securityHeaders({ production }) {
  return (_req, res, next) => {
    res.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
    // Browsers ignore HSTS on plain http, so this only takes effect behind HTTPS.
    if (production) res.setHeader("Strict-Transport-Security", `max-age=${HSTS_MAX_AGE_SECONDS}`);
    next();
  };
}

/**
 * @param {{
 *   env?: ReturnType<typeof loadEnv>,
 *   fetchImpl?: Function,      // used for Safe Browsing, OpenRouter and unwrap hops
 *   lookupImpl?: Function,     // callback-style dns.lookup used by the SSRF guard
 *   now?: () => number,
 *   clientDist?: string,       // overrides STATIC_DIR (tests); served when NODE_ENV=production or STATIC_DIR is set
 * }} [deps]
 */
export function createApp({ env = loadEnv({}), fetchImpl, lookupImpl = dns.lookup, now = Date.now, clientDist } = {}) {
  const app = express();
  app.disable("x-powered-by");
  // false by default: X-Forwarded-For is ignored and req.ip is the socket address. Behind a proxy,
  // TRUST_PROXY makes req.ip (and so the rate-limit key) the real client IP.
  app.set("trust proxy", env.TRUST_PROXY);
  app.use(securityHeaders({ production: env.NODE_ENV === "production" }));

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

  // /api is fully handled above (including its JSON 404), so nothing below ever answers an /api path.
  if (env.serveStatic) {
    const staticDir = clientDist ?? resolveStaticDir(env.STATIC_DIR);
    const indexHtml = path.join(staticDir, "index.html");
    if (existsSync(indexHtml)) {
      app.use(express.static(staticDir, { index: "index.html" }));
      // SPA fallback: any other GET/HEAD gets index.html so client-side routes work on reload.
      app.use((req, res, next) => {
        if (req.method !== "GET" && req.method !== "HEAD") return next();
        res.sendFile(indexHtml);
      });
    } else {
      console.warn(
        `static: ${indexHtml} not found. Run "npm run build" in the repository root (or set STATIC_DIR). Serving the API only.`,
      );
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
