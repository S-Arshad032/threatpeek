import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createApp, resolveStaticDir } from "../src/app.js";
import { loadEnv } from "../src/env.js";
import { fakeLookup, fakeResponse } from "./helpers.js";

const lookupImpl = fakeLookup({ "public.example": "93.184.216.34" });
const env = loadEnv({ ALLOWED_ORIGINS: "http://localhost:5173,https://app.example" });
const make = (over = {}) => createApp({ env, lookupImpl, fetchImpl: vi.fn(async () => fakeResponse(200, { json: {} })), ...over });

describe("app basics", () => {
  it("GET /api/health", async () => {
    const res = await request(make()).get("/api/health");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
    expect(res.headers["x-powered-by"]).toBeUndefined();
  });

  it("unknown /api route gives JSON 404", async () => {
    const res = await request(make()).get("/api/nope");
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: "not_found", message: expect.any(String) });
  });
});

describe("bad bodies", () => {
  it.each([
    ["/api/unwrap", {}],
    ["/api/unwrap", { url: 42 }],
    ["/api/safebrowsing", { urls: [] }],
    ["/api/safebrowsing", { urls: ["javascript:alert(1)"] }],
    ["/api/analyze", { text: "" }],
    ["/api/analyze", { text: "x".repeat(4001) }],
    ["/api/analyze", []],
  ])("POST %s %j gives 400 JSON", async (route, body) => {
    const res = await request(make()).post(route).send(body);
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: "invalid_request", message: expect.any(String) });
  });

  it("malformed JSON gives 400 invalid_json without a stack trace", async () => {
    const res = await request(make()).post("/api/analyze").set("content-type", "application/json").send('{"text": "oops');
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: "invalid_json", message: "The request body is not valid JSON." });
    expect(res.text).not.toMatch(/at .*\.js/);
  });

  it("a 17 kB body gives 413 JSON", async () => {
    const res = await request(make())
      .post("/api/analyze")
      .set("content-type", "application/json")
      .send(JSON.stringify({ text: "x".repeat(17 * 1024) }));
    expect(res.status).toBe(413);
    expect(res.body).toEqual({ error: "payload_too_large", message: expect.any(String) });
  });

  it("a body just under 16 kB is parsed (then rejected by length validation)", async () => {
    const res = await request(make()).post("/api/analyze").send({ text: "x".repeat(15 * 1024) });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
  });

  it("blocked unwrap URL gives 400 blocked_url", async () => {
    const res = await request(make()).post("/api/unwrap").send({ url: "http://169.254.169.254/latest/meta-data/" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("blocked_url");
  });
});

describe("rate limits", () => {
  it("allows 30 /api requests per minute, then 429 rate_limited", async () => {
    const app = make();
    for (let i = 0; i < 30; i++) {
      const res = await request(app).get("/api/health");
      expect(res.status).toBe(200);
    }
    const res = await request(app).get("/api/health");
    expect(res.status).toBe(429);
    expect(res.body).toEqual({ error: "rate_limited", message: expect.any(String) });
  });

  it("allows only 10 /api/analyze requests per minute", async () => {
    const app = make();
    for (let i = 0; i < 10; i++) {
      const res = await request(app).post("/api/analyze").send({ text: `hi ${i}` });
      expect(res.status).toBe(200);
    }
    const res = await request(app).post("/api/analyze").send({ text: "hi" });
    expect(res.status).toBe(429);
    expect(res.body.error).toBe("rate_limited");
    // Other routes still work (11 of 30 used).
    expect((await request(app).get("/api/health")).status).toBe(200);
  });

  it("each app has its own counters", async () => {
    const a = make();
    for (let i = 0; i < 30; i++) await request(a).get("/api/health");
    expect((await request(make()).get("/api/health")).status).toBe(200);
  });
});

describe("CORS", () => {
  it("allows a listed origin", async () => {
    const res = await request(make()).get("/api/health").set("Origin", "https://app.example");
    expect(res.headers["access-control-allow-origin"]).toBe("https://app.example");
    expect(res.headers.vary).toMatch(/Origin/);
  });

  it("does not allow an unlisted origin", async () => {
    const res = await request(make()).get("/api/health").set("Origin", "https://evil.test");
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("answers preflight only for listed origins", async () => {
    const ok = await request(make())
      .options("/api/analyze")
      .set("Origin", "http://localhost:5173")
      .set("Access-Control-Request-Method", "POST");
    expect(ok.status).toBe(204);
    expect(ok.headers["access-control-allow-origin"]).toBe("http://localhost:5173");
    expect(ok.headers["access-control-allow-headers"]).toMatch(/Content-Type/i);

    const bad = await request(make())
      .options("/api/analyze")
      .set("Origin", "https://evil.test")
      .set("Access-Control-Request-Method", "POST");
    expect(bad.headers["access-control-allow-origin"]).toBeUndefined();
    expect(bad.headers["access-control-allow-methods"]).toBeUndefined();
  });

  it("defaults to http://localhost:5173 only", async () => {
    const app = createApp({ env: loadEnv({}), lookupImpl });
    expect((await request(app).get("/api/health").set("Origin", "http://localhost:5173")).headers["access-control-allow-origin"]).toBe(
      "http://localhost:5173",
    );
    expect((await request(app).get("/api/health").set("Origin", "http://localhost:3000")).headers["access-control-allow-origin"]).toBeUndefined();
  });
});

describe("static hosting", () => {
  let dist;
  beforeAll(() => {
    dist = mkdtempSync(path.join(tmpdir(), "tp-dist-"));
    mkdirSync(path.join(dist, "assets"));
    writeFileSync(path.join(dist, "index.html"), "<!doctype html><title>ThreatPeek</title>");
    writeFileSync(path.join(dist, "assets", "app.js"), "console.log(1)");
  });
  afterAll(() => rmSync(dist, { recursive: true, force: true }));

  it("serves frontend/dist with an index.html fallback in production", async () => {
    const app = createApp({ env: loadEnv({ NODE_ENV: "production" }), lookupImpl, clientDist: dist });
    const asset = await request(app).get("/assets/app.js");
    expect(asset.status).toBe(200);
    expect(asset.text).toContain("console.log");
    const deep = await request(app).get("/history/123");
    expect(deep.status).toBe(200);
    expect(deep.text).toContain("<title>ThreatPeek</title>");
    expect((await request(app).get("/api/health")).body).toEqual({ ok: true });
    const apiMiss = await request(app).get("/api/nope");
    expect(apiMiss.status).toBe(404);
    expect(apiMiss.headers["content-type"]).toMatch(/application\/json/);
    expect(apiMiss.body.error).toBe("not_found");
    expect((await request(app).get("/api")).body.error).toBe("not_found");
    const post = await request(app).post("/history/123");
    expect(post.status).toBe(404);
    expect(post.body.error).toBe("not_found");
  });

  it("serves STATIC_DIR outside production too", async () => {
    const app = createApp({ env: loadEnv({ STATIC_DIR: dist }), lookupImpl });
    const res = await request(app).get("/");
    expect(res.status).toBe(200);
    expect(res.text).toContain("<title>ThreatPeek</title>");
  });

  it("resolves a relative STATIC_DIR against backend/server/", () => {
    const serverRoot = path.resolve(import.meta.dirname, "..");
    expect(resolveStaticDir(undefined)).toBe(path.resolve(serverRoot, "../../frontend/dist"));
    expect(resolveStaticDir("public")).toBe(path.join(serverRoot, "public"));
    expect(resolveStaticDir(dist)).toBe(dist);
  });

  it("warns and keeps the API working when the directory is missing", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const missing = path.join(dist, "does-not-exist");
      const app = createApp({ env: loadEnv({ NODE_ENV: "production", STATIC_DIR: missing }), lookupImpl });
      expect(warn).toHaveBeenCalledWith(expect.stringContaining("not found"));
      expect((await request(app).get("/api/health")).body).toEqual({ ok: true });
      expect((await request(app).get("/")).body.error).toBe("not_found");
    } finally {
      warn.mockRestore();
    }
  });

  it("does not serve static files outside production", async () => {
    const app = createApp({ env: loadEnv({ NODE_ENV: "development" }), lookupImpl, clientDist: dist });
    const res = await request(app).get("/");
    expect(res.status).toBe(404);
    expect(res.body.error).toBe("not_found");
  });
});

describe("security headers", () => {
  it("sets a CSP that allows only same-origin scripts, styles and API calls", async () => {
    const res = await request(make()).get("/api/health");
    const csp = res.headers["content-security-policy"];
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("style-src 'self'");
    expect(csp).toContain("img-src 'self' data:");
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("unsafe-eval");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["x-frame-options"]).toBe("DENY");
    expect(res.headers["referrer-policy"]).toBe("no-referrer");
    expect(res.headers["strict-transport-security"]).toBeUndefined();
  });

  it("adds HSTS in production, also on JSON errors", async () => {
    vi.spyOn(console, "warn").mockImplementationOnce(() => {});
    const app = createApp({ env: loadEnv({ NODE_ENV: "production", STATIC_DIR: path.join(tmpdir(), "tp-none") }), lookupImpl });
    const res = await request(app).get("/api/nope");
    expect(res.headers["strict-transport-security"]).toMatch(/^max-age=\d+$/);
    expect(res.headers["content-security-policy"]).toBeDefined();
  });
});

describe("trust proxy", () => {
  const exhaust = async (app, xff) => {
    for (let i = 0; i < 30; i++) await request(app).get("/api/health").set("X-Forwarded-For", xff);
  };

  it("ignores X-Forwarded-For by default, so a client cannot dodge the rate limit", async () => {
    const app = make();
    await exhaust(app, "203.0.113.1");
    const res = await request(app).get("/api/health").set("X-Forwarded-For", "203.0.113.2");
    expect(res.status).toBe(429);
  });

  it("with TRUST_PROXY=1, rate limits each real client IP separately", async () => {
    const app = make({ env: loadEnv({ TRUST_PROXY: "1" }) });
    expect(app.get("trust proxy")).toBe(1);
    await exhaust(app, "203.0.113.1");
    expect((await request(app).get("/api/health").set("X-Forwarded-For", "203.0.113.1")).status).toBe(429);
    expect((await request(app).get("/api/health").set("X-Forwarded-For", "203.0.113.2")).status).toBe(200);
    // Only the last hop is trusted: a faked left-most entry does not change the key.
    expect((await request(app).get("/api/health").set("X-Forwarded-For", "198.51.100.9, 203.0.113.1")).status).toBe(429);
  });
});
