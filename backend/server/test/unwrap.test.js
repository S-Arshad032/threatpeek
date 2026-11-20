import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createUnwrapRouter, unwrapUrl } from "../src/routes/unwrap.js";
import { fakeLookup, fakeResponse, hangingFetch } from "./helpers.js";

const lookupImpl = fakeLookup({
  "short.example": "93.184.216.34",
  "mid.example": "93.184.216.35",
  "final.example": "93.184.216.36",
  "loop-a.example": "93.184.216.37",
  "loop-b.example": "93.184.216.38",
  "slow.example": "93.184.216.39",
  "internal.test": "10.0.0.7",
});

/** fetch fake driven by a map of url -> [status, location?]. */
function routeFetch(routes) {
  return vi.fn(async (url, init) => {
    const r = routes[url];
    if (!r) throw new Error(`unexpected fetch ${url}`);
    if (typeof r === "function") return r(init);
    const [status, location] = r;
    return fakeResponse(status, { headers: location ? { location } : {} });
  });
}

describe("unwrapUrl", () => {
  it("follows a normal chain of 3 hops", async () => {
    const fetchImpl = routeFetch({
      "https://short.example/abc": [301, "https://mid.example/x"],
      "https://mid.example/x": [302, "/landing?id=1"],
      "https://mid.example/landing?id=1": [307, "https://final.example/page"],
      "https://final.example/page": [200],
    });
    const r = await unwrapUrl("https://short.example/abc", { fetchImpl, lookupImpl });
    expect(r).toEqual({
      finalUrl: "https://final.example/page",
      hops: [
        "https://short.example/abc",
        "https://mid.example/x",
        "https://mid.example/landing?id=1",
        "https://final.example/page",
      ],
      truncated: false,
    });
    expect(fetchImpl.mock.calls.every(([, init]) => init.method === "HEAD")).toBe(true);
  });

  it("returns the URL itself when there is no redirect", async () => {
    const fetchImpl = routeFetch({ "https://final.example/": [200] });
    const r = await unwrapUrl("https://final.example/", { fetchImpl, lookupImpl });
    expect(r).toEqual({ finalUrl: "https://final.example/", hops: ["https://final.example/"], truncated: false });
  });

  it("stops at a redirect to a private IP and never requests it", async () => {
    const fetchImpl = routeFetch({
      "https://short.example/a": [301, "https://mid.example/b"],
      "https://mid.example/b": [302, "http://192.168.1.1/admin"],
    });
    const r = await unwrapUrl("https://short.example/a", { fetchImpl, lookupImpl });
    expect(r).toEqual({
      finalUrl: "https://mid.example/b",
      hops: ["https://short.example/a", "https://mid.example/b"],
      truncated: true,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("stops at a redirect to a hostname that resolves privately", async () => {
    const fetchImpl = routeFetch({ "https://short.example/a": [301, "http://internal.test/"] });
    const r = await unwrapUrl("https://short.example/a", { fetchImpl, lookupImpl });
    expect(r).toMatchObject({ finalUrl: "https://short.example/a", truncated: true });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("stops at a redirect to a blocked scheme or port", async () => {
    for (const target of ["file:///etc/passwd", "http://final.example:8080/", "http://u:p@final.example/"]) {
      const fetchImpl = routeFetch({ "https://short.example/a": [301, target] });
      const r = await unwrapUrl("https://short.example/a", { fetchImpl, lookupImpl });
      expect(r).toMatchObject({ finalUrl: "https://short.example/a", truncated: true });
    }
  });

  it("stops a redirect loop after 5 hops", async () => {
    const fetchImpl = routeFetch({
      "https://loop-a.example/": [302, "https://loop-b.example/"],
      "https://loop-b.example/": [302, "https://loop-a.example/"],
    });
    const r = await unwrapUrl("https://loop-a.example/", { fetchImpl, lookupImpl });
    expect(r.truncated).toBe(true);
    expect(r.hops).toHaveLength(5);
    expect(fetchImpl).toHaveBeenCalledTimes(5);
    expect(r.finalUrl).toBe("https://loop-a.example/");
  });

  it("stops when a hop times out (total budget)", async () => {
    const fetchImpl = vi.fn(async (url, init) => {
      if (url === "https://short.example/a") return fakeResponse(301, { headers: { location: "https://slow.example/" } });
      return hangingFetch()(url, init);
    });
    const started = Date.now();
    const r = await unwrapUrl("https://short.example/a", { fetchImpl, lookupImpl, timeoutMs: 50 });
    expect(Date.now() - started).toBeLessThan(2000);
    expect(r).toEqual({
      finalUrl: "https://slow.example/",
      hops: ["https://short.example/a", "https://slow.example/"],
      truncated: true,
    });
  });

  it("uses the 10 s budget by default", async () => {
    vi.useFakeTimers();
    try {
      const fetchImpl = vi.fn(hangingFetch());
      const p = unwrapUrl("https://slow.example/", { fetchImpl, lookupImpl });
      await vi.advanceTimersByTimeAsync(9_999);
      let settled = false;
      p.then(() => (settled = true));
      await vi.advanceTimersByTimeAsync(0);
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await expect(p).resolves.toMatchObject({ truncated: true });
    } finally {
      vi.useRealTimers();
    }
  });

  it("falls back to GET on 405 per hop", async () => {
    const fetchImpl = vi.fn(async (url, init) => {
      if (url === "https://short.example/a") {
        return init.method === "HEAD" ? fakeResponse(405) : fakeResponse(302, { headers: { location: "https://final.example/" } });
      }
      return fakeResponse(200);
    });
    const r = await unwrapUrl("https://short.example/a", { fetchImpl, lookupImpl });
    expect(r).toMatchObject({ finalUrl: "https://final.example/", truncated: false });
    expect(fetchImpl.mock.calls.map(([u, i]) => `${i.method} ${u}`)).toEqual([
      "HEAD https://short.example/a",
      "GET https://short.example/a",
      "HEAD https://final.example/",
    ]);
  });

  it("degrades on a network error mid-chain", async () => {
    const fetchImpl = vi.fn(async (url) => {
      if (url === "https://short.example/a") return fakeResponse(301, { headers: { location: "https://mid.example/" } });
      throw new TypeError("fetch failed");
    });
    const r = await unwrapUrl("https://short.example/a", { fetchImpl, lookupImpl });
    expect(r).toMatchObject({ finalUrl: "https://mid.example/", truncated: true });
  });

  it("throws for a blocked first URL", async () => {
    await expect(unwrapUrl("http://127.0.0.1/", { fetchImpl: vi.fn(), lookupImpl })).rejects.toMatchObject({ code: "blocked_url" });
  });
});

describe("POST /unwrap", () => {
  const appWith = (deps) => {
    const app = express();
    app.use(express.json());
    app.use("/api", createUnwrapRouter(deps));
    return app;
  };

  it("returns the chain as JSON", async () => {
    const fetchImpl = routeFetch({
      "https://short.example/a": [301, "https://final.example/"],
      "https://final.example/": [200],
    });
    const res = await request(appWith({ fetchImpl, lookupImpl })).post("/api/unwrap").send({ url: "https://short.example/a" });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ finalUrl: "https://final.example/", hops: ["https://short.example/a", "https://final.example/"], truncated: false });
  });

  it.each(["file:///etc/passwd", "http://localhost.example:22/", "http://169.254.169.254/", "http://[::1]/", "http://2130706433/"])(
    "answers 400 blocked_url for %s",
    async (url) => {
      const fetchImpl = vi.fn();
      const res = await request(appWith({ fetchImpl, lookupImpl })).post("/api/unwrap").send({ url });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("blocked_url");
      expect(typeof res.body.message).toBe("string");
      expect(fetchImpl).not.toHaveBeenCalled();
    },
  );

  it("answers 400 invalid_request for a bad body", async () => {
    const app = appWith({ fetchImpl: vi.fn(), lookupImpl });
    for (const body of [{}, { url: 5 }, { url: "" }, { url: "x".repeat(4001) }]) {
      const res = await request(app).post("/api/unwrap").send(body);
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("invalid_request");
    }
  });
});
