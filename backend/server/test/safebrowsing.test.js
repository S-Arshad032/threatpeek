import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createSafeBrowsingChecker, createSafeBrowsingRouter } from "../src/routes/safebrowsing.js";
import { fakeResponse, hangingFetch } from "./helpers.js";

const env = { GOOGLE_SAFE_BROWSING_KEY: "test-key-123" };
const BAD = "http://malware.test/payload";
const GOOD = "https://fine.example/";

const matchResponse = (url, cacheDuration = "300s") =>
  fakeResponse(200, {
    json: {
      matches: [
        {
          threatType: "MALWARE",
          platformType: "ANY_PLATFORM",
          threatEntryType: "URL",
          threat: { url },
          cacheDuration,
        },
      ],
    },
  });

describe("safe browsing checker", () => {
  it("reports a hit and sends the documented v4 request", async () => {
    const fetchImpl = vi.fn(async () => matchResponse(BAD));
    const { check } = createSafeBrowsingChecker({ env, fetchImpl });
    expect(await check([BAD, GOOD])).toEqual({ hit: true, checked: true });

    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=test-key-123");
    expect(init.method).toBe("POST");
    expect(init.headers["user-agent"]).toBe("ThreatPeek/0.1");
    expect(init.signal).toBeInstanceOf(AbortSignal);
    const body = JSON.parse(init.body);
    expect(body.client.clientId).toBe("threatpeek");
    expect(body.threatInfo.threatEntryTypes).toEqual(["URL"]);
    expect(body.threatInfo.threatTypes).toContain("SOCIAL_ENGINEERING");
    expect(body.threatInfo.threatEntries).toEqual([{ url: BAD }, { url: GOOD }]);
    expect(JSON.stringify(body)).not.toContain("test-key-123");
  });

  it("reports no hit on an empty object", async () => {
    const fetchImpl = vi.fn(async () => fakeResponse(200, { json: {} }));
    const { check } = createSafeBrowsingChecker({ env, fetchImpl });
    expect(await check([GOOD])).toEqual({ hit: false, checked: true });
  });

  it("degrades without a key and never calls out", async () => {
    const fetchImpl = vi.fn();
    const { check } = createSafeBrowsingChecker({ env: {}, fetchImpl });
    expect(await check([BAD])).toEqual({ hit: false, checked: false });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("degrades on HTTP 500", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const fetchImpl = vi.fn(async () => fakeResponse(500));
    const { check } = createSafeBrowsingChecker({ env, fetchImpl });
    expect(await check([BAD])).toEqual({ hit: false, checked: false });
    expect(warn.mock.calls.flat().join(" ")).not.toContain("test-key-123");
    warn.mockRestore();
  });

  it("degrades on a malformed answer", async () => {
    const fetchImpl = vi.fn(async () => fakeResponse(200, { json: { matches: "nope" } }));
    const { check } = createSafeBrowsingChecker({ env, fetchImpl });
    expect(await check([BAD])).toEqual({ hit: false, checked: false });
  });

  it("degrades on a timeout", async () => {
    const fetchImpl = vi.fn(hangingFetch());
    const { check } = createSafeBrowsingChecker({ env, fetchImpl, timeoutMs: 30 });
    expect(await check([BAD])).toEqual({ hit: false, checked: false });
  });

  it("serves repeated URLs from the cache", async () => {
    const fetchImpl = vi.fn(async () => fakeResponse(200, { json: {} }));
    const { check } = createSafeBrowsingChecker({ env, fetchImpl });
    await check([GOOD]);
    expect(await check([GOOD])).toEqual({ hit: false, checked: true });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("caches a miss for 1 hour", async () => {
    let t = 0;
    const fetchImpl = vi.fn(async () => fakeResponse(200, { json: {} }));
    const { check } = createSafeBrowsingChecker({ env, fetchImpl, now: () => t });
    await check([GOOD]);
    t = 60 * 60 * 1000 - 1;
    await check([GOOD]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    t = 60 * 60 * 1000;
    await check([GOOD]);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("caches a hit no longer than Google's cacheDuration", async () => {
    let t = 0;
    const fetchImpl = vi.fn(async () => matchResponse(BAD, "300.000s"));
    const { check } = createSafeBrowsingChecker({ env, fetchImpl, now: () => t });
    await check([BAD]);
    t = 299_000;
    expect(await check([BAD])).toEqual({ hit: true, checked: true });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    t = 300_000;
    await check([BAD]);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("only asks Google about URLs not in the cache", async () => {
    const fetchImpl = vi.fn(async () => fakeResponse(200, { json: {} }));
    const { check } = createSafeBrowsingChecker({ env, fetchImpl });
    await check([GOOD]);
    await check([GOOD, "https://other.example/"]);
    const body = JSON.parse(fetchImpl.mock.calls[1][1].body);
    expect(body.threatInfo.threatEntries).toEqual([{ url: "https://other.example/" }]);
  });
});

describe("POST /safebrowsing", () => {
  const appWith = (deps) => {
    const app = express();
    app.use(express.json());
    app.use("/api", createSafeBrowsingRouter(deps));
    return app;
  };

  it("returns 200 with the result", async () => {
    const fetchImpl = vi.fn(async () => matchResponse(BAD));
    const res = await request(appWith({ env, fetchImpl })).post("/api/safebrowsing").send({ urls: [BAD] });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ hit: true, checked: true });
  });

  it("returns 200 not-checked without a key", async () => {
    const res = await request(appWith({ env: {}, fetchImpl: vi.fn() })).post("/api/safebrowsing").send({ urls: [BAD] });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ hit: false, checked: false });
  });

  it.each([
    [{}],
    [{ urls: [] }],
    [{ urls: "http://a.example/" }],
    [{ urls: ["ftp://a.example/"] }],
    [{ urls: ["not a url"] }],
    [{ urls: Array.from({ length: 11 }, (_, i) => `https://a${i}.example/`) }],
  ])("answers 400 for %j", async (body) => {
    const res = await request(appWith({ env, fetchImpl: vi.fn() })).post("/api/safebrowsing").send(body);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
  });
});
