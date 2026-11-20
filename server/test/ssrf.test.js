import { describe, expect, it, vi } from "vitest";
import {
  LookupError,
  SsrfError,
  assertSafeUrl,
  createSafeLookup,
  fetchHeadersOnly,
  parseSafeUrl,
} from "../src/security/ssrf.js";
import { fakeLookup, fakeResponse } from "./helpers.js";

const lookupImpl = fakeLookup({
  "public.example": "93.184.216.34",
  "v6.example": "2001:db8::10",
  "loopback.test": "127.0.0.1",
  "metadata.test": "169.254.169.254",
  "mixed.test": ["93.184.216.34", "10.0.0.5"],
  "mixed6.test": ["2001:db8::10", "::1"],
  "mapped.test": "::ffff:127.0.0.1",
});

const expectBlocked = async (url) => {
  await expect(assertSafeUrl(url, { lookupImpl })).rejects.toBeInstanceOf(SsrfError);
};

describe("parseSafeUrl / assertSafeUrl: syntax rules", () => {
  it.each([
    "file:///etc/passwd",
    "ftp://public.example/",
    "gopher://public.example/",
    "data:text/plain,hi",
    "javascript:alert(1)",
    "ws://public.example/",
  ])("rejects scheme %s", async (url) => {
    expect(() => parseSafeUrl(url)).toThrow(SsrfError);
    await expectBlocked(url);
  });

  it.each(["http://public.example:22/", "http://public.example:8080/", "https://public.example:8443/", "http://public.example:444/x"])(
    "rejects port in %s",
    async (url) => {
      await expectBlocked(url);
    },
  );

  it("allows default and explicit 80/443 ports", async () => {
    for (const url of ["http://public.example/", "http://public.example:80/", "https://public.example:443/", "http://public.example:443/", "https://public.example:80/"]) {
      await expect(assertSafeUrl(url, { lookupImpl })).resolves.toBeInstanceOf(URL);
    }
  });

  it.each(["http://user:pass@public.example/", "http://user@public.example/", "https://:secret@public.example/"])(
    "rejects credentials in %s",
    async (url) => {
      await expectBlocked(url);
    },
  );

  it("rejects garbage", async () => {
    await expectBlocked("not a url");
    await expectBlocked("");
  });
});

describe("assertSafeUrl: numeric hostname tricks", () => {
  it.each([
    ["decimal", "http://2130706433/"],
    ["octal", "http://0177.0.0.1/"],
    ["hex", "http://0x7f.1/"],
    ["hex dotted", "http://0x7f.0x0.0x0.0x1/"],
    ["short", "http://127.1/"],
    ["short two parts", "http://10.1/"],
    ["zero", "http://0/"],
    ["decimal metadata", "http://2852039166/"],
  ])("blocks %s form %s", async (_name, url) => {
    await expectBlocked(url);
  });

  it("judges the canonical address, not the text", () => {
    expect(parseSafeUrl("http://2130706433/").hostname).toBe("127.0.0.1");
    expect(parseSafeUrl("http://0x7f.1/").hostname).toBe("127.0.0.1");
  });
});

describe("assertSafeUrl: resolved addresses", () => {
  it("allows a host that resolves to public addresses", async () => {
    await expect(assertSafeUrl("https://public.example/path?q=1", { lookupImpl })).resolves.toBeInstanceOf(URL);
    await expect(assertSafeUrl("https://v6.example/", { lookupImpl })).resolves.toBeInstanceOf(URL);
  });

  it("blocks a hostname that resolves to 127.0.0.1", async () => {
    await expectBlocked("http://loopback.test/");
  });

  it("blocks a hostname with one public and one private address", async () => {
    await expectBlocked("http://mixed.test/");
    await expectBlocked("http://mixed6.test/");
  });

  it("blocks 169.254.169.254 literally and via DNS", async () => {
    await expectBlocked("http://169.254.169.254/latest/meta-data/");
    await expectBlocked("http://metadata.test/");
  });

  it("blocks [::1] and [::ffff:127.0.0.1]", async () => {
    await expectBlocked("http://[::1]/");
    await expectBlocked("http://[::ffff:127.0.0.1]/");
    await expectBlocked("http://mapped.test/");
  });

  it("allows a public IP literal without calling DNS", async () => {
    const lk = fakeLookup({});
    await expect(assertSafeUrl("http://93.184.216.34/", { lookupImpl: lk })).resolves.toBeInstanceOf(URL);
    expect(lk.calls).toEqual([]);
  });

  it("reports an unknown host as a lookup error, not a block", async () => {
    await expect(assertSafeUrl("http://nowhere.invalid/", { lookupImpl })).rejects.toBeInstanceOf(LookupError);
  });
});

describe("createSafeLookup", () => {
  const safeLookup = createSafeLookup(lookupImpl);
  const call = (host, opts) =>
    new Promise((resolve) => safeLookup(host, opts, (err, address, family) => resolve({ err, address, family })));

  it("hands out checked addresses (all: true and all: false)", async () => {
    const all = await call("public.example", { all: true });
    expect(all.err).toBeNull();
    expect(all.address).toEqual([{ address: "93.184.216.34", family: 4 }]);
    const one = await call("public.example", {});
    expect(one).toMatchObject({ err: null, address: "93.184.216.34", family: 4 });
  });

  it("refuses when any resolved address is blocked", async () => {
    const r = await call("mixed.test", { all: true });
    expect(r.err).toBeInstanceOf(Error);
    expect(r.err.code).toBe("EBLOCKED");
    expect(r.address).toBeUndefined();
  });

  it("re-resolves on every call, so a rebinding answer is caught", async () => {
    let n = 0;
    const rebinding = (host, opts, cb) => {
      n += 1;
      const address = n === 1 ? "93.184.216.34" : "127.0.0.1";
      queueMicrotask(() => cb(null, [{ address, family: 4 }]));
    };
    const lookup = createSafeLookup(rebinding);
    await expect(assertSafeUrl("http://rebind.test/", { lookupImpl: rebinding })).resolves.toBeInstanceOf(URL);
    const r = await new Promise((resolve) => lookup("rebind.test", { all: true }, (err) => resolve(err)));
    expect(r.code).toBe("EBLOCKED");
  });

  it("filters by requested family", async () => {
    const r = await call("public.example", { family: 6 });
    expect(r.err.code).toBe("ENOTFOUND");
  });
});

describe("fetchHeadersOnly", () => {
  it("uses HEAD with manual redirects, our User-Agent and no credentials", async () => {
    const fetchImpl = vi.fn(async () => fakeResponse(301, { headers: { Location: "https://next.example/" } }));
    const r = await fetchHeadersOnly("https://public.example/", { fetchImpl, lookupImpl });
    expect(r).toEqual({ status: 301, location: "https://next.example/" });
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe("https://public.example/");
    expect(init.method).toBe("HEAD");
    expect(init.redirect).toBe("manual");
    expect(init.headers["user-agent"]).toBe("ThreatPeek/0.1");
    expect(Object.keys(init.headers).map((k) => k.toLowerCase())).not.toContain("cookie");
    expect(Object.keys(init.headers).map((k) => k.toLowerCase())).not.toContain("authorization");
    expect(init.dispatcher).toBeDefined();
  });

  it.each([405, 501])("retries once with GET on %i and does not read the body", async (status) => {
    const getRes = fakeResponse(200);
    const fetchImpl = vi.fn(async (_u, init) => (init.method === "HEAD" ? fakeResponse(status) : getRes));
    const r = await fetchHeadersOnly("https://public.example/", { fetchImpl, lookupImpl });
    expect(r).toEqual({ status: 200, location: null });
    expect(fetchImpl.mock.calls.map(([, i]) => i.method)).toEqual(["HEAD", "GET"]);
    expect(getRes.cancelled).toBe(true);
  });

  it("with the real HTTP agent, never connects to an address the safe lookup refused", async () => {
    // A local server that records any hit. DNS for rebind.test answers 127.0.0.1.
    const { createServer } = await import("node:http");
    let hits = 0;
    const server = createServer((_req, res) => {
      hits += 1;
      res.end("x");
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address();
    try {
      const lk = fakeLookup({ "rebind.test": "127.0.0.1" });
      // Port check is bypassed on purpose here (fetchHeadersOnly assumes a pre-checked URL);
      // this isolates the connect-time lookup guard.
      await expect(fetchHeadersOnly(`http://rebind.test:${port}/`, { lookupImpl: lk })).rejects.toThrow();
      expect(hits).toBe(0);
      expect(lk.calls).toContain("rebind.test");
    } finally {
      await new Promise((r) => server.close(r));
    }
  });

  it("does not retry on other statuses", async () => {
    const fetchImpl = vi.fn(async () => fakeResponse(404));
    await fetchHeadersOnly("https://public.example/", { fetchImpl, lookupImpl });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});
