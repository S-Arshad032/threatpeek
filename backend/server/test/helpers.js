// Test helpers: fake DNS and fake fetch. Nothing here touches the network.

/**
 * Callback-style dns.lookup fake. `table` maps hostnames to an address or a list of addresses.
 * Unknown names fail with ENOTFOUND. IP literals resolve to themselves, like the real dns.lookup.
 */
export function fakeLookup(table = {}) {
  const calls = [];
  const fn = (hostname, options, callback) => {
    if (typeof options === "function") callback = options;
    calls.push(hostname);
    const entry = table[hostname];
    if (entry === undefined) {
      const err = new Error(`getaddrinfo ENOTFOUND ${hostname}`);
      err.code = "ENOTFOUND";
      return queueMicrotask(() => callback(err));
    }
    const list = (Array.isArray(entry) ? entry : [entry]).map((address) => ({
      address,
      family: address.includes(":") ? 6 : 4,
    }));
    queueMicrotask(() => (options?.all ? callback(null, list) : callback(null, list[0].address, list[0].family)));
  };
  fn.calls = calls;
  return fn;
}

/** Minimal Response-like object. */
export function fakeResponse(status, { headers = {}, json } = {}) {
  const h = new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  let cancelled = false;
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (k) => h.get(k.toLowerCase()) ?? null },
    body: {
      cancel: async () => {
        cancelled = true;
      },
    },
    get cancelled() {
      return cancelled;
    },
    json: async () => {
      if (json === undefined) throw new SyntaxError("no json");
      return typeof json === "function" ? json() : json;
    },
  };
}

/** fetch fake that never resolves until the signal aborts. */
export function hangingFetch() {
  return (_url, init) =>
    new Promise((_resolve, reject) => {
      const sig = init?.signal;
      if (!sig) return;
      const fail = () => reject(sig.reason ?? new DOMException("aborted", "AbortError"));
      if (sig.aborted) fail();
      else sig.addEventListener("abort", fail, { once: true });
    });
}
