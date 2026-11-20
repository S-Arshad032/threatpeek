// SSRF guard for outgoing requests to user-supplied URLs.
//
// Two layers:
// 1. assertSafeUrl(): checks scheme, port and credentials, then resolves the hostname and checks
//    EVERY returned address. Numeric hostname tricks (2130706433, 0177.0.0.1, 0x7f.1, 127.1) are
//    normalized by the WHATWG URL parser to a canonical IP, which is then judged like any other
//    resolved address.
// 2. createSafeLookup(): a dns.lookup replacement used by the HTTP agent. The socket connects only
//    to addresses this function has checked, so DNS rebinding between step 1 and the connect
//    cannot swap in a private address. (For IP-literal hosts Node skips lookup entirely; those
//    cannot rebind and are already judged in step 1.)
import dns from "node:dns";
import { isIP } from "node:net";
import { Agent, fetch as undiciFetch } from "undici";
import { ALLOWED_PORTS, ALLOWED_PROTOCOLS, USER_AGENT } from "../config.js";
import { isBlockedAddress } from "./ip.js";

export class SsrfError extends Error {
  /** @param {string} reason internal reason, never shown to users */
  constructor(reason) {
    super(`blocked_url: ${reason}`);
    this.name = "SsrfError";
    this.code = "blocked_url";
    this.reason = reason;
  }
}

/** DNS failure (host does not exist, resolver down). Not a security block. */
export class LookupError extends Error {
  constructor(reason) {
    super(`lookup_failed: ${reason}`);
    this.name = "LookupError";
    this.code = "lookup_failed";
  }
}

const stripBrackets = (host) => (host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host);

/**
 * Synchronous checks that need no network: parseable, http(s), port 80/443, no credentials.
 * @param {string | URL} input
 * @returns {URL}
 */
export function parseSafeUrl(input) {
  let url;
  try {
    url = new URL(String(input));
  } catch {
    throw new SsrfError("unparseable");
  }
  if (!ALLOWED_PROTOCOLS.includes(url.protocol)) throw new SsrfError("protocol");
  if (!ALLOWED_PORTS.includes(url.port)) throw new SsrfError("port");
  if (url.username !== "" || url.password !== "") throw new SsrfError("credentials");
  if (url.hostname === "") throw new SsrfError("empty_host");
  return url;
}

/** Promise wrapper around a callback-style dns.lookup with { all: true }. */
function lookupAll(lookupImpl, hostname, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason ?? new Error("aborted"));
    const onAbort = () => reject(signal.reason ?? new Error("aborted"));
    signal?.addEventListener("abort", onAbort, { once: true });
    lookupImpl(hostname, { all: true, verbatim: true }, (err, addresses) => {
      signal?.removeEventListener("abort", onAbort);
      if (err) return reject(new LookupError(err.code ?? "error"));
      resolve(Array.isArray(addresses) ? addresses : [{ address: addresses }]);
    });
  });
}

/**
 * Resolves a hostname and checks every address. IP literals are judged directly.
 * @returns {Promise<{ address: string, family: number }[]>} the checked addresses
 */
export async function resolveAndCheck(hostname, { lookupImpl = dns.lookup, signal } = {}) {
  const host = stripBrackets(hostname);
  const literalFamily = isIP(host);
  const addresses = literalFamily ? [{ address: host, family: literalFamily }] : await lookupAll(lookupImpl, host, signal);
  if (addresses.length === 0) throw new LookupError("no_addresses");
  for (const { address } of addresses) {
    if (isBlockedAddress(address)) throw new SsrfError("blocked_address");
  }
  return addresses.map(({ address, family }) => ({ address, family: family ?? isIP(address) }));
}

/**
 * Full check for one URL: syntax rules plus DNS. Throws SsrfError or LookupError.
 * @param {string | URL} input
 * @param {{ lookupImpl?: Function, signal?: AbortSignal }} [opts]
 * @returns {Promise<URL>}
 */
export async function assertSafeUrl(input, opts = {}) {
  const url = parseSafeUrl(input);
  await resolveAndCheck(url.hostname, opts);
  return url;
}

/**
 * A dns.lookup-compatible function that only ever hands out checked addresses.
 * @param {Function} lookupImpl callback-style dns.lookup
 */
export function createSafeLookup(lookupImpl = dns.lookup) {
  return function safeLookup(hostname, options, callback) {
    if (typeof options === "function") {
      callback = options;
      options = {};
    }
    const opts = typeof options === "number" ? { family: options } : options ?? {};
    resolveAndCheck(hostname, { lookupImpl }).then(
      (addresses) => {
        const wanted = opts.family === 4 || opts.family === 6 ? addresses.filter((a) => a.family === opts.family) : addresses;
        if (wanted.length === 0) {
          const err = new Error(`no usable address for ${hostname}`);
          err.code = "ENOTFOUND";
          return callback(err);
        }
        if (opts.all) return callback(null, wanted);
        return callback(null, wanted[0].address, wanted[0].family);
      },
      (err) => {
        const e = new Error(err.message);
        e.code = err instanceof SsrfError ? "EBLOCKED" : "ENOTFOUND";
        callback(e);
      },
    );
  };
}

const agents = new WeakMap();
function agentFor(lookupImpl) {
  let agent = agents.get(lookupImpl);
  if (!agent) {
    agent = new Agent({ connect: { lookup: createSafeLookup(lookupImpl) } });
    agents.set(lookupImpl, agent);
  }
  return agent;
}

async function discardBody(res) {
  try {
    await res.body?.cancel();
  } catch {
    // ignore
  }
}

/**
 * One request to a URL that already passed assertSafeUrl. Returns only status and Location.
 * HEAD first; on 405/501 retries once with GET and aborts right after the headers.
 * Never follows redirects, never sends cookies or auth, never reads the body.
 * @param {URL | string} url
 * @param {{ fetchImpl?: Function, lookupImpl?: Function, signal?: AbortSignal }} [opts]
 * @returns {Promise<{ status: number, location: string | null }>}
 */
export async function fetchHeadersOnly(url, { fetchImpl = undiciFetch, lookupImpl = dns.lookup, signal } = {}) {
  const dispatcher = agentFor(lookupImpl);
  const send = async (method) => {
    const controller = new AbortController();
    const onAbort = () => controller.abort(signal.reason);
    if (signal?.aborted) controller.abort(signal.reason);
    signal?.addEventListener("abort", onAbort, { once: true });
    try {
      const res = await fetchImpl(String(url), {
        method,
        redirect: "manual",
        headers: { "user-agent": USER_AGENT, accept: "*/*" },
        credentials: "omit",
        signal: controller.signal,
        dispatcher,
      });
      const result = { status: res.status, location: res.headers.get("location") };
      await discardBody(res);
      controller.abort(); // drop the connection instead of downloading the body
      return result;
    } finally {
      signal?.removeEventListener("abort", onAbort);
    }
  };

  const head = await send("HEAD");
  if (head.status === 405 || head.status === 501) return send("GET");
  return head;
}
