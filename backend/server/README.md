# @threatpeek/server

Optional API for ThreatPeek. The client always scores messages in the browser with `@threatpeek/engine`, so the app works with this server off. The server adds three optional layers:

| Endpoint | Gives the engine | Needs |
|---|---|---|
| `POST /api/unwrap` | the real destination of a shortened or redirecting link | nothing |
| `POST /api/safebrowsing` | `l2Hit` | `GOOGLE_SAFE_BROWSING_KEY` |
| `POST /api/analyze` | `l3Score` | `AI_ENABLED=true`, `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` |

Each layer fails quietly. A missing key, a timeout, a bad answer or a spent daily budget gives `hit: false` / `l3Score: null` with HTTP 200, not an error. The app is free to use. No endpoint asks for a login or payment.

## Run

Node 20 or newer. From the repository root:

```sh
npm install
cp backend/server/.env.example backend/server/.env   # then fill in what you need
npm run dev  -w @threatpeek/server            # restarts on file changes
npm start    -w @threatpeek/server            # plain start
npm test     -w @threatpeek/server            # vitest, no network needed
```

You can also run `npm run dev` or `npm test` inside `backend/server/`.

On Windows, run the tests from a path with an uppercase drive letter (`D:\...`). If Git Bash starts in `/d/...`, vitest loads twice and every suite fails.

With `NODE_ENV=production` (or `STATIC_DIR` set), the server also serves `frontend/dist` and falls back to `index.html` for any other GET path, so one service hosts the whole app. `/api/*` never falls back: an unknown API path is a JSON 404. For the production build and start commands, see [docs/deploy.md](../../docs/deploy.md).

## Environment variables

The server reads them from `backend/server/.env` or the process environment. Empty or invalid values use the safe default.

| Name | Default | Meaning |
|---|---|---|
| `PORT` | `3001` | Port to listen on. |
| `ALLOWED_ORIGINS` | `http://localhost:5173` | Comma-separated list of origins that get CORS headers. |
| `GOOGLE_SAFE_BROWSING_KEY` | (none) | Safe Browsing Lookup API v4 key. Without it, `/api/safebrowsing` returns `checked: false`. |
| `AI_ENABLED` | `false` | Only the exact value `true` turns on the AI layer. |
| `OPENROUTER_API_KEY` | (none) | One OpenRouter key. The server never rotates keys or uses several accounts. |
| `OPENROUTER_MODEL` | (none) | OpenRouter model id you choose, for example a `:free` model. |
| `AI_DAILY_LIMIT` | `40` | Maximum OpenRouter calls per UTC day. The default stays under the free tier's 50. |
| `NODE_ENV` | `development` | `production` turns on static hosting of `frontend/dist` and the HSTS header. The root `npm start` sets it. |
| `STATIC_DIR` | `../../frontend/dist` | Built frontend folder. Relative paths are read from `backend/server/`. Setting it also turns on static hosting outside production. |
| `TRUST_PROXY` | (off) | Proxy hops in front of the app (`1`-`10`), or a comma-separated list of proxy IPs, subnets or `loopback`/`linklocal`/`uniquelocal`. `true` and invalid values count as off. |

The server never logs keys or pasted text. It logs only upstream status codes.

## Endpoints

All bodies are JSON with a 16 kB limit. Text and URLs are at most 4000 characters. Every `/api` route except `/api/health` allows 30 requests per minute per IP. `/api/analyze` allows only 10. Over the limit you get `429 { "error": "rate_limited", ... }`.

Errors always have this form, with no stack traces:

```json
{ "error": "invalid_request", "message": "The request body is missing a field or has a wrong value." }
```

### `GET /api/health`

Not rate-limited, so it is safe as a host health check. It always returns exactly `{"ok":true}`.

```sh
curl http://localhost:3001/api/health
# {"ok":true}
```

### `POST /api/unwrap`

```sh
curl -X POST http://localhost:3001/api/unwrap \
  -H "Content-Type: application/json" \
  -d '{"url":"https://short.example/abc"}'
# {"finalUrl":"https://landing.example/page","hops":["https://short.example/abc","https://landing.example/page"],"truncated":false}
```

`hops` lists every URL that passed the checks and was requested, in order. `truncated: true` means the chain stopped early: a blocked hop, a timeout, a network error or more than 5 hops. In that case `finalUrl` is the last safe URL. A blocked first URL gives `400 blocked_url`.

### `POST /api/safebrowsing`

```sh
curl -X POST http://localhost:3001/api/safebrowsing \
  -H "Content-Type: application/json" \
  -d '{"urls":["http://malware.test/x","https://fine.example/"]}'
# {"hit":false,"checked":true}
```

Send 1 to 10 http(s) URLs. The server calls Google's `threatMatches:find` with a 5 s timeout. The key is sent in the query string of that server-side request only.

Results are cached in memory (LRU, 500 entries). Misses are kept for 1 hour. Hits are kept for 1 hour or Google's `cacheDuration`, whichever is shorter, because Google's terms allow a warning only while the cached match is valid.

**Usage terms (Google):** the v4 API is for non-commercial use only, and Google now marks v4 as deprecated (no shutdown date was published when this was written). Warnings based on it must be worded as possible or suspected, not certain. They must also include "Advisory provided by Google" with a link to <https://developers.google.com/safe-browsing/v4/advisory>. The client has to show that text.

### `POST /api/analyze`

```sh
curl -X POST http://localhost:3001/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"text":"Your parcel is held. Pay the fee at http://parcel-desk.test"}'
# {"l3Score":88,"cached":false}
```

- When the layer is off (`AI_ENABLED` is not `true`, or the key or model is missing), the response is `{ "l3Score": null, "cached": false }`.
- The pasted text goes inside a `<message>...</message>` block. Any `<message` or `</message` inside the text is escaped first. The system prompt says the message is untrusted data to rate, not instructions to follow.
- The request uses `temperature: 0`, `max_tokens: 60` and a JSON `response_format`, with a 15 s timeout.
- The model's answer must be exactly `{"score": <integer 0-100>}`. Anything else gives `null`, and model text never reaches the client.
- Cache: SHA-256 of the normalized text, kept 24 h (LRU, 500 entries). A cache hit does not count against the daily budget.
- A 401, 402, 429 or 5xx answer, or a timeout, gives `null`. Only the status is logged.

## SSRF rules (`/api/unwrap`)

- Only `http:` and `https:`, only ports 80 and 443. No `user:pass@` in the URL.
- The hostname is parsed with `new URL()`, so numeric tricks such as `2130706433`, `0177.0.0.1`, `0x7f.1` and `127.1` become a normal IP. The server checks the addresses that DNS returns, not the text.
- Every resolved address must be public. If any address is blocked, the request is refused.
- Blocked IPv4 ranges: `0/8`, `10/8`, `100.64/10`, `127/8`, `169.254/16` (cloud metadata), `172.16/12`, `192.168/16`, `224/4`, `240/4` (includes broadcast).
- Blocked IPv6 ranges: `::`, `::1`, the whole `::/96`, `fc00::/7`, `fe80::/10` and `ff00::/8`. IPv4-mapped (`::ffff:a.b.c.d`) and NAT64 (`64:ff9b::/96`) addresses are judged by the IPv4 address inside them.
- The HTTP agent uses a custom `lookup` that hands out only checked addresses, so DNS rebinding cannot swap in a private address after the check.
- Redirects are followed by hand: at most 5 hops, all checks run again on every hop, and the whole chain has a 10 s budget.
- Each hop sends `HEAD`. On a 405 or 501 it retries once with `GET` and drops the connection after the headers. The body is never read or returned.
- Requests send `User-Agent: ThreatPeek/0.1` and never send cookies or auth headers.

## Security headers

Every response sets `Content-Security-Policy` (same-origin scripts, styles, fonts and API calls, `data:` images, no framing), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy` and `Permissions-Policy`. In production it also sets `Strict-Transport-Security`. The policy lives in `CONTENT_SECURITY_POLICY` in `src/config.js`.

## Deploying behind a proxy

The rate limiter keys on `req.ip`. Behind a reverse proxy or load balancer, every client then looks like the proxy's IP. Set `TRUST_PROXY` to the number of proxies in front of the app (usually `1`), so `req.ip` becomes the real client IP from `X-Forwarded-For`. The default trusts nothing, which is right when there is no proxy: clients can fake `X-Forwarded-For`, so trusting it without a proxy would let them dodge the rate limit. See [docs/deploy.md](../../docs/deploy.md).
