# Deploying ThreatPeek

ThreatPeek runs as **one Node.js service**. The Express server answers `/api/*` and also serves the built React app from `frontend/dist`. The page calls the API on the same domain (`/api/...`), so you do not need CORS settings or a second service.

These steps work on any host that can run Node.js 20 or newer.

## Commands

Run both from the repository root.

| Step | Command | What it does |
|---|---|---|
| Build | `npm run build` | Installs the server packages (`npm ci`), installs the frontend packages, and builds the frontend into `frontend/dist`. The build always uses the real API, never mock data. |
| Start | `npm start` | Starts the server in production mode (`NODE_ENV=production` is set for you). It listens on `PORT`. |

Try it on your own computer:

```sh
git clone <your repo url> threatpeek
cd threatpeek
npm run build
npm start
# open http://localhost:3001
```

To run every test (engine, server, frontend): `npm test`.

## Environment variables

Set these in your host's settings. For a local run, you can put them in `backend/server/.env` (copy `backend/server/.env.example`). Never commit real keys. Keys stay on the server; the frontend never sees them.

| Name | Default | Meaning |
|---|---|---|
| `PORT` | `3001` | Port to listen on. Most hosts set this for you. |
| `NODE_ENV` | `development` | `npm start` sets it to `production`. Production serves the frontend and adds the HSTS header. |
| `TRUST_PROXY` | (empty = off) | Number of reverse proxies in front of the app, usually `1`. Needed so rate limits see each visitor's real IP. Leave it empty when there is no proxy. See below. |
| `STATIC_DIR` | `../../frontend/dist` | Folder with the built frontend. A relative path is read from `backend/server/`. |
| `AI_ENABLED` | `false` | `true` turns on the optional AI score. It also needs `OPENROUTER_API_KEY` and `OPENROUTER_MODEL`. |
| `OPENROUTER_API_KEY` | (empty) | Optional. Your OpenRouter key. |
| `OPENROUTER_MODEL` | (empty) | Optional. The OpenRouter model id, for example a `:free` model. |
| `AI_DAILY_LIMIT` | `40` | Maximum AI calls per UTC day. |
| `GOOGLE_SAFE_BROWSING_KEY` | (empty) | Optional. Google Safe Browsing Lookup API v4 key. |
| `ALLOWED_ORIGINS` | `http://localhost:5173` | Only for a frontend on a **different** domain. Not needed for this one-service setup. |

Every optional layer fails quietly. With no keys at all, the app still works and scores messages in the browser.

### TRUST_PROXY

Most hosts put a proxy or load balancer in front of your app. Without `TRUST_PROXY`, the server sees every visitor as the proxy's IP, so all visitors share one rate limit (30 requests a minute).

- Behind one proxy (the usual case): `TRUST_PROXY=1`.
- Behind more proxies: the number of proxies, for example `2`.
- You can also list the proxy addresses: `TRUST_PROXY=10.0.0.0/8` or `TRUST_PROXY=loopback`.
- No proxy (the server faces the internet directly): leave it empty.

Do not set it higher than the real number of proxies. Visitors could then fake their IP with an `X-Forwarded-For` header and dodge the rate limit. For the same reason, `TRUST_PROXY=true` is not accepted and counts as off.

## Check that it works

```sh
curl https://your-domain/api/health
# {"ok":true}
```

- The home page (`/`) shows the app.
- Any other page path (for example `/about`) also gets the app, so links inside the app work after a reload.
- An unknown API path, such as `/api/nope`, returns a JSON `404` (`{"error":"not_found",...}`), never the web page.
- The server log line at startup shows which layers are on, for example `safebrowsing: false, ai: true, static: true, trust proxy: 1`. It never prints keys.

If the log says `index.html not found`, the build step did not run or `STATIC_DIR` points to the wrong folder. The API still works in that case.

Point your host's health check at `/api/health`. Note that this route counts toward the 30-requests-a-minute limit, so do not check more often than every few seconds.

## Security headers

Every response has a Content-Security-Policy that allows only scripts, styles, fonts and API calls from your own domain, plus `data:` images. If you later add something from another domain (for example a web font or analytics), you must add that domain to `CONTENT_SECURITY_POLICY` in `backend/server/src/config.js`, or the browser will block it.

## If you turn on Google Safe Browsing

Google's terms for the Safe Browsing API require that:

- Every warning based on it says **"Advisory provided by Google"** and links to <https://developers.google.com/safe-browsing/v4/advisory>.
- Warnings say a link is *possibly* or *suspected* to be unsafe, never that it is certainly unsafe.
- The v4 Lookup API is for non-commercial use only.

The frontend must show that advisory text whenever a Safe Browsing match changes the result.

## If you turn on the AI score

The AI score is opt-in for each user. The text is sent to OpenRouter only when the user agrees.

The server makes at most **40 AI requests per day** by default (`AI_DAILY_LIMIT`). This stays below OpenRouter's free limit of 50 requests a day. After the limit is reached, the app keeps working with the browser-only score until the next UTC day. Repeated texts are cached for 24 hours and do not count again.
