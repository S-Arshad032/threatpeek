# ThreatPeek

**Paste a suspicious email, SMS or link. Get a 0–100 risk estimate, red-flag cards that explain why, and a haunted ghost that reacts: Pookie (low risk), Skeptical (medium) or Poltergeist (high).**

Built for Kiroween 2026. The spooky look serves a purpose: the ghost is the warning signal.

## Live demo

**https://threatpeek-7pw7.onrender.com**

It runs on a free host that goes to sleep when nobody uses it. The first visit can take up to a minute to load.

## How it works

ThreatPeek checks a message in three layers. Only the first one is needed. The app works fully with the rules engine alone.

| Layer | What it does | Where it runs | Default |
|---|---|---|---|
| **1. Rules engine** | Checks 17 warning signals in English text and gives a score with an explanation for each signal found | In your browser | Always on |
| **2. Google Safe Browsing** | Follows shortened or redirecting links, then asks Google if a link is on its list of known bad sites | Through our server | Off unless a key is set |
| **3. AI second opinion** | Asks an AI model (through OpenRouter) to rate the message | Through our server | Off |

### Layer 1: the rules engine

- Plain JavaScript with no dependencies, no network calls and no browser or Node.js APIs. The browser and the server share the same code ([backend/engine](backend/engine)).
- **Deterministic:** the same text always gives the same result.
- **Explainable:** every point of the score comes from a named signal, and each signal comes with the text that triggered it and a plain-English explanation.
- **17 signals in 4 groups** (English text only):
  - **Identity:** look-alike domains (typosquatting), disguised letters (homograph / punycode), and sender names that don't match the address.
  - **Email auth headers:** SPF, DKIM or DMARC failures, if headers are pasted.
  - **Links:** links to a bare IP address, risky domain endings, and link text that points somewhere else.
  - **Content:** urgency, requests for passwords or codes, risky attachments, prize and lottery bait, inheritance and advance-fee stories, requests for card or bank details, payment by gift card, crypto or money transfer, and requests to keep the message secret.
- **Caps:** each group has a maximum (identity/auth 40, links 35, content 45), so one kind of signal cannot take over the score.
- **Floors:** dangerous combinations get a minimum score. For example, a look-alike domain plus a password request always scores at least 70, and so does a prize or inheritance story combined with a request for card details or gift-card payment. A request for card or bank details on its own scores at least 50.
- The score maps to the ghost: 0–30 Pookie, 31–69 Skeptical, 70–100 Poltergeist.

Weights, caps, floors and word lists are all in [backend/engine/src/config.js](backend/engine/src/config.js).

### Layers 2 and 3: the optional server

The server ([backend/server](backend/server)) adds three endpoints:

| Endpoint | Purpose |
|---|---|
| `POST /api/unwrap` | Follows redirects to find a link's real destination |
| `POST /api/safebrowsing` | Checks up to 10 links with the Google Safe Browsing Lookup API v4 |
| `POST /api/analyze` | Gets the AI score |

The engine combines these results with its own score. The AI can raise or lower the score, but the result never drops below 80% of the engine's score. Every layer fails quietly. If a key is missing, a call times out or the daily AI budget is used up, the app falls back to the engine-only result. The result then says "Heuristics only. No AI check was run."

The live demo currently runs with Safe Browsing and AI both off. The current UI always sends `useAI: false`, so the AI layer is ready on the server, but users cannot turn it on yet.

## Safety and honesty

- **An estimate, never a promise.** ThreatPeek never calls a message "safe". Every result says "This is an estimate, not a guarantee."
- **No API keys in the browser.** All keys live in server environment variables. The frontend only calls our own `/api/...` paths.
- **SSRF guard on link unwrapping:**
  - Only http/https on ports 80 and 443.
  - Every address that DNS returns must be public. Private, loopback, link-local (including cloud metadata) and other reserved ranges are blocked.
  - The check runs again on every redirect, with at most 5 hops in 10 seconds.
  - A pinned DNS lookup stops rebinding tricks.
  - Only headers are read, never the page body.
- **Rate limits:**
  - 30 requests per minute per IP on the API.
  - 10 per minute on `/api/analyze`.
  - A daily AI budget (40 calls by default).
  - JSON bodies are capped at 16 kB, and text at 4000 characters.
- **Prompt-injection defense:**
  - The pasted text goes inside a `<message>` block, and any `<message>` tags in it are escaped.
  - The system prompt says the text is data to rate, not instructions.
  - The model must answer with exactly `{"score": <0-100>}`. Anything else is thrown away, and model text never reaches the user.
- **User text is shown as plain text.** No `innerHTML`, no `dangerouslySetInnerHTML`.
- **Strict security headers:** a same-origin Content-Security-Policy, no framing, and HSTS in production.
- **Privacy:** the server never logs pasted text or keys.
- **Only fictional brands** (such as Galactibank, Orbitins, Nexamail) and reserved domains (`.example`, `.test`, `.invalid`) appear in examples and tests.

### Google Safe Browsing

When Safe Browsing is turned on, Google's terms require warnings to say **"Advisory provided by Google"** with a link to <https://developers.google.com/safe-browsing/v4/advisory>. They also require warnings to say "possibly" or "suspected", never "certainly". The v4 Lookup API is for non-commercial use only. The live demo does not use Safe Browsing right now, and the current UI does not show this advisory yet. It must be added before a key is set.

## Tech stack

- **Frontend:** React 19, Vite 8 and plain CSS. The ghost and backdrop are inline SVG, and the sounds are made with the Web Audio API (no audio files). The page respects `prefers-reduced-motion` and has a mute button.
- **Server:** Node.js 20+, Express 5, zod (input and env validation), express-rate-limit and undici.
- **Engine:** plain ES modules with no dependencies.
- **Tests:** Vitest, fast-check (property tests) and supertest.

## Project layout

```
backend/engine/    Layer 1 rules engine (pure JS, shared by browser and server)
backend/server/    Express API: /api/unwrap, /api/safebrowsing, /api/analyze, /api/health;
                   also serves the built frontend in production
frontend/          React + Vite app (src/api.js is the single entry point to the engine and API)
docs/              deploy.md (build, start, env vars), server-spec.md
.kiro/             Kiro spec for the engine (requirements, design, tasks) and steering files
```

## Run locally

You need Node.js 20 or newer. All commands below are run from the repository root unless noted.

**Production-style run** (one service: server plus built frontend):

```sh
npm run build    # installs packages and builds frontend/dist
npm start        # production mode on http://localhost:3001
```

**Development** (two terminals):

```sh
# Terminal 1: API server on port 3001, restarts on file changes
npm install
npm run dev -w @threatpeek/server

# Terminal 2: frontend on http://localhost:5173 (forwards /api to port 3001)
cd frontend
npm install
npm run dev
```

To build the UI without the server, copy `frontend/.env.example` to `frontend/.env`. It sets `VITE_USE_MOCK=true`, which returns sample results. The production build always uses the real engine and API.

**Environment variables:**
- The server reads them from `backend/server/.env` (copy `backend/server/.env.example`) or from the host's settings.
- None are required. Safe Browsing needs `GOOGLE_SAFE_BROWSING_KEY`. The AI layer needs `AI_ENABLED=true`, `OPENROUTER_API_KEY` and `OPENROUTER_MODEL`.
- Behind a hosting proxy, set `TRUST_PROXY=1` so rate limits see real visitor IPs.
- See [docs/deploy.md](docs/deploy.md) for the full table.

**Windows notes:**
- Run the tests from a path with an uppercase drive letter (`D:\...`). With `/d/...` from Git Bash, Vitest loads twice and every suite fails.
- Stop `npm run dev` before running `npm run build`. The build reinstalls `frontend/node_modules`, and Windows blocks that while the dev server holds a file open.

## Tests

```sh
npm test    # engine, server and frontend
```

| Package | Test files | Tests | What they cover |
|---|---|---|---|
| `backend/engine` | 13 | 173 | Unit tests per module, 13 golden tests, fast-check property tests |
| `backend/server` | 8 | 208 | Endpoints, SSRF guard and IP ranges, env loading, cache; no network needed |
| `frontend` | 1 | 4 | The `api.js` adapter in mock mode |
| **Total** | **22** | **385** | |

## How we built it

- **Kiro:** we wrote the engine spec in Kiro, made up of requirements, design and a task list ([.kiro/specs/threat-scoring](.kiro/specs/threat-scoring)). We also wrote short steering files there for the product, security and tech rules ([.kiro/steering](.kiro/steering)). Those files set the rules the rest of the project follows: for example, never say "safe", keep keys on the server, and use only fictional brands.
- **Claude Code:** we used it to write the implementation (the engine, the server, the frontend and the tests). For the engine, it worked through the Kiro task list. We also used it to review changes and to write this README.
- **Our own decisions:** we made the key choices ourselves and wrote them into the spec and steering files: the three-layer design with the engine as the always-on base, the scoring weights, caps, floors and ghost thresholds, the security rules, and the free-tier limits.

The Kiro spec covers only the engine. The server was planned in [docs/server-spec.md](docs/server-spec.md), not in `.kiro/`. No Kiro hooks are used.

## Credits

Built by a team of two for Kiroween 2026.

Released under the [MIT License](LICENSE).
