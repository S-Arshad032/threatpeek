# ThreatPeek frontend

Vite + React (JavaScript). The page in `src/App.jsx` is only a placeholder that proves the pipeline works. Replace it with the real UI.

## Run it

```sh
cd frontend
npm install
npm run dev      # http://localhost:5173
npm run build    # production build in frontend/dist
npm test         # vitest
```

By default the app runs in **mock mode**, so you do not need the backend server.

## The two files you call

### `src/api.js`

```js
import { analyze, MAX_CHARS } from "./api.js";

const result = await analyze(text, { useAI: false });
```

- `analyze(text, options)` returns a Promise with the same result as the engine's `score()` (see below).
- `options.useAI` must be `true` only when the user has agreed to send the text to the AI.
- It throws `RangeError` if `text` is longer than `MAX_CHARS` (4000).
- If any server call fails or is slow, you still get a result. It is just the engine-only result (`confidence: "limited"`).

### `src/mock.js`

Three sample results: `pookie` (score 12), `skeptical` (52) and `poltergeist` (91). They are real engine output, so you can build the UI against them. The comment at the top of the file explains every field.

Result shape:

```js
{
  riskScore: 52,                         // 0-100
  verdict: "skeptical",                  // "pookie" | "skeptical" | "poltergeist"
  redFlags: [{ id, weight, evidence, explanation }],
  cursedPhrases: [{ text, reason }],
  confidence: "full"                     // "full" if the AI was used, else "limited"
}
```

`evidence` and `cursedPhrases[].text` are copied from what the user pasted. Always show them as plain text. Never use `dangerouslySetInnerHTML`.

## Mock mode on and off

The setting lives in `frontend/.env` (copy it from `.env.example`; it is not committed):

```sh
VITE_USE_MOCK=true    # sample results, no server
VITE_USE_MOCK=false   # real flow
```

Restart `npm run dev` after you change it.

In mock mode the sample is picked by keywords: text with "password" or "urgent" gives `poltergeist`, text with "http" gives `skeptical`, anything else gives `pookie`. There is a short fake delay (about 600 ms) so you can see loading states.

With `VITE_USE_MOCK=false`, the engine runs in the browser. If the text has links, the app also asks the backend to follow redirects and check Safe Browsing, and it asks the AI only when `useAI` is true. Start the backend in another terminal (see `backend/server/README.md`). In dev, Vite forwards `/api` to `http://localhost:3001`.

Never put API keys in the frontend. All keys live in `backend/server/.env`.

The production build (`npm run build`) always uses the real flow: `frontend/.env.production` sets `VITE_USE_MOCK=false`, and Vite reads it in preference to `.env`. `api.js` only calls relative `/api/...` paths, so the deployed app talks to the server on its own domain. See [docs/deploy.md](../docs/deploy.md).

## Who owns what

- **Yours to change freely:** everything in `frontend/src` except `api.js` and `mock.js` (for example `App.jsx`, `main.jsx`, new components and styles).
- **Ask first:** the signatures of `api.js` and `mock.js` (function names, parameters and the result shape). Tell the owner before you change them, because the engine and the server depend on the same shape.
