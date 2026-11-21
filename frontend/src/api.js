// The one function the UI calls to analyze a message: analyze(text, options).
// It always resolves to the same shape as score() from @threatpeek/engine (see mock.js).
//
// Owner note: do not change the signature or the result shape without telling the owner.
// No secrets or API keys belong in the frontend. All keys live in backend/server/.env.

import { score } from '@threatpeek/engine'
import { pookie, skeptical, poltergeist } from './mock.js'

// Max input length. Same value as MAX_INPUT_LENGTH in the engine and in backend/server/src/config.js
// (neither package exports it to the browser, so it is defined here once).
export const MAX_CHARS = 4000

const MOCK_DELAY_MS = 600

// Client-side timeouts: a bit longer than the server's own timeouts for each upstream call
// (unwrap 10 s, Safe Browsing 5 s, AI 15 s), so the server can answer first.
const UNWRAP_TIMEOUT_MS = 12_000
const SAFEBROWSING_TIMEOUT_MS = 7_000
const AI_TIMEOUT_MS = 17_000

// Same as SAFEBROWSING_MAX_URLS in backend/server/src/config.js.
const MAX_URLS = 10

const URL_RE = /https?:\/\/[^\s"'<>()[\]{}]+/gi
const TRAILING_PUNCTUATION_RE = /[.,;:!?]+$/

const useMock = () => import.meta.env.VITE_USE_MOCK === 'true'

function validate(text) {
  if (typeof text !== 'string') throw new TypeError('text must be a string')
  if (text.length > MAX_CHARS) throw new RangeError(`text exceeds ${MAX_CHARS} characters`)
}

/** Picks a sample result by simple keyword rules. Returns a copy so callers cannot change the samples. */
function pickMock(text) {
  const t = text.toLowerCase()
  if (t.includes('password') || t.includes('urgent')) return structuredClone(poltergeist)
  if (t.includes('http')) return structuredClone(skeptical)
  return structuredClone(pookie)
}

/** Unique http(s) URLs found in the text, at most MAX_URLS. */
function extractUrls(text) {
  const urls = new Set()
  for (const m of text.matchAll(URL_RE)) {
    urls.add(m[0].replace(TRAILING_PUNCTUATION_RE, ''))
    if (urls.size >= MAX_URLS) break
  }
  return [...urls]
}

/** POSTs JSON to the server. Throws on network error, timeout or non-2xx status. */
async function postJson(path, body, timeoutMs) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  })
  if (!res.ok) throw new Error(`${path} failed with status ${res.status}`)
  return res.json()
}

/** Final URL after redirects, or null if the server could not unwrap it. */
async function unwrap(url) {
  try {
    const data = await postJson('/api/unwrap', { url }, UNWRAP_TIMEOUT_MS)
    return typeof data?.finalUrl === 'string' ? data.finalUrl : null
  } catch {
    return null
  }
}

/** L2: true only if Safe Browsing reports a match. Any failure counts as no hit. */
async function checkLinks(text) {
  const urls = extractUrls(text)
  if (urls.length === 0) return false
  try {
    const finals = await Promise.all(urls.map(unwrap))
    const all = [...new Set([...urls, ...finals.filter(Boolean)])].slice(0, MAX_URLS)
    const data = await postJson('/api/safebrowsing', { urls: all }, SAFEBROWSING_TIMEOUT_MS)
    return data?.hit === true
  } catch {
    return false
  }
}

/** L3: an integer 0-100 from the AI, or null on any failure or when AI is off. */
async function aiScore(text) {
  if (text.trim() === '') return null
  try {
    const data = await postJson('/api/analyze', { text }, AI_TIMEOUT_MS)
    const s = data?.l3Score
    return Number.isInteger(s) && s >= 0 && s <= 100 ? s : null
  } catch {
    return null
  }
}

/**
 * Analyzes a pasted link, email or SMS.
 *
 * @param {string} text  at most MAX_CHARS characters
 * @param {{ useAI?: boolean }} [options]  useAI: true only if the user opted in to sending the text to the AI
 * @returns {Promise<{ riskScore: number, verdict: "pookie" | "skeptical" | "poltergeist",
 *   redFlags: { id: string, weight: number, evidence: string, explanation: string }[],
 *   cursedPhrases: { text: string, reason: string }[], confidence: "limited" | "full" }>}
 * @throws {TypeError} text is not a string
 * @throws {RangeError} text is longer than MAX_CHARS
 */
export async function analyze(text, options = {}) {
  validate(text)

  if (useMock()) {
    await new Promise((resolve) => setTimeout(resolve, MOCK_DELAY_MS))
    return pickMock(text)
  }

  // Engine-only result first. It is the fallback whenever the server cannot help.
  const local = score(text)

  const wantAI = options?.useAI === true
  const hasUrl = extractUrls(text).length > 0
  if (!hasUrl && !wantAI) return local

  const [l2Hit, l3Score] = await Promise.all([
    hasUrl ? checkLinks(text) : false,
    wantAI ? aiScore(text) : null,
  ])
  if (!l2Hit && l3Score === null) return local

  try {
    return score(text, { l2Hit, l3Score })
  } catch {
    return local
  }
}
