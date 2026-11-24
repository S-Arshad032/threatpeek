// Chithi's voice: a thin, fail-safe wrapper around the browser's built-in
// speechSynthesis. No audio files, no network code of our own.
//
// PRIVACY: callers must only pass fixed, app-authored strings (the greeting and
// the mood lines). Never pass the user's message, evidence, cursed phrases or
// flag explanations. Some browsers send text to a cloud voice service to
// synthesize it, and the README promises the pasted message never leaves the
// browser.

const PITCH = 1.4
const RATE = 1.05

// Tie-break only: names that suggest a female or natural-sounding voice,
// spread across vendors (Apple, Microsoft, Google, eSpeak, ...).
const FRIENDLY_NAME = /\b(female|woman|natural|neural|samantha|zira|aria|jenny|karen|moira|tessa|fiona|serena|libby|sonia|victoria)\b/i

let cachedVoice = null
let listening = false
let unlocked = false
// Chrome can garbage-collect an utterance mid-sentence unless something holds it.
let current = null

function getSynth() {
  try {
    const synth = globalThis.speechSynthesis
    if (!synth || typeof globalThis.SpeechSynthesisUtterance !== 'function') return null
    return synth
  } catch {
    return null
  }
}

function langRank(lang) {
  const tag = String(lang || '').replace('_', '-').toLowerCase()
  if (tag === 'en-us') return 3
  if (tag === 'en-gb') return 2
  if (tag === 'en' || tag.startsWith('en-')) return 1
  return 0
}

/**
 * Pick the best English voice: en-US, then en-GB, then any en-*.
 * Within the same language, prefer a female/natural-sounding name.
 * Returns null when there is no English voice (or no voices yet).
 */
export function pickVoice(voices) {
  if (!Array.isArray(voices)) return null
  let best = null
  let bestScore = 0
  for (const voice of voices) {
    if (!voice) continue
    const lang = langRank(voice.lang)
    if (!lang) continue
    const score = lang * 2 + (FRIENDLY_NAME.test(voice.name || '') ? 1 : 0)
    if (score > bestScore) {
      best = voice
      bestScore = score
    }
  }
  return best
}

function refreshVoice(synth) {
  try {
    cachedVoice = pickVoice(synth.getVoices())
  } catch {
    cachedVoice = null
  }
}

/** Start loading voices early. They arrive asynchronously in most browsers. */
export function preloadVoices() {
  const synth = getSynth()
  if (!synth) return
  refreshVoice(synth)
  if (listening) return
  listening = true
  const onChange = () => refreshVoice(synth)
  try {
    if (typeof synth.addEventListener === 'function') synth.addEventListener('voiceschanged', onChange)
    else synth.onvoiceschanged = onChange
  } catch {
    // Voices will still be read again on the next speak().
  }
}

function utter(synth, text, volume) {
  synth.cancel()
  const utterance = new globalThis.SpeechSynthesisUtterance(text)
  if (cachedVoice) {
    utterance.voice = cachedVoice
    utterance.lang = cachedVoice.lang
  } else {
    utterance.lang = 'en-US'
  }
  utterance.pitch = PITCH
  utterance.rate = RATE
  utterance.volume = Math.min(1, Math.max(0, Number.isFinite(volume) ? volume : 1))
  utterance.onend = utterance.onerror = () => {
    if (current === utterance) current = null
  }
  current = utterance
  synth.speak(utterance)
  unlocked = true
}

/**
 * Say a fixed, app-authored line in Chithi's voice.
 * Does nothing (and never throws) when disabled or unsupported.
 */
export function speak(text, { enabled = true, volume = 1 } = {}) {
  if (!enabled || !text) return false
  const synth = getSynth()
  if (!synth) return false
  try {
    preloadVoices()
    if (!cachedVoice) refreshVoice(synth)
    utter(synth, text, volume)
    return true
  } catch {
    return false
  }
}

/**
 * iOS/Safari only allow speech that starts inside a user gesture. Call this
 * from a tap handler: a silent, near-empty utterance unlocks later ones.
 */
export function unlockSpeech() {
  if (unlocked) return
  const synth = getSynth()
  if (!synth) return
  try {
    preloadVoices()
    utter(synth, ' ', 0)
  } catch {
    // Unsupported or blocked: stay silent.
  }
}

/** Stop anything Chithi is saying right now. */
export function cancelSpeech() {
  const synth = getSynth()
  if (!synth) return
  try {
    synth.cancel()
  } catch {
    // ignore
  }
  current = null
}
