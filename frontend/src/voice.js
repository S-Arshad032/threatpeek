// Chithi's voice: four pre-recorded clips (the author's own voice, pitch-shifted),
// served from our own origin and played through ONE shared <audio> element.
//
// PRIVACY: only these fixed clips are ever played. Nothing from the user's
// message is spoken, synthesized or sent anywhere.
//
// iOS Safari allows an audio element to play outside a user gesture only after
// that same element has played inside one. Reusing a single element means the
// wake tap (or the Peek click, via primeClip) unlocks every later clip.

const BASE = import.meta.env?.BASE_URL ?? '/'

export const CLIPS = Object.freeze(
  Object.fromEntries(
    ['intro', 'pookie', 'skeptical', 'poltergeist'].map((name) => [name, `${BASE}audio/${name}.mp3`]),
  ),
)

const NOT_PLAYED = Object.freeze({ played: false, duration: null, ended: Promise.resolve(false) })

let element = null
let token = 0
let unlocked = false
// Settles the `ended` promise of the clip that is playing now.
let finishCurrent = null

function getElement() {
  if (element) return element
  try {
    if (typeof globalThis.Audio !== 'function') return null
    element = new globalThis.Audio()
    element.preload = 'auto'
    return element
  } catch {
    return null
  }
}

function knownDuration(el) {
  const d = el?.duration
  return Number.isFinite(d) && d > 0 ? d : null
}

/** Stop whatever clip is playing. Never throws. */
export function stopClip() {
  token += 1
  const finish = finishCurrent
  finishCurrent = null
  if (finish) finish(false)
  if (!element) return
  try {
    element.pause()
    element.currentTime = 0
  } catch {
    // ignore
  }
}

/**
 * Play one of CLIPS. Call it synchronously inside a click/tap when you can:
 * play() starts before this function returns.
 *
 * Resolves (never rejects) with:
 *   played   - false when disabled, unsupported, missing (404), blocked or stopped
 *   duration - seconds from loadedmetadata, or null if unknown
 *   ended    - promise: true when the clip finished, false when stopped or failed
 */
export function playClip(name, { enabled = true, volume = 1 } = {}) {
  const url = CLIPS[name]
  if (!enabled || !url) return Promise.resolve(NOT_PLAYED)
  const el = getElement()
  if (!el) return Promise.resolve(NOT_PLAYED)

  stopClip()
  const mine = token
  let duration = null

  let resolveEnded
  const ended = new Promise((resolve) => { resolveEnded = resolve })
  const onMeta = () => { duration = knownDuration(el) }
  const onEnded = () => finish(true)
  const onError = () => finish(false)
  function finish(ok) {
    el.removeEventListener('loadedmetadata', onMeta)
    el.removeEventListener('ended', onEnded)
    el.removeEventListener('error', onError)
    if (finishCurrent === finish) finishCurrent = null
    resolveEnded(ok)
  }
  finishCurrent = finish

  try {
    el.addEventListener('loadedmetadata', onMeta)
    el.addEventListener('ended', onEnded)
    el.addEventListener('error', onError)
    el.muted = false
    el.volume = Math.min(1, Math.max(0, Number.isFinite(volume) ? volume : 1))
    el.src = url
    const started = el.play()
    return Promise.resolve(started)
      .then(() => {
        if (mine !== token) return NOT_PLAYED
        unlocked = true
        return { played: true, duration: duration ?? knownDuration(el), ended }
      })
      .catch(() => {
        // Blocked by autoplay rules, 404, unsupported format, or interrupted by stopClip().
        if (mine === token) finish(false)
        return NOT_PLAYED
      })
  } catch {
    finish(false)
    return Promise.resolve(NOT_PLAYED)
  }
}

/**
 * Call inside a click when a clip will be played later, outside the gesture
 * (the verdict clip starts after the analysis and the synth sound). If the
 * shared element has never played, start it muted and pause it right away so
 * iOS treats it as user-activated. No-op once any clip has played.
 */
export function primeClip() {
  if (unlocked) return
  const el = getElement()
  if (!el) return
  try {
    stopClip()
    const mine = token
    el.muted = true
    el.src = CLIPS.intro
    Promise.resolve(el.play())
      .then(() => {
        unlocked = true
        if (mine === token) el.pause()
      })
      .catch(() => {})
      .finally(() => {
        if (mine === token) el.muted = false
      })
  } catch {
    // ignore
  }
}

/**
 * Bubble typing speed (ms per character) so typing ends ~0.3 s before the clip.
 * Unknown duration -> the old fixed speed. Clamped to 20-90 ms per character.
 */
export function typingDelay(length, duration, { fallback = 32, min = 20, max = 90 } = {}) {
  if (!(length > 0) || !Number.isFinite(duration) || duration <= 0) return fallback
  const ms = ((duration - 0.3) * 1000) / length
  return Math.round(Math.min(max, Math.max(min, ms)))
}

/** Failsafe wait for a clip's 'ended' event: duration + 0.5 s, never more than 9 s. */
export function clipFailsafeMs(duration) {
  if (!Number.isFinite(duration) || duration <= 0) return 9000
  return Math.round(Math.min(duration + 0.5, 9) * 1000)
}
