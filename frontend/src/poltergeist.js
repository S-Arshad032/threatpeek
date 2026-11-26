// The poltergeist screen effect: when a result scores 70 or more, the whole page flickers
// (a class on the app root wrapper dims the page content with a CSS filter, and a fixed overlay
// pulses dark red) and a few bats fly across the screen. Pure timing logic lives here so it can
// be tested without a DOM; PoltergeistEffect.jsx renders the overlay.
//
// Safety: the flicker has 3 dark pulses in 1.4 s (about 2 per second, below the 3-per-second
// limit) and never flashes white. With prefers-reduced-motion nothing plays at all.

export const POLTERGEIST_MIN_SCORE = 70
export const HAUNT_CLASS = 'is-haunted'
export const FLICKER_MS = 1400 // the root class is removed after this
export const EFFECT_MS = 3000 // the overlay (and its bats) is removed after this
const REDUCED_MOTION_QUERY = '(prefers-reduced-motion: reduce)'

// Seven bats from different edges. x/y are vw/vh: start, a curved middle point, end.
// w is the width in px, d the duration and dl the delay in seconds (d + dl <= 2.9 s).
export const HAUNT_BATS = [
  { w: 54, d: 2.2, dl: 0, x: [-12, 40, 112], y: [18, 6, 24] },
  { w: 36, d: 2.0, dl: 0.25, x: [112, 55, -12], y: [62, 50, 70] },
  { w: 46, d: 2.4, dl: 0.1, x: [20, 34, 70], y: [110, 50, -15] },
  { w: 30, d: 1.8, dl: 0.6, x: [-12, 30, 80], y: [-12, 30, 112] },
  { w: 62, d: 2.5, dl: 0.35, x: [112, 60, 10], y: [-10, 30, 112] },
  { w: 40, d: 1.9, dl: 0.9, x: [-12, 50, 112], y: [84, 70, 40] },
  { w: 34, d: 2.1, dl: 0.5, x: [84, 70, 30], y: [112, 60, -15] },
]

/** True for a result in the poltergeist range (score 70-100). */
export function isPoltergeist(result) {
  return typeof result?.riskScore === 'number' && result.riskScore >= POLTERGEIST_MIN_SCORE
}

/** True when the user asked for reduced motion. Never throws. */
export function prefersReducedMotion(win = globalThis.window) {
  try {
    return Boolean(win?.matchMedia?.(REDUCED_MOTION_QUERY)?.matches)
  } catch {
    return false
  }
}

/**
 * Starts the effect for `result` if it is a poltergeist result and motion is allowed: adds
 * HAUNT_CLASS to `root` and calls onChange(true); removes the class after FLICKER_MS and calls
 * onChange(false) after EFFECT_MS. Returns a stop function that clears the timers, removes the
 * class and calls onChange(false) if the effect was still running. Otherwise returns a no-op.
 *
 * @param {{ riskScore?: number } | null} result
 * @param {{ root?: { classList: DOMTokenList } | null, onChange?: (active: boolean) => void, win?: object }} options
 * @returns {() => void}
 */
export function startPoltergeist(result, { root, onChange = () => {}, win } = {}) {
  if (!isPoltergeist(result) || prefersReducedMotion(win)) return () => {}

  let running = true
  root?.classList.add(HAUNT_CLASS)
  onChange(true)
  const unflicker = setTimeout(() => root?.classList.remove(HAUNT_CLASS), FLICKER_MS)
  const finish = setTimeout(() => {
    running = false
    onChange(false)
  }, EFFECT_MS)

  return () => {
    clearTimeout(unflicker)
    clearTimeout(finish)
    root?.classList.remove(HAUNT_CLASS)
    if (running) {
      running = false
      onChange(false)
    }
  }
}
