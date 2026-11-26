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

// Seven bats from different edges: two very large "hero" bats that sweep the whole screen,
// three medium-large ones and two small ones for depth. x/y are the bat's CENTRE in vw/vh:
// start, a curved middle point, end. Start and end are far enough outside the viewport that
// even the largest bat is fully off-screen there. Width is clamp(min px, vw, max px) so the
// bats scale with the viewport (vw is at most 35 and min px fits in 35% of a 375 px screen).
// flap is the wing-beat in seconds (bigger bats beat slower), d the duration and dl the delay
// in seconds (d + dl <= 2.9 s).
export const HAUNT_BATS = [
  { vw: 24, min: 96, max: 380, flap: 0.3, d: 2.6, dl: 0, x: [-22, 45, 122], y: [30, 12, 40] },
  { vw: 21, min: 84, max: 340, flap: 0.28, d: 2.5, dl: 0.4, x: [124, 55, -24], y: [78, 55, 22] },
  { vw: 11, min: 60, max: 170, flap: 0.2, d: 2.2, dl: 0.1, x: [20, 34, 72], y: [118, 50, -18] },
  { vw: 10, min: 56, max: 150, flap: 0.2, d: 2.0, dl: 0.6, x: [-16, 30, 82], y: [-16, 35, 118] },
  { vw: 12, min: 64, max: 180, flap: 0.22, d: 2.3, dl: 0.3, x: [116, 62, 12], y: [-14, 32, 118] },
  { vw: 6, min: 36, max: 90, flap: 0.14, d: 1.9, dl: 0.9, x: [-10, 50, 110], y: [88, 72, 42] },
  { vw: 5, min: 32, max: 76, flap: 0.14, d: 2.0, dl: 0.7, x: [86, 70, 30], y: [112, 60, -12] },
]

/** The CSS width of a haunt bat: scales with the viewport between its min and max. */
export function batWidth(b) {
  return `clamp(${b.min}px, ${b.vw}vw, ${b.max}px)`
}

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
