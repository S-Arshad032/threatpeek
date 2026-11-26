// On narrow screens the form and the result card stack, so a new result appears below the
// fold. scrollToResult() brings the result card (Chithi, mood and score) to the top of the screen.

/** Same breakpoint as the stacking rule in App.css (`.dashboard` becomes one column). */
export const STACKED_QUERY = '(max-width: 680px)'
const REDUCED_MOTION_QUERY = '(prefers-reduced-motion: reduce)'
/** Gap left above the card after scrolling, in px. */
export const TOP_OFFSET = 12
/** No scroll when the card top is already this close (px) to its target position. */
export const ALIGN_TOLERANCE = 40

function matches(win, query) {
  try {
    return Boolean(win?.matchMedia?.(query)?.matches)
  } catch {
    return false
  }
}

/**
 * On the stacked (narrow) layout, scrolls the window so `card` starts TOP_OFFSET px below the
 * top of the viewport, unless its top is already within ALIGN_TOLERANCE px of that spot. Uses an
 * instant jump with prefers-reduced-motion. Does not move focus. Returns true if it scrolled.
 *
 * @param {Element | null} card
 * @param {Window} [win]
 * @returns {boolean}
 */
export function scrollToResult(card, win = globalThis.window) {
  if (!card || !win || typeof win.scrollTo !== 'function') return false
  if (!matches(win, STACKED_QUERY)) return false

  const { top } = card.getBoundingClientRect()
  if (Math.abs(top - TOP_OFFSET) <= ALIGN_TOLERANCE) return false

  win.scrollTo({
    top: Math.max(0, (win.scrollY || 0) + top - TOP_OFFSET),
    behavior: matches(win, REDUCED_MOTION_QUERY) ? 'auto' : 'smooth',
  })
  return true
}
