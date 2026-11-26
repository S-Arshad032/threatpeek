// On narrow screens the form and the result card stack, so a new result appears below the
// fold. scrollToResult() brings the result card (Chithi, mood and score) into view.

/** Same breakpoint as the stacking rule in App.css (`.dashboard` becomes one column). */
export const STACKED_QUERY = '(max-width: 680px)'
const REDUCED_MOTION_QUERY = '(prefers-reduced-motion: reduce)'
/** Gap left above the card after scrolling, in px. */
export const TOP_OFFSET = 12
/** The card counts as "mostly in view" when its top is on screen and this share is visible. */
export const MOSTLY_VISIBLE = 0.6

function matches(win, query) {
  try {
    return Boolean(win?.matchMedia?.(query)?.matches)
  } catch {
    return false
  }
}

/**
 * Scrolls the window so `card` starts TOP_OFFSET px below the top of the viewport, but only
 * on the stacked (narrow) layout and only if the card is not already mostly in view. Uses an
 * instant jump with prefers-reduced-motion. Does not move focus. Returns true if it scrolled.
 *
 * @param {Element | null} card
 * @param {Window} [win]
 * @returns {boolean}
 */
export function scrollToResult(card, win = globalThis.window) {
  if (!card || !win || typeof win.scrollTo !== 'function') return false
  if (!matches(win, STACKED_QUERY)) return false

  const rect = card.getBoundingClientRect()
  const viewport = win.innerHeight || 0
  const visible = Math.min(rect.bottom, viewport) - Math.max(rect.top, 0)
  const needed = MOSTLY_VISIBLE * Math.min(rect.height, viewport)
  if (rect.top >= 0 && visible >= needed) return false

  win.scrollTo({
    top: Math.max(0, (win.scrollY || 0) + rect.top - TOP_OFFSET),
    behavior: matches(win, REDUCED_MOTION_QUERY) ? 'auto' : 'smooth',
  })
  return true
}
