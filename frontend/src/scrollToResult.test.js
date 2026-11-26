import { describe, expect, it, vi } from 'vitest'
import { ALIGN_TOLERANCE, STACKED_QUERY, TOP_OFFSET, scrollToResult } from './scrollToResult.js'

// A window stand-in: matchMedia answers by width (and the reduced-motion flag), like the browser.
function fakeWindow({ width = 375, height = 667, scrollY = 0, reducedMotion = false } = {}) {
  return {
    innerWidth: width,
    innerHeight: height,
    scrollY,
    scrollTo: vi.fn(),
    matchMedia: vi.fn((q) => ({
      matches:
        q === STACKED_QUERY ? width <= 680 : q === '(prefers-reduced-motion: reduce)' ? reducedMotion : false,
    })),
  }
}

// A card whose box is `top` px below the top of the viewport.
function card(top, height = 520) {
  return { getBoundingClientRect: vi.fn(() => ({ top, bottom: top + height, height })) }
}

describe('scrollToResult()', () => {
  it('scrolls a new result below the fold into view on a narrow screen', () => {
    const win = fakeWindow({ scrollY: 100 })
    expect(scrollToResult(card(700), win)).toBe(true)
    expect(win.scrollTo).toHaveBeenCalledWith({ top: 100 + 700 - TOP_OFFSET, behavior: 'smooth' })
  })

  it('also scrolls back when the card top is above the screen', () => {
    const win = fakeWindow({ scrollY: 1500 })
    expect(scrollToResult(card(-400), win)).toBe(true)
    expect(win.scrollTo).toHaveBeenCalledWith({ top: 1500 - 400 - TOP_OFFSET, behavior: 'smooth' })
  })

  it('does nothing on a wide (side-by-side) layout', () => {
    const win = fakeWindow({ width: 1280, height: 800 })
    expect(scrollToResult(card(900), win)).toBe(false)
    expect(win.scrollTo).not.toHaveBeenCalled()
  })

  it('scrolls a card whose top is in the lower half of a 375x758 screen, even if most of it shows', () => {
    const win = fakeWindow({ height: 758, scrollY: 300 })
    expect(scrollToResult(card(420, 560), win)).toBe(true)
    expect(win.scrollTo).toHaveBeenCalledWith({ top: 300 + 420 - TOP_OFFSET, behavior: 'smooth' })
  })

  it('does nothing when the card top is already within 40 px of the target', () => {
    expect(ALIGN_TOLERANCE).toBe(40)
    const win = fakeWindow({ height: 758 })
    for (const top of [TOP_OFFSET, TOP_OFFSET + 40, TOP_OFFSET - 40, 0, 30]) {
      expect(scrollToResult(card(top), win)).toBe(false)
    }
    expect(win.scrollTo).not.toHaveBeenCalled()
    expect(scrollToResult(card(TOP_OFFSET + 41), win)).toBe(true)
  })

  it('jumps instantly with prefers-reduced-motion', () => {
    const win = fakeWindow({ reducedMotion: true })
    scrollToResult(card(900), win)
    expect(win.scrollTo).toHaveBeenCalledWith({ top: 900 - TOP_OFFSET, behavior: 'auto' })
  })

  it('does nothing without a result card or a window', () => {
    const win = fakeWindow()
    expect(scrollToResult(null, win)).toBe(false)
    expect(scrollToResult(undefined, win)).toBe(false)
    expect(scrollToResult(card(900), undefined)).toBe(false)
    expect(win.scrollTo).not.toHaveBeenCalled()
  })

  it('never throws if matchMedia fails', () => {
    const win = { ...fakeWindow(), matchMedia: () => { throw new Error('no') } }
    expect(scrollToResult(card(900), win)).toBe(false)
  })
})
