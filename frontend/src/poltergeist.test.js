import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import {
  EFFECT_MS,
  HAUNT_BATS,
  FLICKER_MS,
  HAUNT_CLASS,
  POLTERGEIST_MIN_SCORE,
  isPoltergeist,
  prefersReducedMotion,
  startPoltergeist,
} from './poltergeist.js'
import { PoltergeistOverlay } from './PoltergeistEffect.jsx'

// The tests run without a DOM: the root wrapper is a minimal classList stand-in, and
// "rendered" means the component was told to show the overlay (onChange(true)).
function fakeRoot() {
  const classes = new Set(['app'])
  return {
    classList: {
      add: (c) => classes.add(c),
      remove: (c) => classes.delete(c),
      contains: (c) => classes.has(c),
    },
  }
}

const motionOk = { matchMedia: () => ({ matches: false }) }
const reducedMotion = { matchMedia: (q) => ({ matches: q === '(prefers-reduced-motion: reduce)' }) }

function start(riskScore, win = motionOk) {
  const root = fakeRoot()
  const changes = []
  const stop = startPoltergeist({ riskScore }, { root, win, onChange: (on) => changes.push(on) })
  return { root, changes, stop }
}

beforeEach(() => vi.useFakeTimers())
afterEach(() => vi.useRealTimers())

describe('isPoltergeist()', () => {
  it('is true from 70 to 100 only', () => {
    expect(POLTERGEIST_MIN_SCORE).toBe(70)
    for (const s of [70, 85, 100]) expect(isPoltergeist({ riskScore: s })).toBe(true)
    for (const s of [0, 52, 69]) expect(isPoltergeist({ riskScore: s })).toBe(false)
    expect(isPoltergeist(null)).toBe(false)
  })
})

describe('startPoltergeist()', () => {
  it('renders the effect and adds the root class for a score >= 70', () => {
    const { root, changes } = start(78)
    expect(root.classList.contains(HAUNT_CLASS)).toBe(true)
    expect(changes).toEqual([true])
  })

  it.each([0, 52, 69])('does neither for score %i', (score) => {
    const { root, changes } = start(score)
    vi.advanceTimersByTime(EFFECT_MS)
    expect(root.classList.contains(HAUNT_CLASS)).toBe(false)
    expect(changes).toEqual([])
  })

  it('does neither with prefers-reduced-motion', () => {
    expect(prefersReducedMotion(reducedMotion)).toBe(true)
    const { root, changes } = start(95, reducedMotion)
    expect(root.classList.contains(HAUNT_CLASS)).toBe(false)
    expect(changes).toEqual([])
  })

  it('removes the root class after the flicker and the overlay after the bats', () => {
    const { root, changes } = start(90)
    vi.advanceTimersByTime(FLICKER_MS - 1)
    expect(root.classList.contains(HAUNT_CLASS)).toBe(true)
    vi.advanceTimersByTime(1)
    expect(root.classList.contains(HAUNT_CLASS)).toBe(false)
    expect(changes).toEqual([true])
    vi.advanceTimersByTime(EFFECT_MS - FLICKER_MS)
    expect(changes).toEqual([true, false])
    expect(vi.getTimerCount()).toBe(0)
  })

  it('keeps the flicker under 2 s', () => {
    expect(FLICKER_MS).toBeLessThan(2000)
  })

  it('stop() (unmount, Clear, a new peek) clears timers, the class and the overlay at once', () => {
    const { root, changes, stop } = start(88)
    stop()
    expect(root.classList.contains(HAUNT_CLASS)).toBe(false)
    expect(changes).toEqual([true, false])
    expect(vi.getTimerCount()).toBe(0)
    stop()
    expect(changes).toEqual([true, false])
  })

  it('never throws without matchMedia or a root', () => {
    expect(prefersReducedMotion({})).toBe(false)
    expect(prefersReducedMotion({ matchMedia: () => { throw new Error('no') } })).toBe(false)
    expect(() => startPoltergeist({ riskScore: 99 }, { win: {} })()).not.toThrow()
  })
})

describe('PoltergeistOverlay', () => {
  it('is aria-hidden and has 6-8 inline SVG bats, no images or scripts', () => {
    const html = renderToStaticMarkup(createElement(PoltergeistOverlay))
    expect(html).toMatch(/^<div class="haunt" aria-hidden="true">/)
    const bats = html.match(/<svg class="haunt-bat"/g) ?? []
    expect(bats.length).toBe(HAUNT_BATS.length)
    expect(bats.length).toBeGreaterThanOrEqual(6)
    expect(bats.length).toBeLessThanOrEqual(8)
    expect(html).not.toMatch(/<img|<script|https?:/)
  })

  it('every bat finishes within the 3 s effect', () => {
    for (const b of HAUNT_BATS) expect((b.d + b.dl) * 1000).toBeLessThanOrEqual(EFFECT_MS)
  })
})
