import { afterEach, describe, expect, it, vi } from 'vitest'
import { CLIPS, clipFailsafeMs, playClip, primeClip, stopClip, typingDelay } from './voice.js'

describe('CLIPS', () => {
  it('maps the four clip names to /audio/<name>.mp3', () => {
    expect(CLIPS).toEqual({
      intro: '/audio/intro.mp3',
      pookie: '/audio/pookie.mp3',
      skeptical: '/audio/skeptical.mp3',
      poltergeist: '/audio/poltergeist.mp3',
    })
  })
})

describe('playClip() without Audio support', () => {
  it('never throws and resolves { played: false }', async () => {
    expect(globalThis.Audio).toBeUndefined()
    let pending
    expect(() => { pending = playClip('intro', { enabled: true }) }).not.toThrow()
    const result = await pending
    expect(result.played).toBe(false)
    expect(result.duration).toBeNull()
    expect(await result.ended).toBe(false)
    expect(() => stopClip()).not.toThrow()
    expect(() => primeClip()).not.toThrow()
  })

  it('resolves { played: false } for an unknown clip or when disabled', async () => {
    expect((await playClip('nope')).played).toBe(false)
    expect((await playClip('pookie', { enabled: false })).played).toBe(false)
  })
})

describe('typingDelay()', () => {
  it('finishes typing about 0.3 s before the clip ends', () => {
    // 74 characters over 5.56 s - 0.3 s
    expect(typingDelay(74, 5.56)).toBe(71)
  })

  it('clamps to 20-90 ms per character', () => {
    expect(typingDelay(74, 0.5)).toBe(20)
    expect(typingDelay(10, 30)).toBe(90)
  })

  it('falls back to the old speed when the duration is unknown', () => {
    expect(typingDelay(74, null)).toBe(32)
    expect(typingDelay(74, Number.NaN)).toBe(32)
    expect(typingDelay(74, Infinity)).toBe(32)
    expect(typingDelay(0, 5)).toBe(32)
  })
})

describe('clipFailsafeMs()', () => {
  it('waits duration + 0.5 s, at most 9 s', () => {
    expect(clipFailsafeMs(5.56)).toBe(6060)
    expect(clipFailsafeMs(12)).toBe(9000)
    expect(clipFailsafeMs(null)).toBe(9000)
  })
})

describe('playClip() with a stubbed Audio element', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.resetModules()
  })

  function stubAudio(play) {
    const made = []
    class FakeAudio {
      constructor() {
        this.listeners = {}
        this.duration = Number.NaN
        made.push(this)
      }
      addEventListener(type, fn) { (this.listeners[type] ??= new Set()).add(fn) }
      removeEventListener(type, fn) { this.listeners[type]?.delete(fn) }
      fire(type) { for (const fn of [...(this.listeners[type] ?? [])]) fn() }
      play() { return play(this) }
      pause() { this.paused = true }
    }
    vi.stubGlobal('Audio', FakeAudio)
    return made
  }

  it('plays through one shared element and reports the duration and end', async () => {
    const made = stubAudio((el) => {
      el.duration = 5.56
      el.fire('loadedmetadata')
      return Promise.resolve()
    })
    const voice = await import('./voice.js')
    const first = await voice.playClip('intro', { volume: 0.5 })
    expect(first.played).toBe(true)
    expect(first.duration).toBe(5.56)
    expect(made[0].src).toBe('/audio/intro.mp3')
    expect(made[0].volume).toBe(0.5)
    made[0].fire('ended')
    expect(await first.ended).toBe(true)

    await voice.playClip('pookie')
    expect(made).toHaveLength(1)
    expect(made[0].src).toBe('/audio/pookie.mp3')
  })

  it('resolves { played: false } when play() is blocked or the file is missing', async () => {
    stubAudio(() => Promise.reject(new Error('NotAllowedError')))
    const voice = await import('./voice.js')
    const result = await voice.playClip('skeptical')
    expect(result.played).toBe(false)
    expect(await result.ended).toBe(false)
  })

  it('stopClip() pauses the element and settles ended as false', async () => {
    const made = stubAudio(() => Promise.resolve())
    const voice = await import('./voice.js')
    const result = await voice.playClip('poltergeist')
    expect(result.duration).toBeNull()
    voice.stopClip()
    expect(made[0].paused).toBe(true)
    expect(await result.ended).toBe(false)
  })
})
