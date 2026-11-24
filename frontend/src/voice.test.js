import { afterEach, describe, expect, it, vi } from 'vitest'
import { cancelSpeech, pickVoice, speak, unlockSpeech } from './voice.js'

const v = (name, lang) => ({ name, lang })

describe('pickVoice()', () => {
  it('prefers en-US over other English voices', () => {
    const voices = [v('Daniel', 'en-GB'), v('Karen', 'en-AU'), v('Alex', 'en-US'), v('Thomas', 'fr-FR')]
    expect(pickVoice(voices).name).toBe('Alex')
  })

  it('falls back to en-GB, then any en-*', () => {
    expect(pickVoice([v('Karen', 'en-AU'), v('Daniel', 'en-GB')]).name).toBe('Daniel')
    expect(pickVoice([v('Amélie', 'fr-CA'), v('Karen', 'en-AU')]).name).toBe('Karen')
    expect(pickVoice([v('Rishi', 'en_IN')]).name).toBe('Rishi')
  })

  it('uses a female/natural-sounding name only as a tie-break', () => {
    const voices = [v('Microsoft David', 'en-US'), v('Microsoft Zira', 'en-US')]
    expect(pickVoice(voices).name).toBe('Microsoft Zira')
    // Language still wins over a friendly name.
    expect(pickVoice([v('Google UK English Female', 'en-GB'), v('Fred', 'en-US')]).name).toBe('Fred')
  })

  it('returns null for an empty list, no English voice, or bad input', () => {
    expect(pickVoice([])).toBeNull()
    expect(pickVoice([v('Anna', 'de-DE')])).toBeNull()
    expect(pickVoice(undefined)).toBeNull()
    expect(pickVoice([null, v('x', undefined)])).toBeNull()
  })
})

describe('speak() without speech support', () => {
  it('does nothing and never throws when speechSynthesis is undefined', () => {
    expect(globalThis.speechSynthesis).toBeUndefined()
    expect(() => speak('Hello', { enabled: true })).not.toThrow()
    expect(speak('Hello', { enabled: true })).toBe(false)
    expect(() => cancelSpeech()).not.toThrow()
    expect(() => unlockSpeech()).not.toThrow()
  })
})

describe('speak() with a stubbed speechSynthesis', () => {
  afterEach(() => vi.unstubAllGlobals())

  function stub() {
    const calls = []
    const synth = {
      getVoices: () => [v('Daniel', 'en-GB'), v('Samantha', 'en-US')],
      addEventListener: vi.fn(),
      cancel: vi.fn(() => calls.push('cancel')),
      speak: vi.fn((u) => calls.push(u)),
    }
    vi.stubGlobal('speechSynthesis', synth)
    vi.stubGlobal('SpeechSynthesisUtterance', class { constructor(text) { this.text = text } })
    return { synth, calls }
  }

  it('cancels first, then speaks with the cute voice settings', () => {
    const { calls } = stub()
    expect(speak("It's safe to respond.", { enabled: true, volume: 0.5 })).toBe(true)
    expect(calls[0]).toBe('cancel')
    const u = calls[1]
    expect(u.text).toBe("It's safe to respond.")
    expect(u.voice.name).toBe('Samantha')
    expect(u.pitch).toBe(1.4)
    expect(u.rate).toBe(1.05)
    expect(u.volume).toBe(0.5)
  })

  it('stays silent when disabled', () => {
    const { synth } = stub()
    expect(speak('Hello', { enabled: false })).toBe(false)
    expect(synth.speak).not.toHaveBeenCalled()
  })
})
