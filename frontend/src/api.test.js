import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { analyze, MAX_CHARS } from './api.js'
import { pookie, skeptical, poltergeist } from './mock.js'

describe('analyze() in mock mode', () => {
  beforeEach(() => vi.stubEnv('VITE_USE_MOCK', 'true'))
  afterEach(() => vi.unstubAllEnvs())

  it('returns pookie for ordinary text', async () => {
    expect(await analyze('See you at lunch tomorrow?')).toEqual(pookie)
  })

  it('returns skeptical when the text contains a link', async () => {
    expect(await analyze('Track it at http://parcel-help.xyz/track')).toEqual(skeptical)
  })

  it('returns poltergeist for "password" or "urgent"', async () => {
    expect(await analyze('Send me your PASSWORD at http://x.example')).toEqual(poltergeist)
    expect(await analyze('Urgent: reply now')).toEqual(poltergeist)
  })

  it(`rejects text longer than ${MAX_CHARS} characters`, async () => {
    await expect(analyze('a'.repeat(MAX_CHARS + 1))).rejects.toThrow(RangeError)
  })
})
