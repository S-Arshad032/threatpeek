import { useEffect, useRef, useState } from 'react'
import { analyze, MAX_CHARS } from './api.js'
import { clipFailsafeMs, playClip, primeClip, stopClip, typingDelay } from './voice.js'
import './App.css'

const MESSAGE = 'Hi, I am Chithi, the peeker! Please check the text before getting hacked!'

const moods = {
  pookie: { name: 'Pookie', risk: 'Low risk', say: "It's safe to respond.", advice: 'Still, review the sender and any links before acting.' },
  skeptical: { name: 'Skeptical', risk: 'Medium risk', say: 'Think before responding.', advice: 'Review the warning signs before clicking or replying.' },
  poltergeist: { name: 'Poltergeist', risk: 'High risk', say: "Please don't respond!", advice: 'Avoid clicking links or sharing information. Verify the sender independently.' },
}

const sounds = {
  pookie: { wave: 'sine', peak: 0.09, notes: [[523, 0, 0.2], [659, 0.09, 0.2], [784, 0.18, 0.2], [1046, 0.27, 0.45]] },
  skeptical: { wave: 'triangle', peak: 0.09, notes: [[330, 0, 0.38, 250], [290, 0.32, 0.5, 380]] },
  poltergeist: { wave: 'sawtooth', peak: 0.07, notes: [[110, 0, 0.6, 45], [82, 0.05, 0.7, 40]], noise: 0.6 },
  poke: { wave: 'sine', peak: 0.1, notes: [[900, 0, 0.09, 1700], [1500, 0.08, 0.14, 800]] },
  tick: { wave: 'square', peak: 0.03, notes: [[2400, 0, 0.03], [2200, 0.09, 0.03], [2600, 0.18, 0.03]] },
}

const drifters = [
  { left: '5%', s: 70, d: 22, dl: 0 },
  { left: '24%', s: 46, d: 28, dl: 6 },
  { left: '48%', s: 90, d: 34, dl: 12 },
  { left: '70%', s: 54, d: 25, dl: 3 },
  { left: '90%', s: 76, d: 30, dl: 15 },
]

const bats = [
  { top: '14%', d: 17, dl: 1 },
  { top: '32%', d: 23, dl: 9 },
  { top: '8%', d: 29, dl: 16 },
]

function Backdrop() {
  return (
    <div className="backdrop" aria-hidden="true">
      <div className="moon" />
      {drifters.map((g, i) => (
        <svg
          key={i}
          className="drifter"
          viewBox="0 0 60 60"
          style={{ left: g.left, '--s': `${g.s}px`, '--d': `${g.d}s`, '--dl': `-${g.dl}s` }}
        >
          <rect x="6" y="14" width="48" height="36" rx="5" fill="currentColor" />
          <path d="m6 17 24 19 24-19" fill="none" stroke="#0d0817" strokeWidth="3" strokeLinejoin="round" />
        </svg>
      ))}
      {bats.map((b, i) => (
        <svg
          key={i}
          className="bat"
          viewBox="0 0 60 30"
          style={{ top: b.top, '--d': `${b.d}s`, '--dl': `-${b.dl}s` }}
        >
          <path className="wing wl" d="M28 16C22 6 12 4 2 8c5 2 6 6 6 10 5-3 11-2 14 2z" />
          <path className="wing wr" d="M32 16C38 6 48 4 58 8c-5 2-6 6-6 10-5-3-11-2-14 2z" />
          <ellipse cx="30" cy="17" rx="4" ry="6" />
        </svg>
      ))}
    </div>
  )
}

function Chithi({ mood = 'idle', busy, poked, greeting, asleep }) {
  const angry = mood === 'poltergeist'
  const eye = angry ? '#9c1030' : '#2a1622'
  return (
    <svg className={`ghost${poked ? ' poked' : ''}${greeting ? ' hello' : ''}${asleep ? ' asleep' : ''}`} viewBox="0 0 200 200" aria-hidden="true">
      <defs>
        <linearGradient id="chithi-fade" x1="0" y1="0" x2="0" y2="1">
          <stop offset=".55" stopColor="currentColor" />
          <stop offset="1" stopColor="currentColor" stopOpacity=".7" />
        </linearGradient>
      </defs>
      <g transform="rotate(-5 100 100)">
        <g transform="translate(38 124) rotate(-25)">
          <rect className="arm arm-l" x="-32" y="-9" width="36" height="18" rx="9" fill="currentColor" />
        </g>
        <g transform="translate(162 124) rotate(25)">
          <rect className="arm arm-r" x="-4" y="-9" width="36" height="18" rx="9" fill="currentColor" />
        </g>
        <path
          className="envelope"
          fill="url(#chithi-fade)"
          d="M34 60Q34 38 56 38h88q22 0 22 22v82
             C166 154 139 158 122 160
             C134 171 122 194 94 194
             C107 188 110 182 101 177
             C91 172 82 172 75 164
             C59 164 34 161 34 148Z"
        />
        <path
          d="M105 167C114 164 123 167 122 174
             C120 182 112 189 102 192
             C111 185 110 180 103 176
             C98 173 99 169 105 167Z"
          fill="#fff"
          opacity=".22"
        />
        <path d="M40 124 100 154l60-30" fill="none" stroke="#24142c" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" opacity=".12" />
        <g className="flap">
          <path d="M34 60Q34 38 56 38h88q22 0 22 22L100 98Z" fill="#fff" opacity=".35" />
          <path d="M40 54 100 96l60-42" fill="none" stroke="#d8bfe6" strokeWidth="9" strokeLinecap="round" strokeLinejoin="round" />
        </g>
        <g className="ghost-face">
          {asleep ? (
            <>
              <path className="ghost-line" d="M64 110q12 9 24 0M114 110q12 9 24 0" strokeWidth="4" />
              <ellipse cx="100" cy="136" rx="5" ry="4" />
              <path className="ghost-line" d="M56 136l6-3m-2 8 6-3m62-8 6-3m-2 8 6-3" strokeWidth="2.5" stroke="#ef9a8a" opacity=".8" />
            </>
          ) : poked ? (
            <>
              <path className="ghost-line" d="m64 104 16 8-16 8m76-16-16 8 16 8" />
              <ellipse cx="100" cy="134" rx="7" ry="9" />
            </>
          ) : (
            <>
              <g className="eyes">
                <g className={busy ? 'pupils scanning' : 'pupils'}>
                  <ellipse cx="76" cy="112" rx="10" ry="13" fill={eye} />
                  <ellipse cx="126" cy="112" rx="10" ry="13" fill={eye} />
                  <g fill="#fff">
                    <circle cx="80" cy="106" r="3.4" />
                    <circle cx="130" cy="106" r="3.4" />
                    <circle cx="73" cy="118" r="1.7" />
                    <circle cx="123" cy="118" r="1.7" />
                  </g>
                </g>
              </g>
              {mood === 'skeptical' && (
                <>
                  <path d="M114 96h24v14h-24z" fill="currentColor" />
                  <path className="ghost-line brow" d="M114 110h24M60 90q12-11 26-4" strokeWidth="3" />
                  <path className="ghost-line" d="M88 136q8-5 16 0t14-2" strokeWidth="3" />
                </>
              )}
              {angry && (
                <>
                  <path className="ghost-line" d="m60 94 26 10m80-10-26 10" strokeWidth="4" />
                  <ellipse cx="102" cy="138" rx="14" ry="12" />
                  <path d="m92 128 4 9 4-9zm12 0 4 9 4-9z" fill="#fff" />
                </>
              )}
              {mood === 'pookie' && (
                <>
                  <path d="M86 128q14 22 28 0z" fill="#2a1622" />
                  <ellipse cx="100" cy="138" rx="6" ry="3.5" fill="#ff7aa8" />
                </>
              )}
              {mood === 'idle' && (
                <>
                  <path d="M92 130q8 12 16 0z" fill="#2a1622" />
                  <ellipse cx="100" cy="135" rx="4" ry="2.5" fill="#ff7aa8" />
                </>
              )}
              {(mood === 'idle' || mood === 'pookie') && (
                <>
                  <path className="ghost-line" d="M62 92q8-6 16-2M114 90q9-6 18 0" strokeWidth="3" />
                  <path className="ghost-line" d="M56 136l6-3m-2 8 6-3m-2 8 6-3m62-10 6-3m-2 8 6-3m-2 8 6-3" strokeWidth="2.5" stroke="#ef9a8a" opacity=".8" />
                </>
              )}
            </>
          )}
        </g>
        <g className="monocle" fill="none" stroke="#c99a3b" strokeLinecap="round">
          <circle cx="126" cy="112" r="20" strokeWidth="4" fill="rgba(255,255,255,.12)" />
          <path d="M144 124q16 6 12 30" strokeWidth="2" />
        </g>
      </g>
      {busy && (
        <g className="lens" transform="translate(70 108)">
          <circle r="16" fill="rgba(255,255,255,.22)" stroke="#c99a3b" strokeWidth="4" />
          <path d="m11 11 15 15" stroke="#8a5a2b" strokeWidth="6" strokeLinecap="round" />
        </g>
      )}
    </svg>
  )
}

function Spiders({ list }) {
  return (
    <div className="spiders" aria-hidden="true">
      {list.map((sp) => (
        <div key={sp.id} className="spider" style={{ left: sp.left, '--drop': sp.drop, '--dl': sp.delay, '--sz': sp.size }}>
          <span className="thread" />
          <svg className="spider-body" viewBox="0 0 40 40">
            <path className="legs" d="M15 20 4 11m11 12L2 22m13 4L5 34m11-4-6 8m14-18 11-9m-11 12 13-1m-13 5 10 8m-9 0 6 8" fill="none" stroke="#c9a5ff" strokeWidth="2" strokeLinecap="round" />
            <circle cx="20" cy="26" r="9" fill="#5b3a86" />
            <circle cx="20" cy="15" r="6" fill="#6d4a9c" />
            <circle cx="18" cy="14" r="1.6" fill="#ff5d73" />
            <circle cx="22.5" cy="14" r="1.6" fill="#ff5d73" />
            <path d="m20 20 0 12" stroke="#ffb061" strokeWidth="2" />
          </svg>
        </div>
      ))}
    </div>
  )
}

function playSound(context, volume, sound) {
  const start = context.currentTime + 0.02

  for (const [pitch, offset, duration, endPitch] of sound.notes) {
    const oscillator = context.createOscillator()
    const envelope = context.createGain()
    const from = start + offset
    const to = from + duration

    oscillator.type = sound.wave
    oscillator.frequency.setValueAtTime(pitch, from)
    if (endPitch) oscillator.frequency.exponentialRampToValueAtTime(endPitch, to)

    envelope.gain.setValueAtTime(0, from)
    envelope.gain.linearRampToValueAtTime(sound.peak, from + Math.min(0.035, duration / 3))
    envelope.gain.exponentialRampToValueAtTime(0.001, to)

    oscillator.connect(envelope)
    envelope.connect(volume)
    oscillator.onended = () => {
      oscillator.disconnect()
      envelope.disconnect()
    }

    oscillator.start(from)
    oscillator.stop(to)
  }

  if (sound.noise) {
    const length = Math.floor(context.sampleRate * sound.noise)
    const buffer = context.createBuffer(1, length, context.sampleRate)
    const data = buffer.getChannelData(0)
    for (let i = 0; i < length; i++) data[i] = Math.random() * 2 - 1
    const source = context.createBufferSource()
    const filter = context.createBiquadFilter()
    const gain = context.createGain()
    source.buffer = buffer
    filter.type = 'lowpass'
    filter.frequency.value = 500
    gain.gain.setValueAtTime(0.12, start)
    gain.gain.exponentialRampToValueAtTime(0.001, start + sound.noise)
    source.connect(filter)
    filter.connect(gain)
    gain.connect(volume)
    source.start(start)
  }
}

// How long a synth sound lasts until its last note (or noise burst) has faded, in ms.
function soundLengthMs(sound) {
  if (!sound) return 0
  const notes = sound.notes.map(([, offset, duration]) => offset + duration)
  return Math.ceil((Math.max(sound.noise || 0, ...notes) + 0.02) * 1000)
}

function useCountUp(target) {
  const [n, setN] = useState(0)
  useEffect(() => {
    if (target == null) {
      setN(0)
      return
    }
    let raf
    let t0
    const tick = (t) => {
      t0 ??= t
      const p = Math.min((t - t0) / 700, 1)
      setN(Math.round(target * (1 - (1 - p) ** 3)))
      if (p < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [target])
  return n
}

export default function App() {
  const [text, setText] = useState('')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [soundOn, setSoundOn] = useState(true)
  const audio = useRef(null)
  const soundEnabled = useRef(true)
  const input = useRef(null)
  const stage = useRef(null)
  const flyer = useRef(null)
  // sleep -> (tap) -> intro (greeting) -> fly -> ready
  const [phase, setPhase] = useState('sleep')
  // How the intro clip went: null while starting, then { played, duration, ended }
  const [introPlan, setIntroPlan] = useState(null)
  const [typed, setTyped] = useState('')
  const [flyRect, setFlyRect] = useState(null)
  const [spiders, setSpiders] = useState([])
  const [poked, setPoked] = useState(false)
  const [home] = useState(() => {
    const w = Math.min(280, window.innerWidth * 0.6, window.innerHeight * 0.36)
    // Leave room above Chithi for the "Tap Chithi to wake him up" hint.
    return { w, left: (window.innerWidth - w) / 2, top: Math.max(76, (window.innerHeight - w - 130) / 2 + 24) }
  })

  const tooLong = text.length > MAX_CHARS
  const mood = result ? moods[result.verdict] : null
  const score = useCountUp(result ? result.riskScore : null)
  const verdict = result?.verdict

  // Chithi's eyes follow the pointer
  useEffect(() => {
    const move = (e) => {
      for (const el of [stage.current, flyer.current]) {
        if (!el) continue
      const r = el.getBoundingClientRect()
      const dx = e.clientX - (r.left + r.width / 2)
      const dy = e.clientY - (r.top + r.height / 2)
      const d = Math.hypot(dx, dy) || 1
      const k = Math.min(d / 160, 1) * 6
      el.style.setProperty('--ex', `${(dx / d) * k}px`)
      el.style.setProperty('--ey', `${(dy / d) * k}px`)
      }
    }
    window.addEventListener('pointermove', move)
    return () => window.removeEventListener('pointermove', move)
  }, [])

  function prepareAudio() {
    if (!soundEnabled.current) return Promise.resolve(null)

    try {
      if (!audio.current) {
        const AudioContext = window.AudioContext || window.webkitAudioContext
        if (!AudioContext) return Promise.resolve(null)
        const context = new AudioContext()
        const volume = context.createGain()
        volume.connect(context.destination)
        audio.current = { context, volume }
      }

      const activeAudio = audio.current
      return activeAudio.context.resume()
        .then(() => activeAudio)
        .catch(() => null)
    } catch {
      return Promise.resolve(null)
    }
  }

  function clipVolume() {
    return audio.current ? audio.current.volume.gain.value : 1
  }

  // Unmounting stops anything Chithi is still saying.
  useEffect(() => stopClip, [])

  // Chithi sleeps until tapped. playClip() calls play() synchronously, inside the
  // tap/keypress, which browsers (iOS Safari especially) require before audio starts.
  function wakeUp() {
    if (phase !== 'sleep') return
    setIntroPlan(null)
    let settled = false
    let slow
    const settle = (plan) => {
      if (settled) return
      settled = true
      clearTimeout(slow)
      setIntroPlan(plan)
    }
    // A clip that takes too long to start would talk over the fly: drop it and
    // use the old timing instead.
    slow = setTimeout(() => {
      stopClip()
      settle({ played: false })
    }, 1500)
    playClip('intro', { enabled: soundEnabled.current, volume: clipVolume() }).then((r) => {
      settle(r.played ? { played: true, duration: r.duration, ended: r.ended } : { played: false })
    })
    // No synth sounds in the intro: the recorded clip is the only thing heard.
    setPhase('intro')
  }

  // Play the verdict clip once per result (keyed on the result object, so
  // re-renders do not repeat it). A new Peek, Clear or edit sets result to null,
  // and the cleanup stops the clip.
  // PRIVACY: only the fixed recorded clips are played, never anything derived
  // from the user's message.
  useEffect(() => {
    const v = result?.verdict
    if (!moods[v]) return
    // Wait for the synth verdict sound to finish (it is under 1 s), and at least
    // 400 ms, so the two never overlap.
    const t = setTimeout(() => {
      playClip(v, { enabled: soundEnabled.current, volume: clipVolume() })
    }, Math.max(400, soundLengthMs(sounds[v]) + 60))
    return () => {
      clearTimeout(t)
      stopClip()
    }
  }, [result])

  // Intro: Chithi greets, then flies to the result panel while the scanner pops in.
  // With the intro clip playing, typing is paced to end ~0.3 s before the clip, and
  // the fly waits for the clip to end (failsafe: duration + 0.5 s, max 9 s).
  // Without it (blocked, missing, Sound off), the old fixed timing is used.
  useEffect(() => {
    if (phase !== 'intro' || !introPlan) return
    const withClip = introPlan.played
    let i = 0
    let wait
    let failsafe
    let cancelled = false
    let typingDone = false
    let clipDone = !withClip
    const maybeFly = () => {
      if (!cancelled && typingDone && clipDone) {
        cancelled = true
        startFly()
      }
    }
    if (withClip) {
      const finishClip = () => {
        clipDone = true
        maybeFly()
      }
      introPlan.ended.then(finishClip)
      // This effect runs right after the clip starts, so time the failsafe from here.
      failsafe = setTimeout(finishClip, clipFailsafeMs(introPlan.duration))
    }
    const id = setInterval(() => {
      i += 1
      setTyped(MESSAGE.slice(0, i))
      if (i >= MESSAGE.length) {
        clearInterval(id)
        typingDone = true
        if (withClip) maybeFly()
        else wait = setTimeout(maybeFly, 900)
      }
    }, withClip ? typingDelay(MESSAGE.length, introPlan.duration) : 32)
    return () => {
      cancelled = true
      clearInterval(id)
      clearTimeout(wait)
      clearTimeout(failsafe)
    }
  }, [phase, introPlan])

  function startFly() {
    const r = stage.current?.getBoundingClientRect()
    const visible = r && r.top < window.innerHeight - r.width / 2
    setFlyRect(visible ? { left: r.left, top: r.top, width: r.width } : null)
    setPhase('fly')
  }

  useEffect(() => {
    if (phase !== 'fly') return
    const t = setTimeout(() => setPhase('ready'), 1050)
    return () => clearTimeout(t)
  }, [phase])

  function skip() {
    // Straight to the app, in silence.
    stopClip()
    setPhase('ready')
  }

  function poke() {
    if (phase !== 'ready') return
    setPoked(true)
    setTimeout(() => setPoked(false), 600)
    const n = 3 + Math.floor(Math.random() * 2)
    const stamp = Date.now()
    const batch = Array.from({ length: n }, (_, i) => ({
      id: `${stamp}-${i}`,
      left: `${8 + (i + Math.random() * 0.7) * (84 / n)}%`,
      drop: `${14 + Math.random() * 40}vh`,
      delay: `${i * 0.18}s`,
      size: `${30 + Math.random() * 20}px`,
    }))
    setSpiders((list) => [...list, ...batch])
    setTimeout(() => setSpiders((list) => list.filter((sp) => !batch.includes(sp))), 4700)
    prepareAudio().then((a) => {
      if (!a) return
      playSound(a.context, a.volume, sounds.poke)
      setTimeout(() => playSound(a.context, a.volume, sounds.tick), 220)
    })
  }

  function toggleSound() {
    const next = !soundEnabled.current
    soundEnabled.current = next
    setSoundOn(next)

    if (audio.current) audio.current.volume.gain.value = next ? 1 : 0
    // The Sound toggle covers Chithi's voice too.
    if (!next) stopClip()
  }

  function updateText(value) {
    setText(value)
    setResult(null)
    setError('')
  }

  async function paste() {
    try {
      updateText(await navigator.clipboard.readText())
      input.current?.focus()
    } catch {
      setError('Could not read the clipboard. Paste the message into the box instead.')
    }
  }

  async function handlePeek(event) {
    event.preventDefault()
    if (busy || tooLong || !text.trim()) return

    const readyAudio = prepareAudio()
    stopClip()
    // The verdict clip can only start after the analysis (>= 1.4 s) and the synth
    // sound, i.e. outside this click. iOS allows that only because the same shared
    // <audio> element was played inside a gesture before: the wake tap, or this
    // muted prime for users who skipped the intro. If iOS still refuses (e.g. Low
    // Power Mode or the silent switch), the clip stays silent and the text result
    // is unaffected.
    if (soundEnabled.current) primeClip()
    setBusy(true)
    setResult(null)
    setError('')

    let nextResult
    try {
      const [res] = await Promise.all([
        analyze(text, { useAI: false }),
        new Promise((r) => setTimeout(r, 1400)),
      ])
      nextResult = res
      setResult(nextResult)
    } catch {
      setError('Could not analyze this message. Please try again.')
    } finally {
      setBusy(false)
    }

    if (nextResult && moods[nextResult.verdict]) {
      void readyAudio.then((activeAudio) => {
        if (activeAudio && soundEnabled.current) {
          playSound(activeAudio.context, activeAudio.volume, sounds[nextResult.verdict])
        }
      }).catch(() => {})
    }
  }

  return (
    <div className="app" data-mood={verdict || 'idle'} data-phase={phase}>
      <Backdrop />
      <Spiders list={spiders} />
      <main className="shell">
        <header className="topbar">
          <span className="brand"><span aria-hidden="true">◈</span> ThreatPeek</span>
          <button
            className="secondary"
            type="button"
            aria-label="Sound"
            aria-pressed={soundOn}
            onClick={toggleSound}
          >
            Sound {soundOn ? 'On' : 'Off'}
          </button>
        </header>

        <section className="intro">
          <h1>What’s haunting your inbox?</h1>
          <p>Paste a suspicious email or message. Chithi will tell you if it’s phishing.</p>
        </section>

        <div className="dashboard">
          <form className="panel composer" onSubmit={handlePeek}>
            <h2>Message scanner</h2>
            <label htmlFor="message">Email or message</label>
            <textarea
              ref={input}
              id="message"
              value={text}
              placeholder="Paste the message you want to check…"
              onChange={(event) => updateText(event.target.value)}
              onKeyDown={(event) => {
                if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') handlePeek(event)
              }}
              disabled={busy}
              aria-describedby="character-count"
              aria-invalid={tooLong}
            />

            <div className="form-footer">
              <span id="character-count" className={tooLong ? 'error' : ''}>
                {text.length.toLocaleString()} / {MAX_CHARS.toLocaleString()}
              </span>
              <div className="actions">
                <button className="secondary" type="button" onClick={paste} disabled={busy}>
                  Paste
                </button>
                <button
                  className="secondary"
                  type="button"
                  onClick={() => {
                    updateText('')
                    input.current?.focus()
                  }}
                  disabled={busy || !text}
                >
                  Clear
                </button>
                <button className="primary" type="submit" disabled={busy || tooLong || !text.trim()}>
                  {busy ? 'Peeking…' : 'Peek'}
                </button>
              </div>
            </div>
            <small className="hint">Tip: press Ctrl or ⌘ + Enter to peek.</small>

            {tooLong && <p className="error">Keep the message within {MAX_CHARS.toLocaleString()} characters.</p>}
            {error && <p className="error" role="alert">{error}</p>}
          </form>

          <section
            className={`panel result${busy ? ' busy' : ''}`}
            data-mood={verdict || 'idle'}
            aria-live="polite"
            aria-label="Scan result"
          >
            <div key={mood ? verdict : busy ? 'busy' : 'idle'} className="bubble" role="status">
              {mood ? mood.say : busy ? 'Peeking…' : 'Paste a message and I’ll peek!'}
            </div>
            <button
              type="button"
              className="stage"
              ref={stage}
              onClick={poke}
              disabled={phase !== 'ready'}
              aria-label="Poke Chithi"
            >
              <Chithi mood={verdict || 'idle'} busy={busy} poked={poked} />
            </button>
            {mood ? (
              <>
                <p className="risk-label">{mood.risk}</p>
                <h2>{mood.name}</h2>
                <div className="score"><strong>{score}</strong> / 100</div>
                <meter min="0" max="100" value={score} aria-label="Risk score" />
                <p>{mood.advice}</p>
                <small>This is an estimate, not a guarantee.</small>
                {result.confidence === 'limited' && (
                  <small>Heuristics only. No AI check was run.</small>
                )}
              </>
            ) : (
              <>
                <h2>{busy ? 'Peeking…' : 'Ready to peek'}</h2>
                <p>{busy ? 'Checking the message for warning signs.' : 'Your result will appear here.'}</p>
                <small>Psst… try poking Chithi.</small>
              </>
            )}
          </section>
        </div>

        {result && (
          <section className="panel findings" aria-labelledby="findings-title">
            <h2 id="findings-title">
              Warning signs{result.redFlags.length ? ` (${result.redFlags.length})` : ''}
            </h2>
            {result.redFlags.length ? (
              <ul>
                {result.redFlags.map((flag, index) => (
                  <li key={`${flag.id}-${index}`}>
                    <h3>{flag.id.replaceAll('-', ' ')}</h3>
                    {flag.evidence && <code>{flag.evidence}</code>}
                    <p>{flag.explanation}</p>
                  </li>
                ))}
              </ul>
            ) : (
              <p>No warning signs detected in this scan. Stay cautious with unexpected requests.</p>
            )}
          </section>
        )}
      </main>

      {phase !== 'ready' && (
        <div className={`curtain is-${phase}`}>
          <div className="veil" />
          {phase === 'sleep' && (
            <p className="wake-hint" style={{ top: home.top - 62 }}>Tap Chithi to wake him up</p>
          )}
          <div
            ref={flyer}
            className="flyer"
            style={
              phase === 'fly' && flyRect
                ? flyRect
                : phase === 'fly'
                  ? { left: home.left, top: home.top, width: home.w, opacity: 0, transform: 'scale(.6)' }
                  : { left: home.left, top: home.top, width: home.w }
            }
          >
            {phase === 'sleep' ? (
              <button type="button" className="wake" onClick={wakeUp} aria-label="Wake Chithi up" autoFocus>
                <Chithi mood="idle" asleep />
                <span className="zzz" aria-hidden="true"><span>z</span><span>z</span><span>z</span></span>
              </button>
            ) : (
              <Chithi mood="idle" greeting={phase === 'intro'} />
            )}
          </div>
          {phase !== 'sleep' && (
            <div className="bubble up intro-bubble" style={{ top: home.top + home.w + 14 }} aria-live="polite">
              {typed}
            </div>
          )}
          <button className="secondary skip" type="button" onClick={skip}>Skip intro</button>
        </div>
      )}
    </div>
  )
}