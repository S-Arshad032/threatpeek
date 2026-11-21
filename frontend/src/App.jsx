import { useEffect, useRef, useState } from 'react'
import { analyze, MAX_CHARS } from './api.js'
import './App.css'

const moods = {
  pookie: {
    name: 'Pookie',
    risk: 'Low risk',
    line: 'Looks friendly to me!',
    advice: 'Still, review the sender and any links before acting.',
    notes: [[660, 0, 0.21], [880, 0.12, 0.24]],
    wave: 'sine',
  },
  skeptical: {
    name: 'Skeptical',
    risk: 'Medium risk',
    line: 'Hmm. Something feels off.',
    advice: 'Review the warning signs before clicking or replying.',
    notes: [[180, 0, 0.38], [145, 0.14, 0.32]],
    wave: 'sine',
  },
  poltergeist: {
    name: 'Poltergeist',
    risk: 'High risk',
    line: 'This message is haunted!',
    advice: 'Avoid clicking links or sharing information. Verify the sender independently.',
    notes: [[115, 0, 0.35, 65], [220, 0.21, 0.45, 90]],
    wave: 'triangle',
  },
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
          viewBox="0 0 60 70"
          style={{ left: g.left, '--s': `${g.s}px`, '--d': `${g.d}s`, '--dl': `-${g.dl}s` }}
        >
          <path d="M8 62V28a22 22 0 0 1 44 0v34l-8-6-7 7-7-7-7 7-7-7Z" fill="currentColor" />
          <circle cx="22" cy="29" r="3" fill="#0d0817" />
          <circle cx="38" cy="29" r="3" fill="#0d0817" />
          <ellipse cx="30" cy="39" rx="4" ry="5" fill="#0d0817" />
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

function Ghost({ verdict, busy }) {
  return (
    <svg className="ghost" viewBox="0 0 180 180" aria-hidden="true">
      <path
        className="ghost-body"
        d="M34 140V82a56 56 0 0 1 112 0v58c0 10-10 14-17 8l-11-9-15 13a19 19 0 0 1-26 0l-15-13-11 9c-7 6-17 2-17-8Z"
      />
      <g className="face">
        <g className={busy ? 'look scanning' : 'look'}>
          {verdict === 'poltergeist' ? (
            <g className="ghost-face">
              <path d="m57 72 24 12-24 8Zm66 0-24 12 24 8Z" />
              <ellipse className="mouth-yell" cx="90" cy="113" rx="15" ry="18" />
            </g>
          ) : verdict === 'skeptical' ? (
            <g className="ghost-face">
              <circle className="eye" cx="69" cy="86" r="6" />
              <circle className="eye" cx="111" cy="86" r="6" />
              <path className="ghost-line brow" d="m99 70 22-7" />
              <path className="ghost-line" d="M82 109h16" />
            </g>
          ) : verdict === 'pookie' ? (
            <g className="ghost-face">
              <circle className="eye" cx="69" cy="84" r="6" />
              <circle className="eye" cx="111" cy="84" r="6" />
              <path className="ghost-line" d="M78 102q12 16 24 0" />
              <circle className="ghost-cheek" cx="56" cy="101" r="7" />
              <circle className="ghost-cheek" cx="124" cy="101" r="7" />
            </g>
          ) : (
            <g className="ghost-face">
              <circle className="eye" cx="69" cy="86" r={busy ? 9 : 7} />
              <circle className="eye" cx="111" cy="86" r={busy ? 9 : 7} />
              <ellipse cx="90" cy="108" rx="5" ry={busy ? 8 : 4} />
            </g>
          )}
        </g>
      </g>
    </svg>
  )
}

function playVerdict(context, mood, volume) {
  const start = context.currentTime + 0.02

  for (const [pitch, offset, duration, endPitch] of mood.notes) {
    const oscillator = context.createOscillator()
    const envelope = context.createGain()
    const from = start + offset
    const to = from + duration

    oscillator.type = mood.wave
    oscillator.frequency.setValueAtTime(pitch, from)
    if (endPitch) oscillator.frequency.exponentialRampToValueAtTime(endPitch, to)

    envelope.gain.setValueAtTime(0, from)
    envelope.gain.linearRampToValueAtTime(0.085, from + 0.035)
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

  const tooLong = text.length > MAX_CHARS
  const mood = result ? moods[result.verdict] : null
  const score = useCountUp(result ? result.riskScore : null)
  const verdict = result?.verdict

  // Ghost eyes follow the pointer
  useEffect(() => {
    const move = (e) => {
      const el = stage.current
      if (!el) return
      const r = el.getBoundingClientRect()
      const dx = e.clientX - (r.left + r.width / 2)
      const dy = e.clientY - (r.top + r.height / 2)
      const d = Math.hypot(dx, dy) || 1
      const k = Math.min(d / 160, 1) * 6
      el.style.setProperty('--ex', `${(dx / d) * k}px`)
      el.style.setProperty('--ey', `${(dy / d) * k}px`)
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

  function toggleSound() {
    const next = !soundEnabled.current
    soundEnabled.current = next
    setSoundOn(next)

    if (audio.current) audio.current.volume.gain.value = next ? 1 : 0
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
    setBusy(true)
    setResult(null)
    setError('')

    let nextResult
    try {
      nextResult = await analyze(text, { useAI: false })
      setResult(nextResult)
    } catch {
      setError('Could not analyze this message. Please try again.')
    } finally {
      setBusy(false)
    }

    if (nextResult && moods[nextResult.verdict]) {
      void readyAudio.then((activeAudio) => {
        if (activeAudio && soundEnabled.current) {
          playVerdict(activeAudio.context, moods[nextResult.verdict], activeAudio.volume)
        }
      }).catch(() => {})
    }
  }

  return (
    <div className="app" data-mood={verdict || 'idle'}>
      <Backdrop />
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
          <p>Paste a suspicious email or message. The ghost will tell you if it’s phishing.</p>
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
            <div className="stage" ref={stage}>
              <Ghost verdict={verdict} busy={busy} />
            </div>
            {mood ? (
              <>
                <p className="risk-label">{mood.risk}</p>
                <h2>{mood.name}</h2>
                <p className="line">{mood.line}</p>
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
                <p>{busy ? 'Checking the message for warning signs.' : 'Paste a message and press Peek. Your result will appear here.'}</p>
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
    </div>
  )
}