import { useEffect, useState } from 'react'
import { HAUNT_BATS, startPoltergeist } from './poltergeist.js'

/** The bat silhouette, shared with the backdrop bats in App.jsx. */
export function BatShape() {
  return (
    <>
      <path className="wing wl" d="M28 16C22 6 12 4 2 8c5 2 6 6 6 10 5-3 11-2 14 2z" />
      <path className="wing wr" d="M32 16C38 6 48 4 58 8c-5 2-6 6-6 10-5-3-11-2-14 2z" />
      <ellipse cx="30" cy="17" rx="4" ry="6" />
    </>
  )
}

/** Fixed, click-through overlay: a dark red pulse layer and the bats. */
export function PoltergeistOverlay() {
  return (
    <div className="haunt" aria-hidden="true">
      <div className="haunt-shade" />
      {HAUNT_BATS.map((b, i) => (
        <svg
          key={i}
          className="haunt-bat"
          viewBox="0 0 60 30"
          style={{
            '--w': `${b.w}px`,
            '--d': `${b.d}s`,
            '--dl': `${b.dl}s`,
            '--x0': `${b.x[0]}vw`, '--x1': `${b.x[1]}vw`, '--x2': `${b.x[2]}vw`,
            '--y0': `${b.y[0]}vh`, '--y1': `${b.y[1]}vh`, '--y2': `${b.y[2]}vh`,
          }}
        >
          <BatShape />
        </svg>
      ))}
    </div>
  )
}

/**
 * Plays the poltergeist screen effect once for each new result scoring 70 or more.
 * `result` changes identity for every new peek (and is null while peeking or after Clear), so
 * the effect restarts for a new poltergeist result and stops when the result goes away.
 * `rootRef` points at the app root wrapper that gets the flicker class.
 */
export default function PoltergeistEffect({ result, rootRef }) {
  const [run, setRun] = useState(0)
  const [active, setActive] = useState(false)

  useEffect(() => {
    if (!result) return undefined
    return startPoltergeist(result, {
      root: rootRef?.current,
      onChange: (on) => {
        if (on) setRun((n) => n + 1)
        setActive(on)
      },
    })
  }, [result, rootRef])

  return active ? <PoltergeistOverlay key={run} /> : null
}
