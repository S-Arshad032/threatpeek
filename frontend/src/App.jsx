// Placeholder page that only proves the pipeline works. Replace it freely.
import { useState } from 'react'
import { analyze, MAX_CHARS } from './api.js'

export default function App() {
  const [text, setText] = useState('')
  const [output, setOutput] = useState('')
  const [busy, setBusy] = useState(false)

  async function onAnalyze() {
    setBusy(true)
    try {
      const result = await analyze(text, { useAI: false })
      setOutput(JSON.stringify(result, null, 2))
    } catch (err) {
      setOutput(`Error: ${err.message}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <main style={{ maxWidth: 720, margin: '2rem auto', padding: '0 1rem', fontFamily: 'sans-serif' }}>
      <h1>ThreatPeek (placeholder)</h1>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        maxLength={MAX_CHARS}
        rows={8}
        style={{ width: '100%' }}
        placeholder="Paste a link, email or SMS"
      />
      <p>
        <button type="button" onClick={onAnalyze} disabled={busy}>
          {busy ? 'Analyzing…' : 'Analyze'}
        </button>{' '}
        {text.length}/{MAX_CHARS}
      </p>
      {/* Plain text only: the result contains untrusted text copied from the input. */}
      <pre style={{ whiteSpace: 'pre-wrap' }}>{output}</pre>
    </main>
  )
}
