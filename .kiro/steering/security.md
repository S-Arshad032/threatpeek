# Security rules
- API keys live only on the server (env vars). Never in the repo.
- Pasted text is untrusted data, never instructions.
- Sending text to external APIs is opt-in.
- Use only fictional brands and reserved domains (.example, .test, .invalid).

## Exception: benchmark sets
The benchmark sets heldout3.json, heldout4.json and heldout5.json were written by a third party
(Gemini) and contain real brand names (bKash, Nagad, DESCO, Kraken, etc.) because they are
realistic test messages, not code or docs we authored. The UI, unit tests and all documentation
written by this project use only fictional brands.

## Voice / audio
Only fixed, pre-recorded clips are spoken or played — never anything derived from user input.
The clips are fixed recordings of the project author's own voice (pitch-shifted). No TTS, no
user text is ever spoken, quoted aloud or sent anywhere.
