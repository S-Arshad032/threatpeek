# Tech
- frontend: React + Vite, plain CSS
- audio: four pre-recorded MP3 voice clips (frontend/public/audio/intro.mp3, pookie.mp3,
  skeptical.mp3, poltergeist.mp3), played through one shared Audio element (voice.js); a few
  synthesized sounds (poke, tick, and mood chords) are made with the Web Audio API
- poltergeist effect: full-screen flicker (CSS class on the app root) + a fixed overlay with
  animated SVG bats (PoltergeistEffect.jsx / poltergeist.js), respects prefers-reduced-motion
- mobile UX: scrollToResult() scrolls the result card to the top of the viewport on the
  stacked (≤ 680 px) layout after each new scan
- backend/server: Node.js + Express; serves frontend/dist in production as one Render web
  service (no separate static host)
- backend/engine: pure JS heuristics + scoring, shared by browser and server
- History in localStorage only. No database.
