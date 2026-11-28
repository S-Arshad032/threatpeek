# Honesty rules (evaluation)

## Benchmark integrity
- Never tune rules on a set after seeing its misses without marking that set as "seen" in
  RESULTS.md and the READMEs.
- Keep at least one fully unseen set at all times. When a set is used for tuning it is marked
  "seen" and a new set must exist before the next tuning round.
- Report numbers exactly as measured: fraction and percentage, detection (31+), scored 50+,
  high risk (70+), false alarms. Never round up or omit a row.

## Claims and language
- Never call a message "safe". Every result says "This is an estimate, not a guarantee."
- Never claim a detection guarantee or a precision/recall figure without citing the specific
  set, its size, its provenance and its "seen/unseen" status.
- Dev-set numbers are always higher than held-out numbers because the rules were tuned on the
  dev set. Say so when quoting them.

## Known gap
The low-risk (Pookie) speech bubble and the recorded Pookie clip currently say "It's safe to
respond.", which does not match the rule above. This is a known inconsistency, kept on purpose
by the author; the result card below it always says "This is an estimate, not a guarantee."
and the limitations are documented in the READMEs.

## Engine scope
- The engine is English-only and rule-based. Say so.
- It is not a classifier and has no ML model. Its scores are weighted sums of named signals.
- An optional AI second opinion exists in the server code but is off by default and disabled
  in the live demo (the frontend always sends useAI:false).
- State what it misses: scams with no link and no keyword pattern (e.g. rental deposits,
  wrong-number openers, fake-check jobs via WhatsApp), non-English text, and novel phrasing
  for known scam families.
- Fully unseen results so far: heldout4 first contact 13.3% detection (2/15) with 1 false
  alarm, and heldout5 40% detection (6/15) with 0 false alarms. Quote both, never only the
  better one.
