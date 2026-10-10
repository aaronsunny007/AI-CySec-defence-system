# M3 — Closed loop and memory (first results)

Campaign memory (SQLite) so AEGIS gets faster and cheaper each time it is
attacked, instead of regenerating from scratch.

## Mitigation decision (cheapest-correct-path first)
`memory/mitigate.py`:
1. **REUSED** — exact campaign signature already has a proven rule -> use it, no
   gate. The repeat speedup.
2. **GENERALISED** — a rule from the same class already blocks the new campaign
   (quick attack replay) -> reuse it, index it under the new signature too.
3. **FRESH** — nothing fits -> synthesise candidates + run the full gate.

Signature = attack class + targeted endpoint shapes (ids collapsed to `{id}`),
not the literal payload -> a re-encoded or reworded variant still matches.

## Repeat speedup (SQLi, measured)

| Exposure | Source | Time-to-mitigate |
|---|---|---|
| 1st | fresh (generate + full gate) | **18,734 ms** |
| 2nd | reused (memory) | **2.8 ms** |

**Repeat speedup: 6,737x** (target >= 10x) -> PASS.

The reuse path skips candidate generation AND all gate replay (no 443k-request
benign pass), so the second exposure is mitigated in milliseconds.

## Cost-control (invariant 9)
Every outcome is recorded with its source, so the fraction taking the expensive
fresh path is measurable and falls as memory fills. With 2 exposures of one
campaign: 1 fresh, 1 reused. Over a stream dominated by repeats/variants, the
fresh fraction (the only path that would ever call an LLM) trends toward the
rate of genuinely novel campaigns -- the target is < 5%.

## Persisted (memory/aegis.db)
campaigns -> candidates (every gate verdict) -> promoted rules (with ttl +
match counts) -> outcomes (source + time-to-mitigate). Rule garbage collection
(`Memory.gc`) retires rules unmatched past their idle window + TTL.

## Honest limitations
- Repeat speedup shown on the exact-signature path; variant **generalisation**
  across differing endpoints is implemented (`_quick_blocks`) but not yet
  demonstrated on a held-out variant set.
- The fresh-path timing (19 s) is dominated by the benign-corpus replay; that is
  the honest first-exposure cost, and exactly what reuse avoids.
- No LLM yet. Memory makes the LLM path rare *before* it is added, which is the
  design (cheap path = correct path).
