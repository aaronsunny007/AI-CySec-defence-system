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
- Repeat speedup shown on the exact-signature path. Variant **generalisation**
  was demonstrated later (a held-out SQLi variant reused the existing rule in
  ~40-74 ms, see M4-RESULTS) but only for one class.
- The fresh-path timing (19 s) is dominated by the benign-corpus replay; that is
  the honest first-exposure cost, and exactly what reuse avoids.
- The LLM path now exists (see the last section); memory still keeps it rare by
  construction (cheap path = correct path), but its rarity has not been measured
  over a campaign stream.

---

## LLM last-resort path — real-model run (2026-10-11)

`deliberator/llm.py` + `memory/mitigate.py --llm ollama`. Local **Mistral 7B**
(`mistral:latest`, Q4_K_M, via Ollama; ~2.3 GB of its 5 GB fit in the laptop's 4 GB
GPU, the rest on CPU). Not a code-specialised model; the spec's Qwen2.5-Coder is a
planned ablation.

**Campaign:** 12 server-side template-injection probes (`{{7*7}}`, `${7*7}`,
`<%= 7*7 %>`, ...) in `data/attack_corpus/novel_ssti.json`. No template class
covers it, so templates produced nothing and the model was called (invariant 9).
(The dossier was supplied directly; the M1 detector has no signature for SSTI and
would not have flagged this campaign by itself.)

**What the model saw:** only the fixed-vocabulary feature summary (e.g.
`template_double_brace: 4`, `arithmetic_probe: 10`, two known endpoint shapes) —
never raw request text. Verified by test (`tests/test_llm_safety.py`).

### Result: the gate rejected everything, and nothing unsafe got through

Three model calls, 15 candidates, **0 promoted**.

| Call | Candidates | Gate outcome |
|---|---|---|
| mitigate, exposure 1 | 5 | 1 rejected at benign replay (FP 0.0151%), 3 at attack replay (blocked 0/12), 1 at benign replay (**FP 17.16%** — would have blocked 76,116 legitimate requests) |
| mitigate, exposure 2 | 5 | 4 rejected at attack replay (0/12), 1 at benign replay (FP 0.2769%) |
| diagnostic (printed, not gated) | 5 | e.g. `detectSQLi`, `detectXSS`, and an arithmetic regex that covers 6/12 of the campaign and would also match dates like `2026-10-11` |

Failure modes seen: **wrong tool for the class** (`detectSQLi`/`detectXSS` for template
injection); **under-coverage** (best regex matched half the campaign); **over-matching**
(one candidate hit 17% of benign traffic). The model's output also **varies between
calls** with identical input (temperature 0.1), so a candidate with the same id has
different content run to run.

### Cost (invariant 7 / NFR-5)
Per call ~677 tokens in, 520-600 out, **75-86 s** on this laptop; 2 calls = 160.5 s,
1,354 in / 1,081 out tokens, £0. Mitigation attempt time (all LLM): 105-117 s.

### What this does and does not show
- **Shows:** the safety design works end to end on a real model — structured-only
  input, schema-constrained IR output, and a gate that absorbed one rule that would
  have broken 17% of legitimate traffic. The LLM gained no authority.
- **Does not show:** that the LLM path adds capability. For this campaign a 7B
  generic model, one shot, produced nothing promotable.
- The "repeat speedup 1x FAIL" line the CLI prints is an artifact: with no promoted
  rule there is nothing to reuse. It is not a memory failure.
- The "< 5% of campaigns reach the LLM" target (invariant 9) cannot be assessed from
  a single novel campaign; it needs a campaign stream.

### Next (not done)
Structured gate feedback and a repair round (stage + numbers only, no traffic text);
a Qwen2.5-Coder 7B ablation; a larger/API-model ablation for the local-vs-frontier
comparison; a larger set of novel campaigns.
