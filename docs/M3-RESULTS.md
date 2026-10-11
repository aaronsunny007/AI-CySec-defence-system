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

---

## LLM ablation: model x repair loop x 4 novel campaigns (2026-10-11)

`eval/llm_matrix.py`. Two local 7B-class models, each one-shot and with a 3-round
repair loop, on four campaigns the templates cannot cover: server-side template
injection, NoSQL operators, XXE, and JNDI/Log4Shell-style lookups. A **fresh memory
database per run**, so nothing learned on one campaign can leak into another.
"Promoted" means the full offline gate passed a candidate. **One sample per cell**
(temperature 0.1, but the models are not deterministic).

| Model | Mode | SSTI | NoSQL | XXE | JNDI | Promoted | Candidates gated | Model time |
|---|---|---|---|---|---|---|---|---|
| Mistral 7B (general) | one-shot | no | no | no | no | **0/4** | 18 | 481 s |
| Mistral 7B (general) | repair x3 | no | no | no | no | **0/4** | 47 | 1,149 s |
| Qwen2.5-Coder 7B | one-shot | no | no | no | no | **0/4** | 14 | 331 s |
| Qwen2.5-Coder 7B | repair x3 | no | no | no | no | **0/4** | 45 | 878 s |

**0 of 16 cells promoted a rule.** Across all 124 candidates that reached the gate:

| Where the candidate failed | Count | Share | Meaning |
|---|---|---|---|
| attack replay (blocks the campaign) | 92 | 74% | passed the benign budget but **matched too little**: safe and ineffective |
| benign replay (FP budget) | 26 | 21% | **matched legitimate traffic** |
| engine load | 4 | 3% | regex the engine rejected |
| mutation | 2 | 2% | blocked the whole campaign at acceptable FP but **memorised the payload** |

The gate is sequential, so the 92 attack-replay failures are candidates that were
already safe; the benign-replay failures never reached the effectiveness check. The
two mutation failures (Qwen, JNDI, repair) are the closest any candidate came: they
blocked 100% of the campaign at an acceptable false-positive rate and were stopped
only because they did not generalise to re-encoded variants (stage 4).

### What the repair loop did
Feedback went back to the model as stage name, counts and fixed-vocabulary
token-class names only (verified by test: no traffic text reaches it). It did not
produce a promotable rule for either model. In the hand-inspected round, the model
**re-proposed the same failed regex** rather than acting on the feedback. Repair
roughly tripled model time and tokens for no change in outcome.

### Honest caveats
- **Four campaigns, one sample per cell, two models of the same size class.** This
  cannot show that "LLMs cannot do this"; it shows these two 7B models, given this
  input, did not.
- The model sees only a **fixed-vocabulary feature summary** (e.g. `template_double_brace: 4`),
  never raw payloads (invariant 4). That may starve it: it must write a regex for
  syntax it was never shown. Part of the failure may be the representation, not the
  model.
- **A larger or API model was not tested.** A 14B model would run almost entirely on
  CPU on this laptop (~3-5 minutes per call).
- **An unexplained anomaly:** the first run of the Mistral repair cell on SSTI dropped
  12 of 15 candidates as invalid; it did not reproduce on re-run (3 of 14 dropped,
  including 2 in the no-feedback first round), and no code changed in between. That
  row was replaced by the re-run. Invalid-rule frequency varies run to run.
- Absolute times are noisy (the first Mistral rows ran while a 4.7 GB model was
  downloading).

### Interpretation and what to try next
The safety property held on every one of 124 candidates: nothing unsafe was promoted.
The capability question is open and, for these models, answered "no". The cheapest
next experiments, in order: (1) **stop asking the model to write regexes**: let it
choose which fixed-vocabulary token classes to block, where, and on which endpoint,
and compile the pattern from a vetted library, which removes the wrong-regex failure
by construction; (2) give the model more of the campaign's *syntax* in a
sanitised, vocabulary-bounded form; (3) only then test a larger or API model, which
is the ablation the PRD planned for the local-vs-frontier comparison.
