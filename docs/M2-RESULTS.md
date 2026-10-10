# M2 — Rule synthesis + validation gate (first end-to-end)

The core of AEGIS: synthesise a mitigation and **prove it safe before enforcing**.
Built gate-first, per CLAUDE.md. Demonstrated on the spec's named acceptance
case (SQLi).

## Pipeline
```
dossier (M1) -> deliberator -> candidate Rule IR (x3) -> ir/compile -> Coraza SecRule
                                                              |
                                                     VALIDATION GATE (bin/replay.exe, real Coraza)
                                                              |
   stage 1 benign replay (443,507 reqs)  FP <= 0.01%
   stage 2 campaign replay               block 100% of the observed attack
   stage 4 mutation test (138 mutants)   block >= 80% (generalises, not memorises)
   [stages 3/5/6 regression/shadow/canary -> next sub-step, need live gateway]
                                                              |
                                                     promote / reject (logged)
```

## Acceptance result — live SQLi campaign, no human in the loop

| Candidate | mechanism | benign FP | campaign block | mutation | verdict |
|---|---|---|---|---|---|
| aegis-sqli-1 | detectSQLi, args+body | 0.0083% | 62% | — | REJECTED (efficacy) |
| aegis-sqli-2 | detectSQLi, scoped to /rest/products/search | 0.0000% | 12% | — | REJECTED (efficacy) |
| **aegis-sqli-3** | **regex, quote+keyword/comment + union** | **0.0045%** | **100% (24/24)** | **87% of 138** | **PROMOTED (offline)** |

- FP measured against the full **443,507-request** benign corpus.
- Mutation set = encoding, case, `/**/` comments, whitespace, chunking (range/mutate).
- Every rejected candidate logged with the stage it failed: `logs/gate/decisions.jsonl`.

**This is the thesis contribution working:** an autonomously generated rule was
proven — before enforcement — to block the attack *and its variants* while
breaking **zero** of 443k legitimate requests (0.0045% < 0.01% budget).

## What makes this honest / defensible
- The gate replays through the **real Coraza engine** (bin/replay.exe), so it
  tests exactly what would enforce, not a Python approximation.
- The LLM is NOT involved: candidates are deterministic templates (invariant 9,
  the cheap path = the correct path). The LLM, when added in M3, emits into the
  same IR and passes the same gate — it never gains authority.
- The IR compiler is the trusted boundary: whitelisted targets/operators/
  transforms only, no free-form directives, quotes forbidden, regex validated.
- Candidate selection is real: the naive libinjection rule was rejected for
  both over-blocking (0.0083% FP, borderline) and under-blocking (62%).

## Not yet done (honest status — this is "passed offline", not "enforced")
1. **Gate stages 3/5/6** (app regression suite, shadow, canary + auto-rollback)
   need the live gateway. The gateway already has a `-rules` flag to load a
   candidate, so the path exists; wiring the orchestration is the next sub-step.
   Until then the verdict is `passed_offline`, never silently enforced.
2. **Runtime rule loading** into the running gateway with per-rule modes
   (off/shadow/canary/enforce) and counters — M2 item 5.
3. **Other attack classes.** Candidates are generated for all signature classes
   (xss, traversal, cmdi, ssrf); only SQLi is validated end-to-end here. The
   behavioural classes (credential_stuffing, user_enumeration, idor_bola) need
   the `rate_limit` mechanism compiled (deferred, M2b) — a signature rule is the
   wrong tool for them, which is itself the right finding.
4. **Action rate limit** on autonomous enforcement (≤ N new rules/hour) — M2 item 6.

## Artefacts
- `ir/schema.json`, `ir/compile.py` — Rule IR + compiler/validator
- `deliberator/generate.py` — dossier -> candidate IR (templates)
- `range/mutate/mutate.py` — payload mutation engine
- `gate/gate.py` — the gate
- `gateway/cmd/replay/` -> `bin/replay.exe` — real-engine replay
