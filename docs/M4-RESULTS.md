> **Update 2026-10-11:** the path-traversal failure reported below has been fixed
> (template no longer uses `normalizePath`, targets the URI, and the mutation engine
> now mutates paths; promoted offline at 100% of the campaign and of 84 mutants, 0
> false positives). The arms-race table below is the original run and has **not**
> been re-run with the fix. The induced self-DoS result is unaffected (it replays
> the benign corpus and does not depend on user-agents).

# M4 — Adaptive adversary + induced self-DoS (first results)

The highest-research-value milestone. Two experiments.

## 1. Induced self-DoS (the headline, open question 5)

*Can an adversary craft traffic that looks malicious but resembles real user
traffic, so the rule AEGIS invents blocks legitimate users?* `eval/self_dos.py`
measures it with and without the validation gate.

Adversarial campaigns blend SQLi into the exact weird-but-legitimate strings
real users send (apostrophe names, "or"/"select" in product text). We then
measure how much of the 443,507-request benign corpus each candidate rule would
block.

| Responder | Max legit traffic forced-blocked |
|---|---|
| **Un-gated / naive** (deploys the overfit rule) | **0.6151%** (an "block any apostrophe" rule kills every O'Brien / O'Neill) |
| **AEGIS (gated)** | **0.0083%** |

**The gate reduces induced self-DoS ~74x** (0.615% -> 0.008%), rejecting every
overfit candidate (apostrophe rule 0.62%, "or" rule 0.032%, "select" rule
0.032% -- all above the 0.01% budget). The residual 0.008% is the FP-budget
edge (strong passwords, unicode-art filenames), not targeted users.

Rate-limit rules add a second structural defence: they are **per-actor** (keyed
on the session fingerprint), so an attacker cannot push *another* actor over the
limit -- induced self-DoS via rate limiting is ~0 by construction.

**This is the publishable finding:** the validation gate is not just a safety
check, it is a *defence against a specific attack on the defender*, and we put a
number on it.

## 2. Adaptive adversary arms race

`eval/arms_race.py` -- a red agent that changes technique each move; AEGIS must
mitigate each, starting from empty memory.

| Move | AEGIS response | Time-to-mitigate |
|---|---|---|
| 1. SQLi | fresh (generate + gate) | 18,972 ms |
| 2. XSS | fresh | 10,224 ms |
| 3. path traversal | **none** (template failed the gate) | — |
| 4. SQLi variant (union-only) | generalised (reuse rule) | 40 ms |
| 5. SQLi repeat | reused (memory) | **1.7 ms** |

- **Coverage: 4/5 moves mitigated.**
- **Repeats/variants met ~700x faster** than first exposure (14.6 s -> 21 ms):
  memory keeps up as the adversary adapts.
- Move 5 (exact repeat) -> reused in 1.7 ms; move 4 (variant) -> generalised in
  40 ms. The signature->rule mapping lets one rule defend many campaigns.

## Honest findings (report the bad ones too)
- **Path traversal was NOT mitigated.** The template's `normalizePath` transform
  resolves `../` before the regex sees it, and the logged campaign mixes true
  traversal with `.bak` sensitive-file access -- one rule doesn't cover both.
  A known template-refinement item, logged rather than hidden. Coverage is 4/5,
  not 5/5, and we say so.
- Induced self-DoS is bounded by the FP budget *per rule*; an attacker who finds
  a genuinely malicious payload sitting inside that 0.0083% edge could affect
  those specific benign requests. The budget is a cap, not zero.

## Supporting M2/M3 hardening delivered alongside
- **Action rate limit on AEGIS itself** (invariant 7): `memory/mitigate.py` caps
  new enforcing rules/hour; a fresh synthesis over the cap is refused
  (`governor_blocked`). Verified with cap=1.
- **Variant generalisation** demonstrated: a held-out SQLi variant (new endpoint
  signature) was mitigated via the generalised path in 74 ms, reusing the
  existing rule instead of regenerating.
