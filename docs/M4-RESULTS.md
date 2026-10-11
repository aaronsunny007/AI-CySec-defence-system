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
| 1. SQLi | fresh (generate + gate) -> `aegis-sqli-3` | 52,469 ms |
| 2. XSS | fresh -> `aegis-xss-2` | 35,072 ms |
| 3. path traversal | fresh -> `aegis-traversal-1` | 19,353 ms |
| 4. SQLi variant (union-only, different endpoint set) | generalised (reuse rule) | 142 ms |
| 5. SQLi repeat | reused (memory) | **3.2 ms** |

**Re-run 2026-10-11** after the path-traversal fix, using ONE clean run per campaign
(the attack log is cumulative, and an earlier version of this script mixed in rows
labelled under an older, mislabelled campaign). The first run of this experiment
reported 4/5 and ~700x; the table above supersedes it.

- **Coverage: 5/5 moves mitigated** (was 4/5 before the traversal fix).
- **Repeats/variants met ~490x faster** than first exposures (35.6 s -> 73 ms).
- Fresh-path times are 2-3x slower than the first run of this experiment (19 s ->
  35-52 s) because the machine was also downloading a 4.7 GB model; treat absolute
  times as noisy and the ratio as the finding. One run, one machine.
- The signature->rule mapping lets one rule defend many campaigns.

## Honest findings
- **Path traversal** was not mitigated in the first run: the template used
  `normalizePath` (which resolves `../` before the regex runs) and inspected args
  instead of the URI, and the logged campaign also contained a plain file read that
  is not traversal at all. Fixed (URI target, no `normalizePath`, path mutations in
  the mutation engine, mislabel corrected): promoted at 100% of the campaign and 100%
  of 84 mutants with 0 false positives.
- **Not yet tested:** an adversary that adapts to the defence (changes technique after
  being blocked). This arms race replays recorded campaigns in a fixed order; it shows
  memory keeping pace, not an adaptive attacker. The slow-and-low evasion measured in
  M1 is the first concrete adaptation to try.
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
