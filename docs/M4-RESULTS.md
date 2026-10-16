# M4 — Adaptive adversary + induced self-DoS (first results)

The highest-research-value milestone. Two experiments.


> **Correction found 2026-10-12 (affects every attacker-side count in this file's first
> run and in M4's adaptive section):** the attacker clients connected to `localhost`, which on
> this Windows laptop costs ~2 s per new connection (IPv6 refused, then fallback). Attackers
> therefore ran at roughly 0.4 requests/s, far slower than their configured pace, so "attacker
> requests that reached the app" and "requests before enforcement" are **lower bounds** for a
> real attacker. Time-to-detect and time-to-enforce are much less affected (they depend on
> windows and gate time). Clients now use `127.0.0.1` with a browser `Host` header; the runs
> labelled "fast clients" below were redone that way.
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

---

# Adaptive red agent vs the closed loop (2026-10-12)

Script: `eval/adaptive_run.py`. Agent: `range/attacks/adaptive.py`. Data:
`docs/data/adaptive_summary.json`, `docs/data/adaptive_closed_events.jsonl`.

The red agent sees only HTTP status codes. After 2 consecutive blocks it climbs a ladder:
**mutate** the payload (8 re-encodings/case/comment mutators), **rotate** its identity (new
visitor cookie, new cookie jar), **slow** down (double the delay, cap 20 s). It also *learns*
the rate limit (requests that got through before the first 429) and then rotates before hitting
it. Budget 260 requests, local range only. Same agent, same seed in both arms. Arm 1 = CRS
alone; arm 2 = CRS + the autonomous controller (`controller/loop.py`, nobody touching it), with
benign Playwright journeys and corpus replay running throughout (130k and 576k benign requests).
Single run per cell; the agent is randomised only through its pacing jitter.

| goal | arm | requests that reached the app | attacker objective | identities used | observer flagged |
|---|---|---|---|---|---|
| credential stuffing | CRS only | 78 / 78 | **3 of 3 valid logins harvested** (351 s) | 1 | 0 |
| | closed loop | 56 / 78 (22 limited by the AEGIS rate rule) | **3 of 3 valid logins harvested** (580 s) | 8 | 8 of 8 (7 with the right technique) |
| SQLi | CRS only | 240 / 260 (20 blocked by CRS) | not met | 4 | 0 |
| | closed loop | 42 / 260 (200 AEGIS, 18 CRS) | not met | 79 | 41 of 78 |
| command injection | CRS only | 206 / 260 (54 by CRS) | no sink to exploit | 3 | 0 |
| | closed loop | 17 / 260 (197 AEGIS, 46 CRS) | no sink to exploit | 40 | 32 of 40 |

"Reached the app" means not blocked; it does **not** mean the exploit worked. The SQLi
objective (authentication bypass) was never met in *either* arm, even with no AEGIS rule, so
for SQLi this experiment measures evasion, not exploitation, and cannot say AEGIS prevented a
compromise. Command injection has no sink in Juice Shop.

## What this shows

* **Signature rules held against payload mutation and identity rotation.** The rule synthesised
  for the first identity kept blocking the agent's re-encoded payloads and its 78 fresh identities
  (SQLi) / 39 (command injection), because the rule matches the payload, not the actor, and
  survived the mutation gate. Requests reaching the app fell from 92 % to 16 % (SQLi) and from
  79 % to 7 % (command injection). Time from first detection to enforcing rule: ~110 s (SQLi)
  and ~65 s (command injection) — an attacker with this budget gets through anything sent before
  that.
* **A rate limit does not stop an adaptive credential-stuffing attacker. Negative result.** The
  controller detected the attacker within ~25 s and enforced a rate rule ~82 s after it started,
  but the agent learned the quota (12), rotated identity 7 times and slowed down, and still
  harvested all three valid logins. The defence cost it 22 blocked requests and ~65 % more time.
  Per-identity limits cannot beat an attacker whose identifier is free to rotate; this is the
  "identifier rotation" gap named in M1, now measured. Stopping it needs actor linkage beyond a
  cookie (IP/ASN/TLS fingerprint on a real deployment, which this single-host range cannot
  provide) or a non-per-actor control such as a global login cap, with its own cost to real users.
* **Attribution under rotation is partial.** When the agent churned identities fast (SQLi: 78
  rotations), the observer flagged 41 of 78: identities that never accumulated enough requests
  went unflagged. They were still blocked, because the rule was already enforcing.
* **Bypass detection fired once** (`rule_bypassed`: 3 of 8 evidence requests of a
  command-injection identity reached the app while `aegis-cmdi-1` was enforcing). It triggered
  re-synthesis, which produced no new rule (the templates are exhausted for that class), so this
  is a detection of the gap, not a repair.

## Safety under a live adaptive attacker (the self-DoS question)

* Benign requests blocked by an AEGIS rule: CRS arm **0** of 130,438; closed-loop arm **14 of
  576,471 (0.0024 %)**, worst 60-second window 0.042 %.
* **All 14 are one distinct request replayed from the corpus**: a real user's strong password
  `7ggq|;]3,p'#` on `POST /rest/user/login`, blocked by `aegis-sqli-3` (an apostrophe followed by
  `#` looks like a quote-then-comment). The gate had measured this rule at 0.0045 % FP on the
  443k corpus, under its 0.01 % budget, and the rule passed shadow and canary because that
  request did not occur in their windows. **The budget was respected and a real user would
  still be locked out of login for as long as the rule enforces.** A percentage budget cannot
  express "never a particular user"; the spec's "zero benign requests broken" is not met for
  `aegis-sqli-3`. The earlier E2E run (44k benign requests) happened not to sample it.
* The attacker did not cause this: the harm comes from the rule's own false-positive edge, present as soon as the rule enforces.
  Journeys broken by the defence: 3.5 % in the CRS arm (51/1452), 4.4 % in the closed-loop arm
  (174/3981). I have not separated CRS from AEGIS as the cause of the difference; AEGIS blocked
  only the 14 requests above.

## Caveats

* One agent, one ladder, one seed, one run. The agent is simple on purpose and does not adapt
  its *strategy*, only its parameters; a smarter one (e.g. one that probes for the rule's
  boundary) would likely do better. These numbers are a floor on attacker capability.
* The controller took the same stage windows as in `E2E-RESULTS.md` (20 s shadow + 30 s canary).
* Slow-and-low was part of the ladder (pace doubled up to a 20 s cap). The stuffing run slowed five times (to ~16 s between attempts) and still harvested all three logins, but a stuffing attacker that starts slow instead of being forced there is the M1 evasion and was not run here.


---

# Adaptive attacker at real speed, closed loop vs CRS alone (2026-10-15)

Supersedes the slowed-client numbers above. Same red agent (`range/attacks/adaptive.py`: mutate,
rotate identity, slow down up to 5 s, learn the rate quota), now connecting by `127.0.0.1`, with a
400-request budget and a ~500-pair guess list for stuffing, run against (a) CRS alone and (b) CRS +
the autonomous controller (signed manifest and admin token on, benign Playwright journeys and corpus
replay at 8 req/s throughout). **One run per cell, same seed in both arms; no confidence intervals.**
Data: `docs/data/rep/adaptive_*.json`.

| goal | arm | requests reaching the app | requests blocked by an AEGIS rule | identities used | valid logins harvested |
|---|---|---|---|---|---|
| credential stuffing | CRS only | 400 / 400 | 0 | 1 | **2** |
| | closed loop | 257 / 400 | 143 | 40 | **0** |
| SQLi | CRS only | 380 / 400 (20 blocked by CRS) | 0 | 4 | n/a (never met) |
| | closed loop | 25 / 400 | 355 (+20 by CRS) | 63 | n/a (never met) |
| command injection | CRS only | 323 / 400 (77 by CRS) | 0 | 3 | n/a (no sink) |
| | closed loop | 40 / 400 | 293 (+67 by CRS) | 59 | n/a (no sink) |

* The observer flagged 40/40 (stuffing), 63/63 (SQLi) and 48/58 (command injection) of the attacker's
  identities. The first AEGIS block came at request 26, 46 and 32 of 400, i.e. within roughly the
  first 10 % of the attack: the rule lands during a persistent campaign.
* **This reverses the earlier negative result for credential stuffing, with caveats.** With a
  persistent, real-speed attacker the loop denied the credential harvest in this run (0 valid logins
  vs 2 with CRS alone), after the attacker had rotated identity 39 times. But this is one run; the
  outcome could differ with another guess order; the stuffing rate limit still only throttles; and a
  *short* attack still beats the loop: in an earlier 78-guess variant the attacker finished in 44 s,
  before any rule existed, in both arms.
* Time to protection is the limit: about 60-160 s from first detection (`E2E-RESULTS.md`). Anything
  the attacker can finish in that window is unmitigated by construction.
* **Safety under a live adaptive attacker:** 0 benign requests blocked by an AEGIS rule across about
  300,000 benign requests in the six runs (the earlier lock-out of one user's password does not recur
  after the SQLi template fix and the hard-negatives gate stage).
* Account-keyed rate rules were exercised: they were proposed once the controller saw a second
  identity but rejected by the gate (benign accounts that would have been limited), so the
  identity-keyed rule did the work.
