# M2 — Live gate stages, hot reload, per-rule modes

Completes the six-stage validation gate. Stages 1, 2, 4 run offline
(`gate/gate.py`), stage 3 is `gate/live_validate.py`; **stage 5 (shadow) and
stage 6 (canary with automatic rollback)** are `gate/live_stages.py`, running on
the live gateway with hot-reloadable rules.

## Gateway changes (`gateway/rules.go`, `gateway/main.go`)
- **Per-rule modes** `off | shadow | canary(x%) | enforce`. AEGIS SecRules compile
  to `pass,log` + tag `aegis-rule:<id>`; the gateway decides per rule whether a
  match blocks. Canary membership is a stable hash of the actor.
- **Hot reload** from a manifest (`rules/active/manifest.json`): a new immutable
  rule set is built in the background and swapped atomically; a failed build keeps
  the old set. **Rollback = mode off**, via a loopback admin API (`/stats`,
  `/mode`, `/rollback`).
- **Counters** per rule (matches / blocks / shadow) and per-slice stats
  (canary vs control: requests, AEGIS blocks, app 5xx, p50/p99 latency).
- **Rule guard:** the gateway re-validates manifest rule text on its own: exactly
  `SecRule <vars> "<op>" "<actions>"`, and every action on an allowlist
  (`id, phase, pass, log, msg, tag, t, chain`).
- AEGIS rules load **before** CRS. Coraza stops evaluating once CRS's blocking
  rule interrupts, so a rule loaded after CRS never sees requests CRS already
  blocked and shadow counts silently under-count.

## Stage 5 — shadow
Rule loaded in `shadow`; realistic traffic for a window (here 45 s, ~55 req/s of
**real requests sampled from the 443k benign corpus** plus a fresh attack
campaign every 10 s). Checks, neither needing ground truth:
1. **Suspected false positives** — matches on actors the M1 observer does *not*
   flag as attackers. Budget = the FP budget applied to that traffic (zero at
   these sample sizes).
2. **Live-vs-offline agreement** — the logged requests are replayed through
   `bin/replay.exe` with the same rule; the live match count must equal the
   prediction. This catches the live engine drifting from the one the gate
   validated against.

## Stage 6 — canary with auto-rollback
Rule blocks only the canary slice (25% of actors); everyone else stays in shadow
and serves as control. Every 2 s the monitor rolls back (mode `off`) on any of:
suspected-FP blocks (>=3 and >0.1% of the slice's non-campaign requests), app 5xx
regression vs control (>2 points), or p99 latency regression (>3x + 20 ms).
Promotion to `enforce` is refused in code unless **both** live stages passed.

## Results (`eval/run_live_stages.py`, one range boot)

| Experiment | Stage | Outcome | Numbers |
|---|---|---|---|
| **E1** good rule `aegis-sqli-3` | shadow | PASS | 2,460 live requests; suspected FPs **0 / 2,440**; live matches **16 = replay-predicted 16** |
| | canary 60 s @25% | PASS -> **promoted** | rule blocked 8 attack / 0 benign requests |
| **E2** overfit rule (any `'` in args) via the full pipeline | shadow | **FAIL** | suspected FPs **16 / 2,447** (allowed 0), e.g. `?q=Bobby Tables' review`; live 32 = replay 32 |
| **E3** fault injection: same overfit rule forced straight into canary | canary | **ROLLED BACK after 53.8 s** | rollback call **0.02 s**; **4 benign requests blocked** of 2,301 in the window (0.17%) before rollback |

E3 is a chaos test of the safety net, not a promotion path: it bypasses every
earlier stage on purpose to show stage 6 works on its own.

## Hot-reload stress (`eval/hotreload_stress.py`)
8 keep-alive client threads, **48 manifest reloads** in 40 s (rules added, modes
cycled shadow/canary/enforce/off, rate and signature rules):

| | |
|---|---|
| Requests | 1,382 |
| **Failed / dropped** | **0** |
| Reload latency | p50 506 ms, max 780 ms (includes the gateway's 500 ms poll interval) |
| Client latency | p50 263 ms, p99 308 ms, max 357 ms (no spike during reloads; dominated by Juice Shop on this laptop) |
| **Corrupt manifest** (a rule smuggling `allow`) | **refused**; gateway kept its previous rules; SQLi probe still blocked |

## What this found (bugs fixed along the way)
- **Windows rename race:** replacing the manifest fails with "Access denied" if
  the other process has it open. Both writers (Python and the gateway admin API)
  now retry. Found by the stress test, not by inspection.
- **Rule ordering** (above) — would have made shadow counts wrong.
- **IR compiler injection holes** found while attacking my own boundary: a
  newline in a model-written `value` could start a second directive; a trailing
  backslash escaped the closing quote; the model's free-text `description` flowed
  into the rule's `msg`. All closed (`ir/compile.py`), covered by tests.

## Caveats (read these before quoting a number)
- **E3 detection took 53.8 s and cost 4 legitimate requests.** The overfit rule
  hits ~0.6% of benign requests, and only 25% of actors are in the canary, so
  evidence accrues slowly. A lower threshold detects sooner but risks rolling
  back good rules; this trade-off is real, not tuned away.
- **M1 is used as the false-positive oracle** ("actors the observer does not flag").
  If the observer wrongly flags a benign actor, that actor's false positives are
  hidden; if it misses an attacker, that attacker's matches count as suspected
  false positives (conservative). M1's measured false-flag rate is low, not zero.
- Traffic is replayed corpus requests spread over synthetic users, not real
  sessions; 60 req/s on one laptop; windows are 45-60 s, not minutes.
- The canary monitor supports **one canary rule at a time**.
- The admin API is loopback-only and unauthenticated; the manifest is not signed
  (PRD section 9, rule-store tampering, is open).
- E1-E3 attack traffic used scanner user-agents; AEGIS rules evaluate before CRS
  and are attributed independently, so the UA does not affect these decisions
  (it did confound the CRS-only baseline, which has been re-measured).
