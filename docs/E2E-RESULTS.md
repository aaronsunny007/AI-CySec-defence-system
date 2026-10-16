# End-to-end autonomous loop — results

Date: 2026-10-12. Branch `autoresume`. Raw data: `docs/data/e2e_summary.json`,
`docs/data/e2e_events.jsonl` (the controller's own event log). Script: `eval/e2e_live.py`.


> **Correction found 2026-10-12 (affects every attacker-side count in this file's first
> run and in M4's adaptive section):** the attacker clients connected to `localhost`, which on
> this Windows laptop costs ~2 s per new connection (IPv6 refused, then fallback). Attackers
> therefore ran at roughly 0.4 requests/s, far slower than their configured pace, so "attacker
> requests that reached the app" and "requests before enforcement" are **lower bounds** for a
> real attacker. Time-to-detect and time-to-enforce are much less affected (they depend on
> windows and gate time). Clients now use `127.0.0.1` with a browser `Host` header; the runs
> labelled "fast clients" below were redone that way.
## What was tested

One range boot (Juice Shop behind the Go/Coraza gateway in **enforce** mode, OWASP CRS on).
Benign traffic ran the whole time: 3 Playwright journey workers (real browsers) plus 40 req/s of
replayed corpus requests spread over 200 synthetic users. The controller (`controller/loop.py`)
ran as a **separate process** that only tails the gateway log. For each class a persistent
attacker (a fresh identity every few seconds, spoofed browser User-Agent) started, and nothing
else was done by anyone: no human action, no script poking the controller.

The controller did the whole loop itself: detect (observer) → mitigate (memory reuse, then
templates) → offline gate (benign replay of all 443,507 requests, campaign replay, 54-mutant
test) or, for rate rules, a rate gate against non-campaign actors → hot-load in **shadow**
(20 s) → **canary** at 25 % (30 s, auto-rollback armed) → **enforce**. Promotion is refused
unless both live stages pass. Window lengths (20 s / 30 s) are my choice for experiment speed;
a production deployment would use longer ones, which would lengthen every "time to enforce"
below by roughly the same amount.

Classes: **command injection** and **credential stuffing** (the two CRS does not stop), plus
**SQLi** as the spec's literal acceptance case. Then each class was repeated with the rule store
**wiped** ("cold repeat") to test what memory buys.

Ground truth (the gateway's range-only `gt_label`) is used only to score; the controller never
reads it (a unit test asserts this).

## Headline

| | command injection | credential stuffing | SQLi |
|---|---|---|---|
| campaign onset → detected | 8.1 s | 23.8 s | 8.7 s |
| onset → **rule enforcing, no human** | **82.6 s** | **80.4 s** | **130.2 s** |
| synthesis + offline gate | 18.1 s | 0.07 s (rate gate) | 63.8 s |
| attacker requests logged before enforcement | 31 (16 blocked by CRS) | 24 (0 blocked) | 48 (38 blocked by CRS) |
| attacker requests logged after enforcement | 25: 19 by the AEGIS rule, 4 by CRS, 2 reached the app | 24: 10 limited by the AEGIS rule, 14 reached the app | 22: 18 by the AEGIS rule, 4 reached the app |
| attacker objective | n/a (no OS-command sink in Juice Shop) | valid credentials found in 2 attacker runs before enforcement, **1 after** | not met in any run |

"Reached the app" counts **every** request carrying the attacker's label, including the
innocuous recon requests each campaign starts with (`GET /`, product pages), so it overstates
how many *payloads* got through.

**Benign side, whole run (44,093 benign requests, 460 Playwright journeys):**

* blocked by an AEGIS rule: **0** of 44,093 in this run. **Do not read that as "never":** the longer adaptive run (576k benign requests) showed `aegis-sqli-3` blocking one real user's password (`...'#`) 14 times; see `M4-RESULTS.md`.
* blocked by CRS: 3,385 (7.7 %); 22 of 460 journeys broken, all by CRS (AEGIS blocked no benign
  request, so none can be AEGIS's). This is the CRS baseline problem already in `BASELINE.md`,
  not something AEGIS added or fixed.
* 93 journeys failed in total: 22 by the defence (CRS), 41 app errors, 30 script errors.

**Spec acceptance, as literally worded** ("live SQLi campaign, no human: detects, generates
candidates, gate validates one, it blocks the campaign *and* the mutation set, breaks zero
benign requests, end to end"): met in this run. Honest context: CRS already blocked most SQLi
(38 of 48 pre-enforcement requests), so the new rule's value on SQLi is the variants CRS
misses, not the headline attack. The value is clearest on command injection and stuffing.

## Second exposure (memory)

With the rule store wiped but memory kept, the same campaign came back from a new identity:

| | command injection | credential stuffing | SQLi |
|---|---|---|---|
| synthesis + offline gate, first exposure | 18.1 s | 0.07 s | 63.8 s |
| same step, second exposure (memory) | 0.010 s (**reused**) | 0.013 s (reused) | 0.003 s (reused) |
| onset → enforcing, first exposure | 82.6 s | 80.4 s | 130.2 s |
| onset → enforcing, cold repeat | 69.9 s | 134.5 s | 231.7 s |

**The ≥10× repeat speed-up holds for the synthesis step (hundreds to tens of thousands of ×)
but NOT for end-to-end time to enforcement.** A reused rule still goes through shadow and canary
(~57 s here), because I did not give memory a path around the live stages (the rule had passed
them before, but the world may have changed, and invariant 5 says no fast paths). Cold-repeat
times were *worse* for stuffing and SQLi because of head-of-line blocking, see below. The one
repeat where a rule was still enforcing (the normal case without a wipe) is the strong result:
every later attacker identity of an already-handled campaign was recognised in 3–30 ms
(`already_enforcing`, 26 times) and its requests were blocked from the first one.

## What went wrong (and what I did about it)

1. **First live run exposed a real bug in my own templates.** All three command-injection
   templates blocked 0 % of `; cat /etc/passwd`: ModSecurity's `cmdLine` transform *deletes* the
   `;` before the regex runs. It was invisible in earlier offline experiments because command
   injection had never been pushed through the gate on real captured evidence. Fixed (match raw
   decoded text, tolerate `/**/` and double encoding); gate: 100 % of campaign, 100 % of 54
   mutants, 0.0007 % FP on the 443k corpus. The traversal templates needed double URL-decoding
   for the same reason.
2. **Canary 5xx comparison false-alarmed on noise.** The original rule (canary 5xx rate > control
   + 2 points) fired on 11.4 % vs 9.1 % at ~150 requests per slice. I added a significance
   requirement (z ≥ 3). That is not enough on its own: in the final run it still rolled back the
   credential-stuffing rule once (9.1 % vs 4.6 %, z = 3.0) — the two slices contain different
   actors, traffic is clustered, and the check is repeated every 2 s. A rate rule that only
   limits the attacker cannot plausibly cause app 5xx, so I judge this a false alarm, in the safe
   direction, but it left the stuffing rule **off at the end of the run**. Since then the
   controller retries a latency/5xx rollback **once** (a suspected-false-positive rollback stays
   final). This retry is new and **not yet re-run live**.
3. **Operational error treated as a gate verdict.** My experiment harness wiped the rule store
   while a pipeline was in flight; the admin API answered 404 and the controller blacklisted the
   rule, so a later command-injection repeat found no usable rule. A crash or a vanished rule is
   now logged and the rule switched off, but not blacklisted (unit-tested; not re-run live).
4. **Campaign budget exhausted by the attacker.** In an earlier run every new attacker identity
   counted against the 30 campaigns/hour budget, so an attacker rotating identities starved real
   work (SQLi was never handled). The budget now counts only campaigns that need new synthesis.
5. **A laptop suspend invalidated one full run** (65-minute gap with no requests in the gateway
   log). The harness now reports gaps; the run reported here has none.

## Controller behaviour and limits

* Detections: 158; 66 on real attacker identities. **92 false triggers, all `idor_bola`, all on
  my synthetic replay users** (random corpus requests assigned to 200 pseudo-users, so each one
  "walks" many product ids — not a realistic user). **0 of the Playwright journey actors were
  flagged.** None of the 92 produced a rule: the rate gate rejected all 26 candidates because
  the "attacker" would not have been limited. 104 repeat triggers were absorbed by the cooldown.
  So the observer is not shown to be wrong on realistic users here, but the live false-trigger
  rate on real traffic is only as good as the 460 journeys.
* **One live pipeline at a time**, ~57 s each. Campaigns queue behind it (detection-to-action
  delays of 76 s and 172 s in the cold repeats). Parallel pipelines would need several canary
  slices; not built.
* 0 % of campaigns reached an LLM (not enabled in this run; templates + memory sufficed for
  these three classes).
* `scan` is detected but has no mitigation template; the controller reports and ignores it.
* The attacker was one scripted campaign repeated, not an adaptive adversary (see M4 notes in
  `M4-RESULTS.md` for the adaptive-agent experiment, run separately).
* Rate limit **throttles**, it does not prevent: in the first exposure the attacker still found
  valid credentials in 1 run after enforcement.
* Single run per cell; no confidence intervals. Times depend on the stage windows chosen.
* Not exercised here: signed manifest/admin token (`HARDENING.md`), the LLM path, slow-and-low
  or identity-rotation evasion, a second target app.

---

# Run 2 (2026-10-12): all fixes in, **signed manifest and admin token ON**

Same experiment (`eval/e2e_live.py`), after the fixes listed above plus the SQLi template fix,
the live-FP-judge fix and the account-keyed rate rule. The gateway log shows
`rule store: signed manifest true, admin token true`; every hot load, shadow/canary mode change
and rollback in the run went through the signed manifest and the bearer-token admin API.
Data: `docs/data/e2e_signed_summary.json`, `docs/data/e2e_signed_events.jsonl`. No log gaps.

| | command injection | credential stuffing | SQLi |
|---|---|---|---|
| detected after onset | 7.9 s | 16.0 s | 7.4 s |
| **rule enforcing after onset** | **70.2 s** | **71.7 s** | **82.6 s** |
| synthesis + offline gate | 6.9 s | 0.014 s | 18.1 s |
| attacker requests before enforcement (AEGIS-blocked / CRS-blocked / reached app) | 29 (10 / 10 / 9) | 29 (0 / 0 / 29) | 32 (0 / 24 / 8) |
| after enforcement | 27 (20 / 4 / 3) | 19 (10 / 0 / 9) | 18 (16 / 0 / 2) |
| attacker runs that found a valid login (before / after) | n/a | 2 / 1 | n/a |

(Pre-enforcement AEGIS blocks on command injection are the canary slice: 25 % of identities
are blocked while the rule is being tested.)

* **Benign:** 85,462 requests, **0 blocked by an AEGIS rule**; CRS blocked 4,548 (5.3 %); 821
  journeys, 44 broken by the defence (all CRS, since AEGIS blocked nothing).
* **Controller:** 265 detections, 193 false triggers, **all `idor_bola` on synthetic replay
  users, none on a real journey**; none produced a rule. 19 `already_enforcing` repeats absorbed
  in milliseconds.
* **Cold repeat (rule store wiped, memory kept):** command injection 63.2 s and SQLi 64.1 s,
  reused in 1.8 / 1.9 ms: 10-22 % faster than the first exposure here (63.2 vs 70.2 s; 64.1 vs 82.6 s), the saving being
  the offline gate. **Credential stuffing was NOT enforced in this phase.** Cause: the
  controller saw a second identity run the stuffing campaign, escalated to an account-keyed
  rate rule, the gate rejected both account-keyed candidates (7/103 and 1/103 *other* accounts
  would have been limited: the replayed benign logins reuse a handful of recorded accounts, so
  they hammer the same accounts), and the escalation then **refused to fall back** to the
  identity-keyed rule that had worked. The attacker found valid logins in 15 runs. This was a
  regression I introduced with the escalation; it is fixed (account-keyed first, identity-keyed
  as fallback; unit-tested) but this exact cold-repeat phase has not been re-run in the full flow.
  The adaptive-stuffing run in `M4-RESULTS.md` exercises the fixed path.
* Signing cost: none observable at this timescale; hot reloads took the same time.

Honest comparison with run 1: enforcement times are lower (70-83 s vs 80-130 s) mostly because
the command-injection and SQLi offline gates are faster (6.9 s and 18.1 s vs 18.1 s and 63.8 s):
the SQLi template change removed a benign-corpus false-positive family and the machine was less
loaded. Differences of this size between single runs should not be over-read.


---

# Replicates on two apps, real-speed attackers (2026-10-15)

This supersedes the single-run tables above for any claim about timing. Setup as in run 2 (signed
manifest and admin token ON, controller in its own process, benign load throughout), but: attackers
connect by `127.0.0.1` (the `localhost` delay is gone), the live stages ignore requests that arrived
before the rule was loaded, the SQLi template needs a real comparison after `and`/`or`, bypass
detection ignores pre-enforcement history, and the campaigns-per-hour budget is per technique. One
replicate = one range boot with the three classes in sequence (no cold repeat). Raw per-run data:
`docs/data/rep/`. Intervals are Student-t on the runs that enforced; with n = 5 and n = 3 they are
wide and should be read as rough.

### Juice Shop (signed, fast clients): 5 replicate runs

| class | enforced | detect (s) | time to enforce (s) | synthesis (s) | attacker reached app, before / after |
|---|---|---|---|---|---|
| command_injection | 5/5 | 4.0 (95% CI 1.3-6.7; range 1.0-7.1; n=5) | 84.5 (95% CI 72.4-96.5; range 74.1-99.4; n=5) | 16.3 (95% CI 8.3-24.4; range 7.4-24.2; n=5) | 49.8 / 10.6 |
| credential_stuffing | 5/5 | 39.0 (95% CI 34.6-43.4; range 33.6-42.2; n=5) | 96.6 (95% CI 91.3-101.8; range 89.7-100.9; n=5) | 0.0 (95% CI -0.0-0.1; range 0.0-0.1; n=5) | 64.6 / 20.8 |
| sqli | 5/5 | 15.6 (95% CI 9.1-22.2; range 9.4-19.9; n=5) | 137.1 (95% CI 120.3-153.9; range 125.3-158.8; n=5) | 63.0 (95% CI 43.6-82.4; range 48.9-89.8; n=5) | 34.8 / 10.4 |

benign requests 94640, blocked by an AEGIS rule: 0; live-stage rejections: 0; false triggers per run: [13, 3, 14, 5, 22]; log gaps: [[], [], [], [], []]


### BookNook (second app): 3 replicate runs

| class | enforced | detect (s) | time to enforce (s) | synthesis (s) | attacker reached app, before / after |
|---|---|---|---|---|---|
| sqli | 3/3 | 1.1 (95% CI -0.2-2.3; range 0.6-1.6; n=3) | 62.9 (95% CI 57.7-68.0; range 60.6-64.7; n=3) | 4.3 (95% CI 0.2-8.4; range 3.3-6.2; n=3) | 10.7 / 6.7 |
| command_injection | 3/3 | 1.3 (95% CI 0.6-2.0; range 1.0-1.5; n=3) | 64.0 (95% CI 59.9-68.1; range 62.4-65.7; n=3) | 2.3 (95% CI 0.1-4.4; range 1.3-3.0; n=3) | 31.3 / 7 |
| credential_stuffing | 3/3 | 1.5 (95% CI 1.2-1.8; range 1.4-1.6; n=3) | 64.1 (95% CI 62.2-66.0; range 63.2-64.6; n=3) | 0.0 (95% CI -0.0-0.1; range 0.0-0.1; n=3) | 120.3 / 48 |

benign requests 145454, blocked by an AEGIS rule: 0; live-stage rejections: 3; false triggers per run: [41, 48, 44]; log gaps: [[], [], []]


**Reading these.**

* Every class was mitigated in every replicate on **both** apps (Juice Shop 15/15, BookNook 9/9
  class-runs) with **0 benign requests blocked by an AEGIS rule** (94,640 and 145,454 benign
  requests). Time to a rule enforcing is ~60-160 s, dominated by the gate, the fixed 20 s shadow +
  30 s canary windows and the queue, not by detection (1-40 s).
* **Credential stuffing detection is slowest on Juice Shop (~39 s)** because the detector needs six
  logins inside 60 s and the attacker's first login attempts are spread by its recon steps.
* **The second app needed two fixes first.** The detector hard-coded Juice Shop's login URL (blind on
  `/api/login`), and the SQLi template flagged a benign review `'quoted' and "double"` (0.60 % of
  BookNook's corpus) until its boolean branch required a real comparison. Both were found by running
  on the second app. BookNook is my own small app (stdlib Python, simulated command sink), so this
  is evidence of some generalisation, not of generalisation to real applications.
* On BookNook the account-keyed stuffing candidate was rejected by the live stages in 3/3 runs and
  the identity-keyed rule was enforced instead.
* **Benign-corpus diversity caveat (important).** The 443,507-row Juice Shop corpus contains only
  62,162 distinct `(method, URI, body)` triples, and 58k of those are `/socket.io` polls with unique
  session ids. Excluding them there are **4,101 distinct requests**, and the 100 most common distinct
  requests make up 83 % of all rows. A false-positive rate over the raw rows is therefore dominated by
  repeats; the corpus supports "no false positives on these 4.1k request shapes", a weaker claim than
  its row count suggests. Generating more diverse benign traffic is the first thing to do before
  claiming a production-grade false-positive rate.
* False triggers per run (detections on non-attacker actors) were 3-22 on Juice Shop and 41-48 on
  BookNook, all handled by the gate and cooldown without producing a rule, but they cost controller
  time and, before the per-technique budget, starved real work.
