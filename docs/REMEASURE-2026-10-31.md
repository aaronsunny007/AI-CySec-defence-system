# Re-measurement after the security review, 2026-10-31

The review changed two things that can affect the research numbers: the observer's SQL-injection pattern
(bounded quantifiers) and rule template 3 (one added alternative). This document re-measures the lab on
the final code, with Juice Shop v20.2.0 (the original version) on Linux, and says plainly what it can and cannot
tell you.

**What differs from the original runs, and so limits comparison:** the 443,507-request benign corpus was not
available. A new 15,396-request corpus (8,568 distinct requests, 1,394 visitors) was generated with the lab's own
`eval/diverse_capture.py` through the gateway in detect mode. The machine is a 4-core cloud sandbox, not the
original laptop, and Juice Shop ran about 40 requests a second there. One replicate, not five. So: the
**comparisons between old and new code below are exact** (same data through both); the **comparisons with the
numbers in `E2E-RESULTS.md` are only indicative**.

Raw data: `docs/data/review-remeasure/` (`compare.json`, `e2e_summary.json`, `e2e_events_decisions.jsonl`).
Scripts: `eval/review_compare.py`, `eval/e2e_live.py` (both run unchanged apart from Linux portability).

## 1. Did the review change detection or false positives? No.

`python eval/review_compare.py` loads the pre-review code from git (`c47c8da`) and runs old and new through
identical data.

| | pre-review | after review |
|---|---|---|
| Observer signatures, benign requests matched (sqli / xss / traversal / cmdi / ssrf) | 66 / 0 / 20 / 64 / 0 | 66 / 0 / 20 / 64 / 0 |
| Observer signatures, attack requests matched (590 payloads and their mutations) | 42 / 30 / 56 / 20 / 54 | 42 / 30 / 56 / 20 / 54 |
| Requests matched by exactly one version, any family | | **0** |
| Benign actors the full detector flags (corpus) | 16 of 1,386 | 16 of 1,386, the same actors |
| Template 3 through Coraza: benign matched | 0 of 15,396 | 0 of 15,396 |
| Template 3: SQLi attack requests matched | 60 of 101 | 60 of 101 |

On the closed-loop run's own log (48,131 requests, 1,390 benign actors judged, 112 attacker actors) the two
detectors also agree exactly: the same 242 benign technique-hits (188 id-walk, 32 enumeration, 10 SQLi, 8 command
injection, 4 traversal) and the same 112 of 112 attacker actors flagged.

The comparison data contains no time-based payloads (`SLEEP(5)`), so it does not exercise the one thing template 3
gained; that is covered by `tests/test_sqli_templates.py` (blocked) and its ten ordinary-text cases (not blocked).

## 2. The closed loop, one replicate (`eval/e2e_live.py`, 939 s)

Juice Shop behind the gateway in enforce mode, benign traffic throughout (3 real-browser journey workers, 25 requests
a second of replayed corpus, persistent varied sessions), controller as a separate process, shadow 20 s and canary
30 s as in the original. Nobody touches anything after start.

| | command injection | credential stuffing | SQLi |
|---|---|---|---|
| rule enforcing after onset, first exposure | 56 s | 74 s | 61 s |
| same, `E2E-RESULTS.md` | 83 s | 80 s | 130 s |
| rule enforcing, rule store wiped (cold repeat) | 58 s (reused) | 136 s | 185 s (reused) |

**All six phases enforced a rule with no human involved.** The first-exposure times are in the documented range or
faster; the SQLi gap is mostly the offline gate, which replays 15 thousand requests here instead of 443 thousand
(0.7 s against 64 s). The cold stuffing and SQLi repeats were slower than the first exposure here, which is not what
the original reported for memory; with one replicate I cannot tell noise from a real difference.

**The safety claim held:**

| | this run | `E2E-RESULTS.md` |
|---|---|---|
| benign requests | 46,823 | 44,093 |
| blocked by an AEGIS rule | **0** | 0 |
| blocked by CRS | 5,204 (11.1%) | 3,385 (7.7%) |
| Playwright journeys broken by the defence | 22 of 515, all CRS | 22 of 460, all CRS |

## 3. What did not reproduce: false triggers

The controller flagged **242 benign actors** as campaigns (188 id-walk, 32 enumeration, 10 SQLi, 8 command
injection, 4 traversal). The documentation reports 7 to 10 per run after the id-walk fix. Facts:

* The pre-review and post-review detectors flag **exactly the same 242**, so this is not a regression from the
  review.
* All 242 are on benign lab visitors (`ident: vid`), so the identity-rotation pooling is not involved.
* The id-walk ones have the shape of the replay driver's pseudo-users, not of a browser journey: the flagged actors
  I inspected made 60 to 70 requests spread over about 15 minutes, and the example I read fetched reviews of more
  than ten different products, against a measured ceiling of 5 (`data/idor_ceilings.json`, built from the original
  corpora). I did not trace all 188 back to the driver.
* My best explanation is the traffic mix: the regenerated corpus is review-heavy, so random sampling produces more
  id-walking pseudo-users. I did not prove it, and it is the same unexplained pseudo-user effect the notes on PR #2
  already record.

What the controller did with them (468 candidate rules were tried, 453 rejected, 15 passed the offline gate):

* The id-walk (354) and enumeration (72) candidates were all rejected at the `attack_actor` stage: such a rate limit
  would not have limited the flagged actor, so there was nothing to enforce. That is the false trigger fizzling out,
  not the gate catching a harmful rule.
* 27 credential-stuffing candidates were rejected at `benign_accounts`: the rate gate refused a limit that would
  have throttled legitimate accounts. That is the gate doing its job.
* One kind of false trigger did reach enforcement: **`aegis-traversal-1` was created from traversal false triggers
  on benign visitors (4 and 14 requests each), passed every stage on live traffic, and was enforced (twice, once
  after the cold-repeat wipe)**. It blocked no benign request in this run, so the gate's verdict was correct for
  the traffic seen, but a rule born from a false alarm is now live. That is worth knowing; it is not a safety
  failure here.

Two `live_error` events (`aegis-traversal-1`, HTTP 404 from the admin API) mean the controller asked about a rule
that was no longer in the store; the code treats that as an operational error and switches the rule off, not as a
gate verdict. I believe it follows the cold-repeat wipe (which clears the store) but did not confirm the timing.

## What this does and does not establish

* The review's two behaviour-affecting changes did not move detection or false positives on 15,396 benign and 590
  attack requests, nor on the closed-loop log. That is a strong, direct comparison.
* The central safety result (AEGIS rules blocked no benign request; the journeys broken were CRS's) reproduced on a
  different machine, different corpus, and the final code.
* The headline timings are in the same range. They are not a replication: one replicate, a 29-times-smaller corpus.
* The false-trigger count did not reproduce, for reasons I believe, but cannot show, lie in the traffic mix.
* DVWA, the second app, the adaptive attacker and the 443k-request FP figure were not re-run.
