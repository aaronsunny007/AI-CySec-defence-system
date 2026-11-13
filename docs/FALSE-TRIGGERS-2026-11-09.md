# The 242 false triggers were the test driver, 2026-11-09

`REMEASURE-2026-10-31.md` reported 242 benign actors flagged as campaigns where earlier notes had 7 to 10, and could
not explain it. This note explains it, fixes the cause, and re-measures. Everything here comes from this repo's own
scripts; the data is in `docs/data/session-replay/`.

## 1. Cause: the replay driver, not the observer

`eval/traffic.py` (`ReplayDriver`) sent random requests from a corpus under 200 made-up visitor ids. A visitor id that
gets a random mix of everyone's requests looks like an id-walker, an enumerator and a scanner at once. That is not
how any real visitor behaves.

`python eval/driver_artefact_check.py` runs the same detector over the same requests (`benign_diverse_detect.jsonl`,
30,121 requests) two ways:

| How actors are formed | Actors with 3+ requests | Flagged as campaigns |
|---|---|---|
| Real visitor sessions, as recorded | 2,681 | **34 (1.3%)**: 28 cmdi, 6 sqli |
| Replay driver's pseudo-users (200 users, 25 req/s, three seeds) | 200 | **200, 200, 200** |

So the detector flagged almost every pseudo-user, and about one in 80 real visitors. The 242 measured the driver.

## 2. Fix

The driver now replays whole real visitors, in recorded order, each under a fresh id, whenever the corpus records
`session` (`load_sessions`; test: `tests/test_replay_sessions.py`). The live harnesses (`eval/e2e_live.py`,
`eval/adaptive_run.py`) use `benign_diverse_detect.jsonl` for this. `AEGIS_LEGACY_REPLAY=1` restores the old driver for
comparison. The big 443k-request corpus has no session field, so it still works only in the old mode.

## 3. Live re-measurement (Juice Shop, enforce mode, `eval/e2e_live.py --no-cold`, 3 replicates)

| | rep 1 | rep 2 | rep 3 |
|---|---|---|---|
| benign requests | 22,249 | 21,766 | 22,140 |
| blocked by an AEGIS rule | **0** | **0** | **0** |
| blocked by CRS | 1,841 | 1,808 | 1,834 |
| false triggers (benign actors flagged) | 18 | 18 | 18 |
| cmdi / stuffing / SQLi enforced after onset | 56.5 / 75.6 / 78.3 s | 58.5 / 74.6 / 77.4 s | 56.7 / 74.9 / 77.4 s |
| controller errors, log gaps over 60 s, share of campaigns reaching an LLM | 0, none, 0 | 0, none, 0 | 0, none, 0 |

False triggers fall from 242 to 18 per run. All three classes were enforced with no human involved in every run, and
no AEGIS rule blocked a benign request.

## 4. What this does not show

* **18 is not zero, and not independent.** The stored samples (the summary keeps five per run) are all cmdi in rep 1 and four cmdi plus one traversal in reps 2 and 3. The counts are replays of a finite set of recorded visitors under fresh ids, so a few
  oddly-shaped real visitors are counted many times. I did not count the distinct visitors behind the 18. The same
  pattern appears offline: the 34 flagged real sessions are mostly cmdi. That is a genuine detector weakness on
  benign input, now visible because the driver no longer hides it.
* **A rule born from a false alarm is still enforced.** `aegis-traversal-1` was created from traversal triggers on
  benign actors (13 and 4 requests), passed every gate stage, and was enforced in all three runs, as in the earlier
  re-measurement. It blocked no benign request here. The gate approved it because it is harmless on the traffic
  seen, not because the trigger was right.
* **No browser journeys.** Playwright is not installed on this machine, so `journeys` is 0 in every run. The earlier
  "22 of 515 journeys broken, all CRS" is not re-measured here.
* **Compressed time.** Replayed visitors run at the driver's rate (about 25 req/s over all workers), not at their
  original pace.
* **Smaller than the original runs.** About 22,000 benign requests per run and three replicates, not 443,507 requests
  and five. No cold-repeat phase (`--no-cold`). One machine, one app.
* **Not re-run:** the 443k-request false-positive figure, DVWA, the second app, and the adaptive attacker. The stored
  numbers for those were produced with the old driver and are still the published ones.
* A short unrelated offline check (`driver_artefact_check.py`) ran for about 40 seconds at the start of replicate 2.
* `bin/gateway.exe` was stale (built before the `-range` flag existed) and was rebuilt from source before these runs.

## 5. Follow-up: tightening the cmdi and sqli signatures (not yet re-run live)

What the 34 flagged real sessions had in common, from `observer/detector.py` run over `benign_diverse_detect.jsonl`:

* **Random passwords.** A password containing a backtick, `$(`, `'#` or `)#` matched once at registration and once at
  login (same string, two requests), which satisfies `injection_min = 2` on its own. Most of the 34 (I read the first dozen cmdi cases and all six sqli; I did not tabulate every one).
* **Deliberate hard negatives** in free text: `$(10) off`, `` `code` ``, `' and '`, `select * from happiness`.

Changes (`SIGS` in `observer/detector.py` and the copy in `gateway/redact.go`, kept identical by
`tests/test_redaction_parity.py`):

* cmdi: `$(` and backticks must be followed by a known command word (`sleep id whoami cat ls ping uname curl wget nc echo nslookup bash sh python perl env pwd hostname`), optionally behind a short path.
* sqli: a comment marker (`--`, `#`) after a quote or `)` must end a token; `or`/`and` after a quote counts only when SQL follows (a quote, `1=1`, `a=b`, `like`, `f(`, `not/true/false/null`).

Measured by re-scoring stored logs with the new signatures (`python observer/detector.py --log ... --eval`; no new traffic):

| Log | Benign actors flagged, before | after | Attack actors detected, before and after |
|---|---|---|---|
| Real visitor sessions (`driver_artefact_check.py`, 2,681 actors) | 34 | **2** | n/a |
| `e2e.jsonl` (a stored live Juice Shop run) | 18 | **2** | 54/54, p50 0.8 s, unchanged |
| `dvwa.jsonl` | 2 | **0** | 44/44, unchanged |
| `app2.jsonl` (second app) | 56 | **23** | 54/54, unchanged |
| `m1_episode`, `adaptive_closed`, `adaptive_crs` | 0, 6, 1 | 0, 6, 1 | 17/18, 35/36, 3/3, unchanged (same single miss each) |

Caveats:

* **Not a live re-run.** These re-score logs recorded earlier; the controller, gate and enforcement path did not run. The
  live three-replicate measurement in section 3 has not been repeated with the new signatures.
* **Recall cost, not measured outside the stored logs.** The observer no longer sees a shell substitution whose command is
  not in the list (`$(nmap ...)`), or an `or`/`and` injection followed by something other than the shapes above. CRS and the
  gateway still inspect those requests; only the campaign detector is blinder. The staged campaigns use `| whoami`, `$(sleep 3)`,
  `` `id` ``, `&& ping` and the SQLi payloads in `data/attack_corpus/payloads.json`, all still matched. Payloads written after
  these signatures were chosen would be a fair test; I have not run one.
* **The remaining flags are the generator's own hard negatives.** Both remaining Juice Shop-corpus sessions typed two of
  them (`select * from happiness`, `' and '`). The generator inserts them at about 1% of tokens, so the residual rate says
  something about the generator, not about real shoppers.
* **The e2e leftover traversal flag (13 requests) is unexplained.** It matches the actor behind `aegis-traversal-1`. The
  traversal signature was not changed, and the same sessions replayed offline produce no traversal flag, so I could not
  reproduce its cause offline. The gate still has no defence against a rule born from a false alarm.
* `tests/test_aegis_cli.py` used `' or x` as its "attack-like" request; that no longer matches, so the fixture is now
  `' or 1=1`.
