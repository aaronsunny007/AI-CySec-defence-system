# AUTORESUME — handoff for unattended continuation

A scheduled task reads this file every couple of hours. **Each run starts with no
memory of any conversation**, so everything it needs is here. A run does at most one
work item (or one coherent slice of it), commits to a branch, updates this file, and
stops. If nothing is actionable it exits immediately (that costs almost nothing).

Owner: Sunny Aaron. Repo: the local clone of this repository.
Spec: `CLAUDE.md`. Decisions: `docs/DECISIONS.md`. Honest status: `README.md` and the
`docs/*-RESULTS.md` files. **Auto-resume expires 2026-10-18**: after that date do nothing.

## 1. Skip this run (exit silently, change nothing) if ANY of these is true
- The date is after 2026-10-18.
- `git status --short` is non-empty (a person or another session is mid-edit), or the
  newest commit is less than 30 minutes old (a person is probably working with Claude).
- Another AEGIS job is already running: a process whose command line contains
  `AI-CySec-defence-system` (check with
  `Get-CimInstance Win32_Process | ? { $_.CommandLine -like '*AI-CySec-defence-system*' -and $_.ProcessId -ne $PID }`),
  or `gateway.exe` / the Juice Shop (`build/app`) is running, or ports 3000/8080/8081 are in use.
- This file's queue has no item marked `[ ]` that is not blocked.

**Do NOT skip just because `ollama.exe` or some Python process exists.** `ollama.exe` is the
always-on Ollama service, and the owner runs an unrelated project (`llm-eval-redteam`) whose
Python processes may be running at any time. Those are not AEGIS jobs: never touch or stop
them. They only matter for item D (LLM work): do item D only if
`curl http://127.0.0.1:11434/api/ps` shows no loaded model AND no `llm-redteam` process is
running; otherwise leave D for a later run and skip it for now (items A-C do not need Ollama).
Timing numbers can be noisier while the unrelated project runs: say so in the results.

Usage-limit note: the owner's usage window resets at **05:20 local time**. Runs that fire
before then may be unable to start; that is normal, not an error.

## 2. Hard rules (never break these, even if a task seems to require it)
1. **Own range only.** Traffic goes to `localhost:8080`/`:3000` of the project range and
   nowhere else. No scanning, probing or contacting any other host. No offensive action
   (CLAUDE.md invariant 2).
2. **Branches only.** Work on branch `autoresume` (create from the latest
   `llm-ablation-diagnostics` or `main` if missing). **Never push to `main`, never force-push,
   never rewrite history, never delete branches.** Push only `autoresume`.
3. **No downloads and no installs** (models, binaries, packages, installers) without the
   owner. If something needs one, record it under "Blocked on the owner" and move on.
4. **No credentials.** Do not attempt `gh auth login`, do not read or write tokens, keys or
   password stores, do not open pull requests (the owner will).
5. **Kill only what you started.** Use `eval/rangectl.py` (it tracks its own PIDs). Never
   `taskkill`/`Stop-Process` by image name (this once stopped every `node.exe` on the
   owner's machine). Never touch processes you did not start.
6. **Honest results.** Report negative and surprising results as they are. Never edit a
   number to look better, never delete a failed run, never loosen a gate threshold to make
   something pass. If a measurement looks wrong, find out why before reporting it (this
   project has already caught: scanner-UA confound, mislabelled attacks, a lucky 0/160).
7. **Quality bar.** `python -m unittest discover -s tests` and `cd gateway && go test ./...`
   must pass before every commit. New code gets tests where it enforces a safety property.
8. **Budget.** One run ~ at most 90 minutes of wall-clock and no more than ~3 range boots.
   Prefer finishing a small verified slice over starting a large unverified one.
9. Do not edit `CLAUDE.md`, the PRD, or anything outside the repo except appending one dated
   line to the owner's local run log at the end of a run that changed
   something.

## 3. Queue (do the first `[ ]` item that is not blocked; update its status here)

### [x] A. The autonomous loop, end to end  — DONE 2026-10-12 (see docs/E2E-RESULTS.md)
Built interactively, not by a scheduled run. Original brief kept below for reference.
Follow-ups left: re-run the e2e once with the new controller fixes (noisy-canary retry, no blacklisting of operational errors) to confirm them live; try signing ON in that same boot.
Today the detector, deliberator, gate, hot reload and memory all work, but each is driven by a
separate experiment script. Nothing wires them into one process that runs with no human.
Build `controller/loop.py` (plus tests) that, while the gateway runs in `enforce` mode:
1. tails `logs/gateway/requests.jsonl`;
2. keeps a sliding window of actors and runs `observer/detector.py` `detect()` on it;
3. on a new campaign: builds a dossier, calls `memory/mitigate.py` `mitigate()` (templates
   first, memory reuse, budgets) to get a gate-passed rule; for rate-limit classes uses
   `gate/ratelimit.py`;
4. hot-loads it via `gate/rulestore.py` in `shadow`, then `canary`, then `enforce`, through
   `gate/live_stages.py` (promotion refused unless both live stages pass);
5. honours the budgets (new rules/hour, LLM calls/hour) and the fail-open rule (a controller
   crash must never affect traffic: the gateway already keeps serving).
Then `eval/e2e_live.py`: one range boot, benign replay traffic running, a fresh attack
campaign started with a spoofed browser UA and **no human action**; report time from campaign
onset to enforcement, requests the attacker got through before the rule enforced, benign
requests blocked by AEGIS rules (must be 0), whether the attacker's objective was met, and the
speed of a **second** exposure (memory). Use classes CRS does not stop: credential stuffing
(rate rule) and command injection (CRS blocked only 8/12 of ours). Also one SQLi run for the
spec's literal acceptance case. Write `docs/E2E-RESULTS.md` with the honest numbers and caveats.

### [~] B. Adaptive adversary against the closed loop  (M4)  — agent + experiment built 2026-10-12; results in docs/M4-RESULTS.md when written
A red agent (`range/attacks/adaptive.py`) that observes whether each request was blocked and
changes technique: re-pace (slow-and-low), rotate the visitor identifier, apply the existing
`range/mutate/mutate.py` mutators. Local range only, bounded request budget. Run it against
CRS-only and against the controller from A. Report attacker objective success, requests until
first block, whether M1 detected and correctly attributed it, how many new rules AEGIS had to
make, and the maximum fraction of legitimate traffic blocked (induced self-DoS under a live
adaptive attacker). Extend `docs/M4-RESULTS.md`. Slow-and-low evasion measured in
`docs/M1-RESULTS.md` is the first adaptation to try.

### [~] C. Harden the rule store — implemented + unit-tested 2026-10-12 (docs/HARDENING.md); NOT yet exercised in a live range boot
HMAC-sign the manifest (key from an environment variable or a file outside git; never
committed) and require a bearer token on the admin API's mutating endpoints; the gateway must
refuse an unsigned or wrongly signed manifest and keep its previous rules. Go tests plus a
Python test. Document the threat model it does and does not cover.

### [ ] D. LLM interface: choose from a vetted pattern library instead of writing regexes
Only if no other Ollama/Python job is running and nothing needs a download. Let the model pick
fixed-vocabulary token classes, locations and endpoints; we compile the regex from a tested
library. Re-run the 4-campaign ablation for `mistral:latest` and `qwen2.5-coder:7b` (both are
installed) and report next to the existing 0/16 result in `docs/M3-RESULTS.md`.

## 4. Blocked on the owner (a run must not try to do these)
- `gh auth login` is needed before any pull request can be opened by a tool.
- Any model or package download (e.g. a 14B model or an API-model key for the planned
  local-vs-frontier ablation).
- Verifying the PRD's citations before any submission.

## 5. Run log (append one entry per run that did anything; newest last)
- 2026-10-11: queue created. State: all of M0-M3 and the first M4 results are measured and on
  branch `llm-ablation-diagnostics`; the autonomous loop (item A) is not built.
- 2026-10-12 (interactive session, not a scheduled run): the scheduled run that fired at 05:22 stalled for ~17 h with no progress (probably an unanswerable permission prompt) and was stopped. Items A, C and most of B done interactively on branch `autoresume`; see commits.
