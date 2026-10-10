# Decisions log

Deviations from the build spec / PRD, with reasons. Newest first.

## 2026-10-10 — Native Windows range; Go gateway brought forward from M2

**Context.** Docker Desktop needs WSL2; WSL could not be installed or repaired
on the dev laptop (`Wsl/CallMsi/Install/REGDB_E_CLASSNOTREG`).

**Decision.** Run the range natively:
- Juice Shop v20.2.0, official prebuilt `node24_win32_x64` release, run with `node build/app`.
- Enforcement plane: our own Go gateway (`gateway/`) embedding OWASP Coraza v3.8.1
  + coraza-coreruleset v4.25.0 (OWASP CRS 4.x), default paranoia level 1,
  inbound anomaly threshold 5.
- `docker-compose.yml` kept for machines where Docker works (e.g. Codespaces).

**Consequences.**
- The spec planned this gateway for M2; it now exists from M0. It already
  satisfies fail-open (Coraza errors/panics forward the request) and logs
  every request in the v1 schema with per-request WAF latency.
- Baseline (2) "CRS at default paranoia" is now CRS-on-Coraza, not
  CRS-on-ModSecurity. Coraza is CRS-compatible and passes the CRS test suite,
  but state it explicitly in the write-up.
- Juice Shop listens on 0.0.0.0:3000, so it is reachable directly, bypassing
  the gateway. Only traffic sent to :8080 counts in any measurement.

**First observations (8-request smoke test, not a measurement).**
- CRS missed `; cat /etc/passwd` in a query parameter at PL1 (score 0).
- WAF evaluation ~1.8–3.7 ms per request, cold. Above the 1 ms p99 budget
  (invariant 8). To be measured properly under load before drawing conclusions.

## 2026-10-10 — Per-actor `aegis_vid` nonce on the single-host range (M1)

**Context.** On one laptop every client (benign and attack) connects from
127.0.0.1, so IP cannot separate actors, and the only other per-client signal
is the user-agent — which must NOT be a detection feature.

**Decision.** The range stamps each independent client with a random
`aegis_vid` cookie (benign: per Playwright context; attack: per campaign actor).
The gateway hashes it into the `session` field. The observer groups requests by
that session to reconstruct actors.

**Consequences.**
- Substitutes for the distinct source IPs / sessions a real deployment provides.
- The observer uses it ONLY to group requests, never to classify — detection
  stays behavioural. Stated as a limitation in docs/M1-RESULTS.md.
- Real actor reconstruction across IP rotation + fingerprint is deferred; it is
  an M1-hardening / M4 item, not needed to prove the M1 detection thesis.

## 2026-10-11 — Gateway: rule modes, hot reload, and why AEGIS rules `pass`

**Decision.** AEGIS SecRules compile in *gateway form* (`pass,log`, tagged
`aegis-rule:<id>`); the gateway decides per rule whether a match blocks, from the
rule's mode `off | shadow | canary(x%) | enforce`. The replay tool and gate still
use the `deny` form, since they test a single rule in isolation.
Rules live in a manifest (`rules/active/manifest.json`) the gateway polls; on
change a new immutable rule set is built in the background and swapped in with an
atomic pointer, so in-flight requests finish on the old set (no dropped
connection). A failed build keeps the old set. Rollback = mode `off`.

**Why.** Per-rule modes, shadow, canary and sub-5-second rollback (FR-E2/E3/E5)
are all "the same match, a different decision", so the decision belongs in one
place that is not the rule text.

**Consequences / limits.**
- The admin API (stats, mode, rollback) is loopback-only and unauthenticated.
  Manifest signing (PRD section 9, rule-store tampering) is NOT implemented.
- The gateway validates manifest rule text independently of the compiler: each
  line must be `SecRule <vars> "<op>" "<actions>"` and every action must be on an
  allowlist (`id, phase, pass, log, msg, tag, t, chain`). An allowlist on the
  parsed actions argument, not a substring blocklist, so legitimate regexes
  containing e.g. "exec" are not rejected.
- Canary membership is a stable hash of the actor, not per request. The
  monitor supports one canary rule at a time (the canary slice is defined by the
  highest canary_pct).

## 2026-10-11 — AEGIS rules load BEFORE CRS

Coraza stops evaluating once CRS's blocking rule (949110, phase 2) interrupts. A
rule loaded after CRS would therefore never see any request CRS already blocked,
and shadow counts would silently under-count. AEGIS rules now precede CRS in the
directive order; being `pass` rules they never interrupt.

## 2026-10-11 — Renamed observer/campaigns.py -> observer/detector.py

Two modules were both called `campaigns` (the M1 detector and the attack
scripts), so whichever directory was first on `sys.path` won. The detector is
now `observer/detector.py`.

## 2026-10-11 — Live range orchestration moved from PowerShell to Python

`eval/rangectl.py` launches Juice Shop and the gateway directly, records only the
PIDs it created, waits for real readiness, and terminates exactly those PIDs. The
PowerShell start/stop loop repeatedly hung during multi-phase experiments.
(`range/start.ps1`/`stop.ps1` remain for manual use.)

## 2026-10-11 — LLM deliberator: local Mistral 7B behind a swappable interface

Ollama 0.40.2 was already installed with `mistral:latest` (7B). The spec prefers
Qwen2.5-Coder; the backend interface (`deliberator/llm.py`) is swappable, so a
Qwen or API backend can be added for the planned local-vs-frontier ablation.
The model sees only a fixed-vocabulary feature summary and known-route endpoint
shapes — never raw traffic — and may emit only IR, which goes through the same
compiler and gate as template candidates.
