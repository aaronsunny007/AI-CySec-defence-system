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
