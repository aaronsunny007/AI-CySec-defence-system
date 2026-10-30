# AEGIS — Autonomous Web-Application Defence Agent

An autonomous defender for a web app: it watches live HTTP traffic, recognises an
attack **campaign** in progress, invents a **new** blocking rule, **proves the rule
does not break legitimate traffic** before enforcing it, deploys it without a
restart, and gets faster on repeat and variant attacks. Containment only — never
offensive action.

The contribution is the **validation gate**, not the detection: anyone can build
something that blocks traffic; the open problem is proving, automatically and
before enforcement, that an autonomously invented mitigation will not harm the
application it defends.

- Spec (agent-executable): [CLAUDE.md](CLAUDE.md) · PRD + literature review: [docs/AEGIS-PRD-v0.2.md](docs/AEGIS-PRD-v0.2.md)
- Why things deviate from the spec: [docs/DECISIONS.md](docs/DECISIONS.md)

## Status

| Milestone | State | Results |
|---|---|---|
| M0 range + baseline | done; **re-measured** after a user-agent confound was found and fixed (CRS alone: 2/8 campaigns contained, attacker still succeeds in 3/8, 4.0% benign FP) | [docs/BASELINE.md](docs/BASELINE.md) |
| M1 campaign detection | heuristics, **re-measured**: 16/16 detected and correctly attributed; slow-and-low pacing evades it | [docs/M1-RESULTS.md](docs/M1-RESULTS.md) |
| M2 rule synthesis + 6-stage gate | done | [docs/M2-RESULTS.md](docs/M2-RESULTS.md), [docs/M2-LIVE-STAGES.md](docs/M2-LIVE-STAGES.md) |
| M3 memory, repeat/variant speed-up | done | [docs/M3-RESULTS.md](docs/M3-RESULTS.md) |
| M3 LLM last-resort path | **0/16** ablation cells promoted a rule (Mistral 7B and Qwen2.5-Coder 7B, one-shot and repair loop, 4 novel campaigns); the gate absorbed all 124 candidates | [docs/M3-RESULTS.md](docs/M3-RESULTS.md) |
| M2/M3 closed loop (the whole thing, no human) | **done and replicated**: `controller/loop.py` enforced a rule 58-80 s (mean) after a campaign began in 33 of 33 class-runs (5 replicates on Juice Shop, 3 on a second small app, 3 on DVWA), gate corpus of 20,262 distinct benign requests; 0 of 151,726 benign requests blocked on Juice Shop and 0 of 155,444 on the second app, 0 of 40,828 on DVWA; memory speeds the synthesis step by orders of magnitude but not end-to-end time; attacks shorter than the ~1-1.5 minute loop latency are not mitigated | [docs/E2E-RESULTS.md](docs/E2E-RESULTS.md) |
| Rule-store hardening | HMAC-signed manifest + admin bearer token implemented, unit-tested and **used in every end-to-end run since 2026-10-12**; tamper/replay against a live gateway untested | [docs/HARDENING.md](docs/HARDENING.md) |
| M4 adaptive adversary, induced self-DoS | self-DoS 0.62% -> 0.008% with the gate; real-speed adaptive red agent: requests reaching the app 380 -> 11 of 400 (SQLi), 323 -> 40 (cmdi); credential stuffing slowed (400 -> 267) but not stopped (single runs); a first adaptive run found one real password blocked by the SQLi rule, fixed | [docs/M4-RESULTS.md](docs/M4-RESULTS.md) |
| Baselines | CRS alone (above) and a static ML-WAF trained on public attack data (`docs/ML-BASELINE.md`): good on classic XSS/SSRF/traversal payloads, 0% on command injection, 37.5% on SQLi and 0% on the behavioural campaigns | [docs/ML-BASELINE.md](docs/ML-BASELINE.md) |
| M5 write-up | **draft v0.3** (numbers trace to the results files; 15 methodology/engineering errors disclosed) | [docs/PAPER-DRAFT.md](docs/PAPER-DRAFT.md) |

Read the "Caveats" section of each results file before quoting a number. Early
measurements that were later found to be flawed are corrected in place and the
superseded versions kept (e.g. `docs/BASELINE.v1-tool-ua.md`).

## Architecture

```
client -> gateway (Go + Coraza + AEGIS rules + CRS) :8080 -> Juice Shop :3000
              | per-rule modes off/shadow/canary/enforce, hot-reloaded from a manifest
              v
       request log (JSONL) -> observer (actors, campaign detector, M1)
                                   v dossier
              deliberator: templates first; LLM only as a last resort -> typed Rule IR
                                   v
              ir/compile (the trusted boundary) -> VALIDATION GATE
                1 benign replay (443k real requests)   FP <= 0.01%
                2 campaign replay                      blocks the attack
                3 live regression (A/B vs CRS only)
                4 mutation test                        generalises, not memorised
                5 shadow (live, M1 as the FP oracle)   live == replay prediction
                6 canary x% + automatic rollback
              memory (SQLite): reuse / generalise / fresh; rule GC; budgets
```

Invariants (CLAUDE.md section 2) that the code enforces: fail open; the LLM is
unprivileged and sees only a fixed-vocabulary feature summary, never raw traffic;
no rule reaches `enforce` without passing every stage; hard budgets (rules/hour,
LLM calls/hour, tokens, candidates).

## Quickstart (free, local, one command)

```bash
curl -fsSL https://raw.githubusercontent.com/aaronsunny007/AI-CySec-defence-system/main/install.sh | sh   # Linux/macOS
irm https://raw.githubusercontent.com/aaronsunny007/AI-CySec-defence-system/main/install.ps1 | iex      # Windows
aegis init --target http://127.0.0.1:3000   # the app to protect
aegis learn                                 # observe only; records your normal traffic
aegis protect                               # enforce + autonomous, gated rule synthesis
```

Or `docker compose -f docker-compose.aegis.yml up -d`. Details, safety defaults and what is not
built yet: [docs/INSTALL.md](docs/INSTALL.md).

## Research range (native Windows — no Docker, no WSL)

One-time: Go (zip) in `%USERPROFILE%\tools\go`, Juice Shop
`juice-shop-20.2.0_node24_win32_x64.zip` in `%USERPROFILE%\tools\juice-shop`, Node 24,
Python 3.12.

```powershell
cd gateway; go build -o ..\bin\gateway.exe .; go build -o ..\bin\replay.exe .\cmd\replay; cd ..
python -m venv .venv
.venv\Scripts\pip install -r range\benign\requirements.txt
.venv\Scripts\python -m playwright install chromium
```

Tests (no network, no range needed):

```powershell
cd gateway; go test ./...; cd ..
.venv\Scripts\python -m unittest discover -s tests -v
```

Experiments (each starts and stops its own range through `eval/rangectl.py`):

| Command | What it does |
|---|---|
| `python eval/baseline.py` | CRS-only baseline -> `docs/BASELINE.md` |
| `python eval/m1_episode.py` | campaign detection, correct attribution, slow-and-low evasion |
| `python eval/ab_stuffing.py` | credential-stuffing A/B using a hot-loaded rate rule |
| `python eval/run_live_stages.py` | gate stages 5 + 6: shadow, canary, auto-rollback |
| `python eval/hotreload_stress.py` | no dropped requests across 48 reloads; corrupt manifest refused |
| `python eval/self_dos.py` | induced self-DoS with and without the gate |
| `python eval/arms_race.py` | adaptive adversary vs memory |
| `python memory/mitigate.py --novel data/attack_corpus/novel_ssti.json --llm ollama` | last-resort LLM path (needs Ollama + a local model) |

The benign corpus (`data/benign_corpus/`, ~260 MB) is not in git; regenerate it
with `python range/benign/generate.py --workers 4 --fast --duration 180` while the
gateway runs in `detect` mode.

## Layout

| Path | Plane | Purpose |
|---|---|---|
| `gateway/` | Enforcement | Go reverse proxy: Coraza + CRS, fail-open, modes, hot reload, counters, admin API, rate limiter; `cmd/replay` = real-engine replay for the gate |
| `observer/` | Observation | actor reconstruction, behavioural campaign detector, known-route learner |
| `deliberator/` | Deliberation | template candidates; `llm.py` last-resort model path |
| `ir/` | trusted boundary | Rule IR schema + validator/compiler (injection-hardened) |
| `gate/` | Validation gate | offline stages, live regression, shadow, canary, rate-limit evaluator, rule store client |
| `memory/` | Memory | SQLite store, mitigation loop, budgets |
| `range/` | Range | benign Playwright journeys, 8 attack campaigns, mutation engine |
| `eval/` | Evaluation | experiments above |
| `tests/`, `gateway/*_test.go` | | adversarial tests for the LLM boundary and the rule guard |
| `docker-compose.yml` | Range | Docker alternative where WSL2 works |

## Limitations (headline ones)

One app (Juice Shop), eight attack classes we wrote, one laptop. Actor
reconstruction uses a per-client cookie that stands in for distinct source IPs; a
real deployment's IP rotation is not handled. Rate limits throttle rather than
prevent. The manifest and admin API are unauthenticated. See each results file.

## Licence

MIT (own code). GPL/AGPL range tools (sqlmap, nikto, DVWA, Grafana) run as
separate processes and are not linked.


## Third target: DVWA (optional)

`python range/dvwa/setup_dvwa.py` downloads PHP 8.3 and MariaDB 10.11 (SHA-256 verified) and DVWA 2.5 under
`~/tools`, then `python eval/e2e_dvwa.py` runs the autonomous loop against it. Loopback only; DVWA is
deliberately vulnerable. See `docs/E2E-RESULTS.md` (DVWA section).
