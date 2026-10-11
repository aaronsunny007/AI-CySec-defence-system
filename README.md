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
| M4 adaptive adversary, induced self-DoS | self-DoS 0.62% -> 0.008% with the gate; arms race 5/5 (replay of recorded campaigns, not yet an adaptive attacker) | [docs/M4-RESULTS.md](docs/M4-RESULTS.md) |
| M5 write-up | **draft v0.1** (numbers all trace to the results files) | [docs/PAPER-DRAFT.md](docs/PAPER-DRAFT.md) |

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

## Run it (native Windows — no Docker, no WSL)

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
