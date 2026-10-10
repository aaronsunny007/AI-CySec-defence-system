# AEGIS — Autonomous Web-Application Defence Agent

An autonomous defender for a web app: detects attack campaigns in live HTTP
traffic, synthesises new blocking rules, **proves they don't break legitimate
traffic** before enforcing them, and gets faster on repeat/variant attacks.
Containment only — never offensive action.

- Spec (agent-executable): [CLAUDE.md](CLAUDE.md)
- Full PRD, literature review, bibliography: [docs/AEGIS-PRD-v0.2.md](docs/AEGIS-PRD-v0.2.md)
- Deviations from the spec and why: [docs/DECISIONS.md](docs/DECISIONS.md)

## Status: M0 step 1 — range + logging ✅

```
client ──► gateway (Go + Coraza + OWASP CRS) 127.0.0.1:8080 ──► Juice Shop :3000
                │
                └─► logs/gateway/requests.jsonl   (one JSON line per request, schema v1)
```

### Run it (native Windows, no Docker)

One-time setup: Go zip in `%USERPROFILE%\tools\go`, Juice Shop
`juice-shop-20.2.0_node24_win32_x64.zip` in `%USERPROFILE%\tools\juice-shop`, Node 24.

```powershell
cd gateway; go build -o ..\bin\gateway.exe .; cd ..      # build once
.\range\start.ps1                                        # start (add -Mode detect to log-only)
python eval\smoke.py                                     # sanity check
.\range\stop.ps1                                         # stop
```

Browse Juice Shop through the WAF at http://localhost:8080.

### Alternative: Docker (where WSL2/Docker work)

`docker compose up -d` runs Juice Shop behind the nginx ModSecurity/CRS image;
`python observer/normalise.py` converts its audit log to the same v1 schema.

### Layout (grows per milestone)

| Path | Plane | Purpose |
|---|---|---|
| `gateway/` | Enforcement | Go reverse proxy: Coraza + CRS, fail-open, JSONL logging, enforce/detect modes |
| `range/start.ps1`, `stop.ps1` | Range | Bring the native range up/down |
| `range/benign/` | Range | Playwright robot shoppers: 11 journeys, random personas, weird-but-legitimate input |
| `range/attacks/` | Range | 8 scripted attack campaigns (SQLi, XSS, traversal, cmdi, SSRF, user-enum, IDOR/BOLA, cred-stuffing) |
| `observer/normalise.py` | Observation | ModSecurity audit log → v1 schema (Docker path) |
| `eval/smoke.py` | Eval | Sanity check the range is wired up |
| `docker-compose.yml` | Range | Docker alternative |

Benign traffic (one-time: `python -m venv .venv`, `.venv\Scripts\pip install -r range\benign\requirements.txt`, `.venv\Scripts\python -m playwright install chromium`):

```powershell
.\range\start.ps1 -Mode detect
.venv\Scripts\python range\benign\generate.py --workers 4 --fast --duration 30
```

Early (pre-baseline) results: [docs/FINDINGS.md](docs/FINDINGS.md).

### Next (M0)
1. ~~Playwright benign traffic generator~~ ✅
2. ≥100k-request benign corpus
3. ~~Scripted attack campaigns (8 classes)~~ ✅ (`range/attacks/`)
4. Episode harness → `metrics.jsonl`
5. **Baseline number in `docs/BASELINE.md`** — no AI before this exists.
