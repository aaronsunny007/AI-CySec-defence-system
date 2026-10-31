# Installing AEGIS

Everything here is free and runs locally: Go, Python, SQLite, the OWASP Core Rule Set, and
(optionally) Ollama. No accounts, no cloud, no API keys.

## One command

Linux / macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/aaronsunny007/AI-CySec-defence-system/main/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/aaronsunny007/AI-CySec-defence-system/main/install.ps1 | iex
```

Or from a clone: `./install.sh` / `.\install.ps1`.

It needs Python 3.10+ and (for the curl/irm form) git. If there is no Go toolchain it downloads
the official one into `~/.aegis/go` (no root, no admin). It builds the gateway, which embeds
Coraza and the Core Rule Set, and puts an `aegis` command on your PATH. It never touches your app.

## Docker instead

```bash
AEGIS_TARGET=http://host.docker.internal:3000 docker compose -f docker-compose.aegis.yml up -d
```

Starts in learn mode on port 8080. Add `--profile demo` to also start OWASP Juice Shop and
target it. Switch to protect mode with `AEGIS_MODE=protect docker compose -f docker-compose.aegis.yml up -d`.

## Using it: learn first, then protect

```bash
aegis init --target http://127.0.0.1:3000   # your app
aegis doctor                                # checks Python, binaries, target, ports
aegis learn                                 # proxy on :8080; observes, never blocks
#   ... send your normal traffic through :8080 (users, staging, your test-suite) ...
aegis status                                # request count so far
aegis protect                               # enforce + autonomous rule synthesis
aegis stop                                  # traffic goes straight to your app again
```

**Why learn first.** The validation gate proves a new rule would not block legitimate users by
replaying *your* traffic against it. With no traffic to replay it cannot prove anything. So
`aegis protect` refuses to start with fewer than 2,000 requests from 20 distinct visitors, and
there is no override. Visitors the observer flags as running an attack while learning are left
out of the corpus.

**Learn from traffic you trust.** Anything in the corpus is treated as normal. An attacker who
is present, and quiet enough not to be flagged, during learning teaches AEGIS that their
traffic is fine. Learn on a staging copy, a quiet period, or a replayed test-suite.

## Safety defaults

- **Fails open, with one condition.** If the controller dies, the gateway keeps passing
  traffic and existing rules stay as they are. `aegis stop` never changes your app; it is
  still reachable on its own port. But if the *gateway* process dies, everyone pointed at
  AEGIS's port loses the app, because it is a reverse proxy. Keep a direct route as a fallback:
  put a load balancer or health-checked DNS in front that falls back to the app, and let a
  supervisor restart the gateway (the Docker file uses `restart: unless-stopped`). A built-in
  bypass is not done yet.
- **No rule enforces without passing the gate:** benign replay, campaign replay, mutation,
  live shadow, then a canary with automatic rollback.
- **Secrets** (rule-store signing key, admin token) are generated into `.aegis/` with 0600
  permissions on first `aegis init`.
- **LLM is off by default.** Templates cover the known attack classes. To enable the last-resort
  LLM path for novel campaigns, install Ollama (free), `ollama pull qwen2.5-coder:7b`, and run
  `aegis init --llm ollama`. In the measured ablation it promoted 0 of 16 rules
  ([M3-RESULTS](M3-RESULTS.md)), so leaving it off costs you little.

## Behaviour you should know about

- **Bodies over 1 MiB are refused (HTTP 413) by default.** A WAF can only judge what it reads; before this was
  fixed, padding a request body past the inspected prefix carried a SQL-injection payload straight to the app.
  If your app takes large uploads, either raise the limit or accept uninspected uploads explicitly: start the
  gateway with `-max-body BYTES` and/or `-oversize pass` (the request is forwarded, only the first `-max-body`
  bytes are inspected, and the log record is flagged `"oversize": true`). `aegis` does not expose these yet; pass
  them to `bin/gateway` directly.
- **Passwords and tokens are not logged.** Values of fields named like `password`, `token`, `secret`, `api_key`,
  `card`, `cvv` ... in JSON, form, XML and query strings are replaced by `[redacted]` before a request is
  written (the field name stays, so login detection still works). A value that looks like an attack payload is
  kept, because the observer needs it. Redaction is by field name: a secret in a field named something else is
  logged. Bodies are cut at 64 KiB in the log; the request log is created readable by you only, and rotates to
  `requests.jsonl.1` at 1 GiB.
- **Attackers who change identity on every request are still caught,** for injection-style payloads: requests
  from small, caller-chosen identities (a fresh `Authorization` header or app cookie each time) are pooled by
  client IP. This does not cover credential stuffing or id-walking by a rotating attacker beyond what the
  account-keyed rate limit already did, and it cannot tell clients apart behind a load balancer that hides the
  client IP (the gateway does not read `X-Forwarded-For` yet).
- **`-range` is for the research lab only.** It makes the `aegis_vid` cookie the visitor identity, which an
  attacker can set freely. `aegis` never passes it.

## What this install does not give you yet

Honest list: the dashboard and alerting are not built (use `aegis status` and
`logs/controller/events.jsonl`); there is no human-approval mode yet; it has only been run in
front of Juice Shop, DVWA and one small test app; and attacks shorter than the ~1-1.5 minute
loop are not mitigated in time. See the status table in the README.
