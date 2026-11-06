---
name: aegis-install
description: Install and run AEGIS, a free local defence agent that sits in front of your web app, learns its normal traffic, then blocks attack campaigns with rules it writes and tests itself. Use when asked to set up AEGIS, protect a local or staging web app with it, or check what it has detected.
---

# Install and run AEGIS

AEGIS is a reverse proxy that blocks HTTP attack traffic ("virtual patching"). It does not patch your code and does not inspect responses. Free, local, MIT. Repo: https://github.com/aaronsunny007/AI-CySec-defence-system

## Rules for the agent

- Only point AEGIS at an app the user owns or is allowed to protect. Never use it, or anything in this repo, against someone else's system.
- Do not pipe a remote script into a shell. Clone, read `install.sh` (or `install.ps1`), tell the user what it does, then run it.
- Start in learn mode. `aegis protect` refuses to start under 2,000 learned requests from 20 distinct visitors. Do not try to get around that; it is how the safety gate proves a rule will not block real users.
- Learn from traffic you trust (staging, a quiet period, a replayed test suite). An attacker present during learning teaches AEGIS that their traffic is normal.
- Report what you saw, including failures. Do not claim the app is "secured".

## Steps

1. Check Python 3.10+ and git are present. Go is optional; the installer downloads it into `~/.aegis/go` if missing.
2. `git clone https://github.com/aaronsunny007/AI-CySec-defence-system` and read `install.sh` / `install.ps1`.
3. Run the installer from the clone (`./install.sh` or `.\install.ps1`). It builds the gateway and puts `aegis` on PATH.
4. Ask the user for the app URL, then:

```bash
aegis init --target http://127.0.0.1:3000
aegis doctor
aegis learn
```

5. Have the user send normal traffic through port 8080 (real users, staging, or a test suite). Check progress with `aegis status`.
6. When the corpus is big enough, `aegis protect`. Read what it decided with `aegis events`. `aegis stop` sends traffic straight to the app again.

## Know before you rely on it

- The gateway is a reverse proxy: if the gateway process dies, anything pointed at its port loses the app. Keep a direct fallback route and a supervisor that restarts it.
- Request bodies over 1 MiB are refused (HTTP 413) by default.
- No `X-Forwarded-For` handling yet; behind a load balancer that hides client IPs, clients cannot be told apart.
- Slow-and-low attacks and attackers who rotate identities on credential stuffing or id-walking can evade it.
- Tested only on OWASP Juice Shop, DVWA and one small test app. No outside pentest.
- The LLM path is off by default; deterministic templates cover the known attack classes.

Full details: `docs/INSTALL.md` in the repo.
