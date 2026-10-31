# The 60-second demo

A real run, not a mock-up: BookNook (a small shop with a login page), the AEGIS gateway in front of it and the
controller, then a credential-stuffing bot. Every request the bot sends is an ordinary login, so the standard
OWASP Core Rule Set has nothing to flag. AEGIS notices the pattern, writes a rate limit, tests it on live traffic
and enforces it.

```bash
python demo/run_demo.py                       # about a minute; needs the gateway built (docs/INSTALL.md)
python demo/record.py demo/aegis-demo.cast -- python demo/run_demo.py          # record it
python demo/build_page.py demo/aegis-demo.cast demo/aegis-demo.html --standalone   # playable page
```

`aegis-demo.html` opens in any browser with no network: the player is a small script in the page. Every number on
the page is read out of the recording, so the text cannot disagree with what is shown.

What it does not show, and you should not claim from it:

* The gate's watching windows are shortened to 8 s (shadow) and 12 s (canary) so it fits in a minute; defaults are
  30 s and 45 s. Every stage still runs.
* One run, one attack class, a toy app. The research results are in `docs/`.
* The bot cracks two accounts before the rule lands. AEGIS limits the damage; it does not prevent the first guesses.
* The controller also looks at a handful of other alerts raised by ordinary visitors with odd searches. It made no
  rule for any of them; the count is printed at the end of the run.

Files: `run_demo.py` (the orchestrator), `visitors.py` (normal users, identified by bearer token as real API clients
are), `attacker.py` (the bot), `record.py` (pseudo-terminal recorder), `build_page.py` (the page).
