# Security and robustness review, 2026-10-31

Method: read the trust-boundary code line by line (rule compiler, gateway proxy path, rule store and admin
API, controller, observer, CLI, installers, Docker), then **attacked a running system** (gateway in enforce
mode with signing on, a backend that records what reaches it, the real `aegis` CLI) instead of trusting the
code's comments. Every finding below was reproduced against the live system first; every fix was then
re-attacked the same way and has a regression test. Nothing here is a claim about the research results in the
other documents; see "What was not re-measured".

## Findings

Severity is for a deployment in front of a real app, judged by what an attacker or a bad day can do.

### High

| # | What was wrong | Reproduced as | Fix | Re-attack result |
|---|---|---|---|---|
| 1 | **A padded request body bypassed the WAF.** Only the first 1 MiB of a body was inspected; the rest streamed to the app unseen. | `POST` 1 MiB of `pad=AAAA...` then `&q=1' OR 1=1--`: **HTTP 200, payload reached the app**. The same payload without padding: 403. | New `-max-body` (default 1 MiB) and `-oversize reject|pass`. Default rejects with 413; `pass` forwards but flags `"oversize": true`. | Padded request: **413, backend received nothing**. A body exactly at the cap is still inspected and blocked. |
| 2 | **One header blinded campaign detection.** Actors are keyed on a hash of the visitor's own `Authorization` header or cookie, which the attacker chooses. | 40 SQLi requests, a fresh `Authorization` per request: 40 actors of one request each, **0 campaigns detected** (same traffic, one identity: detected). | The controller pools payload-bearing requests of too-small, caller-chosen identities by client IP (`ident` is now logged: `auth`/`cookie`/`ip`). Lab cookie identities are never pooled. | Rotating attacker detected in 0.4 s as `orphans:<ip>`, in every end-to-end run. |
| 3 | **Passwords and tokens were logged in plaintext**, world-readable (0644), and copied into the learned corpus. | Login body `{"password":"Sup3rS3cret!"}` and `?token=...` appeared verbatim in `requests.jsonl`. | Secret-named fields are redacted before writing (key kept, so login detection still works; a value that looks like an attack payload is kept). Log mode 0600 in a 0700 directory, body capped at 64 KiB, rotation at 1 GiB. | No plaintext secret in the log or in the corpus; files 0600. A Go test and a cross-language parity test guard the redaction. |
| 4 | **One request could freeze the controller for 43 s (ReDoS).** The observer's SQLi pattern had nested and unbounded quantifiers. | A quote followed by 60,000 spaces: **43 s**. `select ` x 9,000: 4 s. The LLM vocabulary: 4.3 s on a few KB of `{{`. | Bounded quantifiers (RE2-compatible, linear), and at most 32 KiB of any request is scanned. | Worst case on a 200,000-character hostile input: 34 ms (observer), 54 ms (vocabulary). Regression test fails if any pattern turns super-linear again. |

### Medium

| # | What was wrong | Fix |
|---|---|---|
| 5 | **The gateway's rule validator parsed quotes differently from Coraza.** `msg:\'x,allow,tag:\'y` was one action to the validator and three to Coraza, so a hidden `allow` switched the WAF off for matching requests, and a hidden `deny` made a rule in **shadow** mode block real traffic (HTTP 418). Needs the signing key, so defence in depth, but its documented guarantee was false. | Closed grammar: no backslashes, balanced quotes, allowlisted actions, operators, transformations and variables, ids confined to 100000-199999. |
| 6 | **Rollback across a restart.** A validly signed *older* manifest put on disk before a restart was accepted and the newer rules vanished silently. | `<manifest>.hw` remembers the newest version loaded; `<manifest>.good` holds the last good copy and is restored. |
| 7 | **A corrupt or unsigned manifest plus a restart stopped the gateway from starting**, taking the protected app down (violates fail-open). | Restores the last-good manifest, else starts with the Core Rule Set only and logs an ERROR. |
| 8 | **Rule compiler:** an id with a trailing newline was accepted (Python `$`), producing a two-line rule the gateway then rejects on every reload; eight wrongly typed inputs crashed with `TypeError` instead of being rejected; `%{...}` macro expansion, regexes RE2 cannot run, and match-everything regexes were accepted. | Strict, type-safe validation that only ever raises `IRError`. |
| 9 | **Rule-id collisions wedged the rule store.** Ids map into 90,000 slots by hash; 89 of 3,990 plausible ids collide (`aegis-idor_bola-8` and `-48`), Coraza refuses duplicates, so the second rule never loaded and every later reload failed. | The rule store gives a colliding rule the next free Coraza id. Verified live: both rules enforce. |
| 10 | **`aegis stop` trusted its pid file.** A stale or edited file could make it kill an unrelated process. | Verifies the command line of each recorded pid before touching it. |
| 11 | **The lab-only `aegis_vid` cookie was honoured in production** as the visitor identity and as a ground-truth label. | Only with `-range` (which `aegis` never passes); lab launchers pass it. |
| 12 | **A single template could not cover a mixed campaign.** Template 3 had no rule for a function call after quote+`and`/`or`, so `' AND SLEEP(5)--` escaped it, while libinjection misses `admin'--`. Once a campaign's evidence reached five requests, every candidate was rejected at attack replay and no rule was made. | Template 3 now covers the function-call shape. Offline gate on the five-request campaign: false positives 0/3000, hard negatives 0/4, attack 5/5, mutation 31/31. Ten ordinary-text cases still do not match. |

### Low

| # | What | Fix |
|---|---|---|
| 13 | `/mode` wrote an invalid manifest to disk, then failed to load it. | Validates first (HTTP 400). |
| 14 | Secret files were created world-readable for an instant; logs and state directories used default permissions. | Created 0600/0700 from the first byte. |
| 15 | `-admin 0.0.0.0:...` without a token would expose the rule store. | Refuses to start. |
| 16 | Installers downloaded a Go toolchain with no integrity check; a truncated `curl \| sh` could half-run; the launcher embedded unquoted paths. | SHA-256 from the official index, fail closed; whole script is one function; unsafe path characters refused. |
| 17 | The Docker image ran as root. | Unprivileged user, no capabilities, `no-new-privileges`, health check. |
| 18 | Controller memory grew with an identity-rotating attacker's request rate. | Hard budgets on actors, requests per actor, context records and pooled requests. |

## Tested and found sound

Admin API: 401 without the token, 401 with a wrong one, 405 for GET, and not reachable through the proxy port
(Host-header tricks included). Running gateway: a wrong signature, an unsigned file, an older signed manifest and
garbage are each refused with the previous rule still blocking. The memory store uses parameterised SQL
throughout. A hostile endpoint in the request path cannot stop mitigation: the scoped candidate is rejected and
the unscoped ones remain.

## Not fixed, on purpose or for lack of means

- **No `X-Forwarded-For` handling.** Behind a load balancer every client has the balancer's address: anonymous
  clients share one actor, and the identity-rotation pooling groups everything by that one IP. Needs a
  trusted-proxy setting; not built.
- **Slow-and-low attacks and rotation of credential stuffing / id-walking beyond the account-keyed limit** are
  still evasions (see `M1-RESULTS.md`, `M4-RESULTS.md`).
- **Per-identity rate-limit state** is pruned hourly, so an attacker minting identities can grow it until then.
- **HMAC is a shared secret**: a compromised gateway or controller holds the key. Admin token travels over
  loopback HTTP.
- **Learning on traffic that includes an attack** still teaches AEGIS that traffic is normal. `aegis protect`
  now warns when more than 2% of learned requests carry attack-like payloads, and keeps them in the corpus
  (the safe direction for a gate), but cannot know the traffic was hostile.
- **A rule that mirrors the observer's own signature is not offered**: tried, and the gate correctly rejected it
  at the mutation stage (it does not survive encoding and comment mutations).

## What was re-measured afterwards, and what was not

Re-measured the same day on Juice Shop v20.2.0 (details and caveats: [REMEASURE-2026-10-31.md](REMEASURE-2026-10-31.md)):
the pre-review and post-review code behave **identically** on 15,396 benign requests, 590 attack requests and the
closed-loop run's own 48,131-request log, so the observer-pattern and template-3 changes did not move detection or
false positives. One closed-loop replicate enforced a rule in all six phases (56 to 185 s) and no AEGIS rule blocked any of
46,823 benign requests.

Not re-measured: the original 443,507-request corpus (a 15,396-request one was regenerated), five replicates, DVWA,
the second app and the adaptive attacker. The closed-loop run flagged 242 benign actors where the earlier notes report
7 to 10; the old and new detectors flag exactly the same ones, so it is not a regression from this review, but I did not
establish why it differs (my best explanation is the traffic mix of the regenerated corpus).

Other limits: `govulncheck` could not run in the review sandbox (it runs in CI, and found the Go standard-library
issue fixed in `5f8fb74`). `bandit` ran: its three "High" findings are SHA-1/MD5 used as fingerprints, not for
security. `install.ps1` and the Docker image were exercised by CI, not by me. No third-party penetration test: one
reviewer, one pass.

## Reproducing

`go test -race ./...` in `gateway/`, `python -I -m unittest discover -s tests`, and the end-to-end runs through
the real CLI (learn on 3,000 requests from 30 visitors, then protect, then a single-identity SQLi campaign, a
rotating-identity one, and a padded oversize body), repeated three times.
