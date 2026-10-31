# Rule-store hardening: signed manifest and authenticated admin API

Status: implemented, unit-tested (Go + Python) and **exercised in one full live end-to-end run**
(2026-10-12, `docs/E2E-RESULTS.md` run 2: all rule changes went through the signed manifest and
the token-guarded admin API). Off by default; switched on by setting a key.

## Why

The gateway's whole rule set is one file, `rules/active/manifest.json`, hot-reloaded when it
changes. Whoever can write that file can switch the defence off, or install a rule that
blocks real users: the same self-DoS the validation gate exists to prevent, but done around
the gate. The admin API on `127.0.0.1:8081` can also change rule modes. PRD section 9
listed rule-store tampering as a threat; until now nothing defended it.

## What it does

* **Signed manifest.** With `AEGIS_MANIFEST_KEY` (or `AEGIS_MANIFEST_KEY_FILE` = path to a
  file outside the repo) set, the manifest file is an envelope
  `{"payload": "<manifest JSON text>", "sig": "<hex HMAC-SHA256 of payload>"}`.
  The gateway **refuses** an unsigned file, a wrongly signed file, an edited payload, and
  garbage, logs the reason, and **keeps serving with its previous rules**.
* **Replay refusal.** In signed mode the gateway also refuses a validly signed manifest whose
  `version` is lower than the one already loaded (an old, weaker rule set cannot be swapped
  back in).
* **Admin token.** With `AEGIS_ADMIN_TOKEN` (or `_FILE`) set, the mutating endpoints
  (`/mode`, `/rollback`) require `Authorization: Bearer <token>` (constant-time compare,
  401 otherwise). `/health` and `/stats` stay open on loopback.
* **Same code path for writers.** `gate/rulestore.py` (the controller's writer) and the
  gateway's own admin writer both sign when a key is configured; both read the same
  environment variables. A cross-language test vector pins the two HMAC implementations
  together (`TestSignatureMatchesPythonVector` / `test_vector_matches_go`).
* Secrets are read from the environment or a file, never from the repo and never logged.

Turn it on (PowerShell), with a key stored outside the repository:

```powershell
$dir = "$env:USERPROFILE\.aegis"; New-Item -ItemType Directory -Force $dir | Out-Null
[guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N") | Set-Content "$dir\manifest.key"
[guid]::NewGuid().ToString("N") | Set-Content "$dir\admin.token"
$env:AEGIS_MANIFEST_KEY_FILE = "$dir\manifest.key"
$env:AEGIS_ADMIN_TOKEN_FILE  = "$dir\admin.token"
# then start the range / controller from the same shell
```

## Threat model

Covered:

| Attacker capability | Outcome |
|---|---|
| Can write the manifest file but does not hold the key | Edits are rejected; previous rules stay live |
| Can replace the manifest with an older signed copy | Refused while running, **and across a restart** (`<manifest>.hw` remembers the newest version loaded); the last-good copy is restored |
| Another local process calls `/mode` or `/rollback` without the token | 401 |
| Corrupts the file (partial write, garbage), or replaces it with an unsigned one | Refused; previous rules stay live. At a restart the last-good manifest (`<manifest>.good`) is restored instead of starting without rules |
| Smuggles `allow` / `deny` / `ctl:` into a rule's actions with backslash-escaped quotes | Refused: the gateway's validator now has a closed grammar (no backslashes, balanced quotes, allowlisted actions, operators, transformations, ids 100000-199999) |

**Not** covered (be honest about these):

* **Key theft.** Anything that can read the key file or the environment of the gateway or
  controller can sign. File permissions on the key are the real boundary and are the
  operator's job. This is HMAC (shared secret), not public-key signing: the gateway holds the
  same key that signs, so a gateway compromise also yields the key.
* A compromised controller process: it holds the key and may legitimately write any rule. The
  defence against a bad rule from a compromised or mistaken controller is the gate and the
  gateway's action allowlist, not the signature.
* A root/administrator attacker on the host (can read process memory, replace the binary).
* Confidentiality: the manifest is signed, not encrypted.
* Availability: with an invalid manifest and no usable `<manifest>.good` the gateway starts with the OWASP
  Core Rule Set only and logs an ERROR (it no longer refuses to start, which took the protected app
  down). It will not run an unverified rule set, and it keeps serving with its loaded rules if the file
  goes bad while running.
* The admin token is a bearer secret over loopback HTTP; a local attacker who can sniff
  loopback traffic as the same user can read it.
* Rollback by deleting the manifest (and `.hw`/`.good`) and restarting: that is the documented way to reset
  the store, so it cannot also be refused. It leaves the gateway with no AEGIS rules, not with old ones.
* A root-level attacker can also rewrite `<manifest>.hw` and `<manifest>.good`; both are signed with the key,
  so only a key holder can forge them.

## What was and was not tested

* Go unit tests: round trip, tampered payload, unsigned file in signed mode, wrong key,
  garbage, unsigned mode unchanged, token guard (missing / wrong / no-"Bearer" / correct /
  not configured), and a `reload()` test showing an older signed manifest and an unsigned one
  are refused while the v5 rules stay loaded and a newer valid one is accepted.
* Python unit tests: envelope shape and round trip, tamper and unsigned refusal, unsigned mode
  unchanged, key from a file, the token is sent on POST only, no key in source.
* Cross-language HMAC vector.
* One full live run with signing and the token on (see the status line).
* **Tested live against a running gateway (2026-10-31):** wrong signature, unsigned file, an older signed
  manifest and a garbage file are each refused with the previous rule still blocking; an older signed manifest,
  a corrupt one and an unsigned one put on disk before a restart are each replaced by the last-good manifest
  (before the fix: the gateway refused to start, or silently lost the newer rule); admin calls without a token
  get 401, with a GET 405; the admin API is not reachable through the proxy port; `-admin` on a non-loopback
  address without a token refuses to start. Not tested: key rotation.
* Found while doing it: `rulestore.clear()` crashed over a leftover *unsigned* manifest once a
  key was set; fixed and tested.
