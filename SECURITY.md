# Security policy

AEGIS is a research project. It has been tested only against OWASP Juice Shop, DVWA and one small test app, and has had one internal review ([docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md)) but no outside penetration test. Do not treat it as a hardened product.

## Reporting a vulnerability

Please report privately, not in a public issue.

1. Use GitHub's private report form: <https://github.com/aaronsunny007/AI-CySec-defence-system/security/advisories/new>.
2. If that form is not available, open a public issue titled "Security contact request" with **no details**, and I will arrange a private channel.

Include what you found, how to reproduce it, and the commit you tested. This is a one-person, spare-time project, so there is no guaranteed response or fix time; I will reply when I can. That said, real bypasses of the validation gate or the gateway are the highest priority.

## In scope

- The Go gateway, rule compiler (`ir/`), validation gate (`gate/`), controller and observer.
- Ways to make AEGIS block legitimate traffic, skip the gate, or leak secrets from its logs.

## Out of scope

- Attacks AEGIS documents as unhandled (slow-and-low, identity rotation on credential stuffing, missing `X-Forwarded-For` handling). See [docs/INSTALL.md](docs/INSTALL.md).
- The lab target apps themselves (Juice Shop, DVWA).

## Using AEGIS responsibly

AEGIS is defensive only. Run it only in front of applications you own or are allowed to protect.
