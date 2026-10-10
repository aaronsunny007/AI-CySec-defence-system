"""Smoke test for the M0 range: benign requests pass, obvious attacks are blocked.

This is NOT the baseline measurement -- it is a sanity check that the
enforcement plane is wired up and logging. Run it after `docker compose up`.

    python eval/smoke.py [--base http://localhost:8080]

Exit code 0 = all checks passed.
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

# (name, method, path, query/body, expect_blocked)
CASES = [
    ("home page", "GET", "/", None, False),
    ("product search", "GET", "/rest/products/search", {"q": "apple"}, False),
    # Weird-but-legitimate: SQL-ish words and an apostrophe in normal text.
    ("benign apostrophe", "GET", "/rest/products/search", {"q": "O'Brien hummus"}, False),
    ("sqli tautology", "GET", "/rest/products/search", {"q": "' OR 1=1--"}, True),
    ("sqli union", "GET", "/rest/products/search",
     {"q": "')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--"}, True),
    ("xss script tag", "GET", "/rest/products/search", {"q": "<script>alert(1)</script>"}, True),
    ("path traversal", "GET", "/ftp/..%2f..%2f..%2fetc%2fpasswd", None, True),
    ("cmd injection", "GET", "/rest/products/search", {"q": "; cat /etc/passwd"}, True),
]


def send(base: str, method: str, path: str, params: dict | None) -> int:
    url = base.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, method=method, headers={"User-Agent": "aegis-smoke/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:8080")
    args = p.parse_args()

    attacks_blocked = benign_ok = 0
    for name, method, path, params, expect_blocked in CASES:
        try:
            status = send(args.base, method, path, params)
        except (urllib.error.URLError, OSError) as e:
            print(f"ERROR  {name:20s} cannot reach {args.base}: {e}")
            return 2
        blocked = status == 403
        if expect_blocked:
            attacks_blocked += blocked
            verdict = "blocked" if blocked else "CRS MISS"
        else:
            # A 5xx here is the APP failing, not the WAF: Juice Shop's search
            # is deliberately SQL-injectable, so a lone apostrophe crashes it.
            benign_ok += not blocked
            if blocked:
                verdict = "CRS FALSE POSITIVE"
            elif status >= 500:
                verdict = "allowed (app error)"
            else:
                verdict = "allowed"
        print(f"{verdict:20s} {name:20s} status={status}")

    n_attack = sum(c[4] for c in CASES)
    n_benign = len(CASES) - n_attack
    print(f"\nbenign allowed: {benign_ok}/{n_benign}   attacks blocked: {attacks_blocked}/{n_attack}")
    # The smoke test checks the RANGE, not CRS. CRS misses and false positives
    # are findings for the baseline, not range failures. The range is broken
    # only if the app is down or nothing at all is being blocked.
    if benign_ok == 0:
        print("RANGE BROKEN: no benign request succeeded (app down?)")
        return 1
    if attacks_blocked == 0:
        print("RANGE BROKEN: no attack was blocked (WAF not in the path?)")
        return 1
    print("range OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
