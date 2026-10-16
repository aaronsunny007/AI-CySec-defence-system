"""Deliberator: campaign dossier -> candidate mitigations (Rule IR).

Deterministic template synthesis from the attack class and the targeted
endpoints. No LLM -- per invariant 9 the model is the LAST resort, reserved for
campaigns memory does not recognise (M3). For the eight known classes, templates
are the cheap path AND the correct path.

Emits >= 3 candidates spanning a range of specificity / blast radius, so the
gate has real choices: a broad detector, an endpoint-scoped detector (smaller
blast radius), and a stricter pattern. The gate picks the first that passes
every stage.

Each candidate carries a short rationale (what it targets, estimated blast
radius intent). The LLM, when added, will emit into this same IR schema and go
through this same gate -- it never gains more authority than a template.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _endpoint_prefix(dossier: dict) -> str | None:
    """Most-targeted endpoint prefix, for blast-radius scoping."""
    eps = dossier.get("endpoints", [])
    for e in eps:
        if e not in ("/", "") and not e.startswith("/socket.io"):
            return e.replace("{id}", "")
    return None


def candidates_for(attack_class: str, dossier: dict) -> list[dict]:
    ep = _endpoint_prefix(dossier)
    c: list[dict] = []

    if attack_class == "sqli":
        # 1) broad libinjection detector on args+body
        c.append(_ir("sqli", 1, "signature", "args_and_body", "detectSQLi", "",
                     ["urlDecodeUni", "removeComments"],
                     desc="detect SQLi in any arg or body"))
        # 2) same, scoped to the targeted endpoint -> smaller blast radius
        if ep:
            c.append(_ir("sqli", 2, "signature", "args_and_body", "detectSQLi", "",
                         ["urlDecodeUni", "removeComments"], endpoint=ep,
                         desc=f"detect SQLi, scoped to {ep}"))
        # 3) strict regex for the classic tautology/union patterns
        # Comment-tolerance is in the regex (not a transform): removeComments
        # would delete the `--` we match for payloads like admin'--. The
        # (?:\s|/\*.*?\*/) class also absorbs the /**/ whitespace-evasion mutant.
        # A bare quote followed by '#' is NOT matched: a real user's password
        # (7ggq|;]3,p'#) contained it and was locked out of login in a live run
        # (docs/M4-RESULTS.md). "' OR 1=1#" is still caught by the quote+or branch.
        # The boolean branch demands an actual COMPARISON after or/and (1=1, '1'='1', a call,
        # not/true/false/null). A bare "quote then and" matched the review text 'quoted' and
        # "double" on a second app (0.60% of its benign corpus) and was rightly rejected.
        ws = r"(?:\s|/\*.*?\*/)"
        cmp_ = (r"(?:\d+" + ws + r"*[=<>]|'[^']*'" + ws + r"*[=<>]|\(|\bnot\b|\btrue\b|\bfalse\b|\bnull\b|\w+" + ws + r"*=)")
        c.append(_ir("sqli", 3, "input_constraint", "args_and_body", "rx",
                     r"(?i)(union(?:\s|/\*.*?\*/)+(?:all(?:\s|/\*.*?\*/)+)?select|('|%27)(?:\s|/\*.*?\*/|\)|%29)*--(?:[^a-z]|$)"
                     r"|('|%27)(?:\s|/\*.*?\*/|\)|%29)*\b(or|and)\b" + ws + r"*" + cmp_ +
                     r"|\bor\b" + ws + r"+\d+" + ws + r"*=" + ws + r"*\d+)",
                     ["urlDecodeUni", "urlDecodeUni"],
                     desc="regex for quote+boolean comparison / comment / union-select SQLi (comment- and double-encoding tolerant)"))

    elif attack_class == "xss":
        c.append(_ir("xss", 1, "signature", "args_and_body", "detectXSS", "",
                     ["urlDecodeUni", "htmlEntityDecode"], desc="detect XSS in arg/body"))
        c.append(_ir("xss", 2, "input_constraint", "args_and_body", "rx",
                     r"(?i)(<script|onerror\s*=|onload\s*=|<svg|javascript:)",
                     ["urlDecodeUni", "htmlEntityDecode", "lowercase"],
                     desc="regex for script/handler XSS"))
        if ep:
            c.append(_ir("xss", 3, "signature", "args_and_body", "detectXSS", "",
                         ["urlDecodeUni", "htmlEntityDecode"], endpoint=ep,
                         desc=f"detect XSS, scoped to {ep}"))

    elif attack_class == "traversal":
        # NOTE: no normalizePath transform. It RESOLVES ../ before the regex runs,
        # so the very pattern we want to match is gone (found in the M4 arms race).
        # The payload is in the PATH, so the target is the URI, not args/body.
        # `.{2,}` followed by a slash also catches `....//` (a ../ filter bypass).
        # A single "../" is ordinary text ("see ../docs": 0.22% of a diverse benign corpus). Attacks
        # chain several, name a sensitive file, use a null byte, or climb one level straight into
        # a system directory.
        trav = (r"(?i)((\.{2,}(/|%2f|%5c|\\)+){2,}|(%2e%2e(/|%2f|%5c|\\)+){2,}|/etc/(passwd|shadow)"
                r"|win\.ini|boot\.ini|/proc/self|%00|%2500|\x00"
                r"|\.{2,}(/|%2f|%5c|\\)+(etc|windows|winnt|proc|boot|root|var)\b)")
        c.append(_ir("traversal", 1, "input_constraint", "uri", "rx", trav,
                     ["urlDecodeUni", "urlDecodeUni"], desc="traversal sequences / null byte / /etc/passwd in URI"))
        if ep:
            c.append(_ir("traversal", 2, "input_constraint", "uri", "rx", trav,
                         ["urlDecodeUni", "urlDecodeUni"], endpoint=ep.split("{")[0].rstrip("/") or None,
                         desc="traversal patterns in URI, scoped to the targeted endpoint"))
        c.append(_ir("traversal", 3, "input_constraint", "uri", "rx",
                     r"(\.{2,}[/\\]+){2,}", ["urlDecodeUni", "urlDecodeUni"],
                     desc="two or more consecutive ../ sequences in URI"))

    elif attack_class == "cmdi":
        # NOTE: no cmdLine transform. ModSecurity's cmdLine DELETES quotes/backslashes and
        # turns ';' into a space, so a regex that looks for ';' can never match after it
        # (found by the first live end-to-end run: all three templates blocked 0% of
        # '; cat /etc/passwd'). Match the raw decoded text instead.
        ws = r"(?:\s|/\*.*?\*/)"
        cmd = r"(cat|id|whoami|ls|ping|sleep|uname|wget|curl|nc|bash|sh)\b"
        # $( and backticks count only when a command word follows ("$(10) off" and `code` are
        # ordinary text); HTML entities are decoded first so "&amp; ping" is not read as "; ping".
        c.append(_ir("cmdi", 1, "input_constraint", "args_and_body", "rx",
                     r"(?i)((;|&&|\|\|?)" + ws + r"*" + cmd + r"|\$\(" + ws + r"*" + cmd + r"|`" + ws + r"*" + cmd + r"[^`]*`)",
                     ["urlDecodeUni", "urlDecodeUni", "htmlEntityDecode"],
                     desc="shell separator + command, $(command), `command` (entity-decoded, comment/double-encoding tolerant)"))
        c.append(_ir("cmdi", 2, "input_constraint", "args_and_body", "rx",
                     r"(?i)(&&|\|\||;|\$\(|`).*(cat|id|whoami|ls|ping|sleep)",
                     ["urlDecodeUni", "urlDecodeUni"], desc="command chaining then command (broad)"))
        c.append(_ir("cmdi", 3, "input_constraint", "args_and_body", "rx",
                     r"(?i)[;&|]{1,2}" + ws + r"*" + cmd + r"(?:" + ws + r"+[^\s]|$)",
                     ["urlDecodeUni", "urlDecodeUni", "htmlEntityDecode"],
                     desc="separator directly before a command that has an argument or ends the value"))

    elif attack_class == "ssrf":
        c.append(_ir("ssrf", 1, "input_constraint", "args_and_body", "rx",
                     r"(?i)(https?|file|gopher)://(127\.0\.0\.1|localhost|169\.254\.169\.254|\[::1\]|0\.0\.0\.0)",
                     ["urlDecodeUni", "lowercase"], desc="internal/metadata URL in input"))
        c.append(_ir("ssrf", 2, "input_constraint", "args_and_body", "rx",
                     r"(?i)169\.254\.169\.254|metadata",
                     ["urlDecodeUni", "lowercase"], desc="cloud metadata host"))
        if ep:
            c.append(_ir("ssrf", 3, "input_constraint", "args_and_body", "rx",
                         r"(?i)(https?|file|gopher)://(127\.0\.0\.1|localhost|169\.254\.169\.254)",
                         ["urlDecodeUni", "lowercase"], endpoint=ep,
                         desc=f"internal URL, scoped to {ep}"))

    else:
        # credential_stuffing / user_enumeration / idor_bola -> rate_limit
        # mechanism, whose compilation is deferred (M2b). Emit the IR so the
        # record exists and the gate explicitly reports it as not-yet-compilable.
        c.extend(_rate_ir(attack_class, dossier))

    return c


def _ir(cls: str, n: int, mechanism: str, target: str, operator: str, value: str,
        transforms: list[str], endpoint: str | None = None, desc: str = "") -> dict:
    ir = {
        "id": f"aegis-{cls}-{n}",
        "description": desc,
        "attack_class": cls,
        "mechanism": mechanism,
        "action": "block",
        "ttl_s": 86400,
        "match": {"target": target, "operator": operator, "value": value,
                  "transformations": transforms},
    }
    if endpoint:
        ir["scope"] = {"endpoint_prefix": endpoint}
    return ir


def _rate_ir(cls: str, dossier: dict) -> list[dict]:
    """Rate-limit candidates, scoped to the endpoint(s) the campaign abused.
    Two specificities so the gate can choose: a tight count and a looser one."""
    cfg = {
        "credential_stuffing": ("/rest/user/login", ["POST"], [(5, 60), (10, 60)]),
        "user_enumeration": ("/rest/user/security-question", ["GET"], [(5, 60), (8, 120)]),
        "idor_bola": ("/rest/basket", ["GET"], [(8, 30), (15, 60)]),
    }
    endpoint, methods, rates = cfg.get(cls, ("/rest", ["GET", "POST"], [(10, 60)]))
    if cls == "credential_stuffing":
        # scope to the endpoint the campaign actually hit (works on apps other than Juice Shop)
        for e in dossier.get("endpoints", []):
            if e not in ("", "/") and not e.startswith("/socket.io"):
                endpoint = e.replace("{id}", "").rstrip("/") or endpoint
                break
    out = []
    for i, (n, w) in enumerate(rates, 1):
        out.append({
            "id": f"aegis-{cls}-{i}", "description": f"rate-limit {cls}: >{n} req/{w}s to {endpoint}",
            "attack_class": cls, "mechanism": "rate_limit", "action": "block",
            "ttl_s": 86400, "key": "actor",
            "scope": {"endpoint_prefix": endpoint, "methods": methods},
            "rate": {"count": n, "window_s": w},
        })
    if cls == "credential_stuffing":
        # Account-keyed variants: count guesses per TARGET account, so an attacker who rotates
        # identity cannot reset the counter. Tried only after the identity-keyed ones (smaller
        # blast radius: an attacker can deliberately lock a victim account out of logins).
        for j, (n, w) in enumerate([(5, 60), (10, 60)], len(rates) + 1):
            out.append({
                "id": f"aegis-{cls}-{j}",
                "description": f"rate-limit {cls} per ACCOUNT: >{n} attempts/{w}s on one account",
                "attack_class": cls, "mechanism": "rate_limit", "action": "block",
                "ttl_s": 86400, "key": "account",
                "scope": {"endpoint_prefix": endpoint, "methods": methods},
                "rate": {"count": n, "window_s": w},
            })
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--dossier", type=Path, help="a dossier JSON (from observer); "
                   "or use --class to synthesise from class alone")
    p.add_argument("--class", dest="cls", help="attack class if no dossier")
    p.add_argument("--out", type=Path, required=True, help="write candidate IR list here")
    args = p.parse_args()

    if args.dossier:
        d = json.loads(args.dossier.read_text(encoding="utf-8"))
        cls = (d.get("techniques") or [d.get("attack_class", "")])[0]
        dossier = d
    elif args.cls:
        cls, dossier = args.cls, {"endpoints": []}
    else:
        print("need --dossier or --class", file=sys.stderr)
        return 2

    cands = candidates_for(cls, dossier)
    args.out.write_text(json.dumps(cands, indent=2), encoding="utf-8")
    print(f"{len(cands)} candidates for '{cls}' -> {args.out}")
    for c in cands:
        print(f"  {c['id']:18s} {c['mechanism']:16s} {c['description']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
