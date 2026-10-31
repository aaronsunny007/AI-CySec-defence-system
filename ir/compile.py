"""Compile and validate the AEGIS Rule IR -> Coraza SecRule.

The LLM/deliberator emits IR only; this module is the trusted boundary. It:
  1. validates the IR against a fixed whitelist (no free-form directives ever),
  2. compiles it to a single Coraza SecRule (optionally a scope chain),
  3. assigns a numeric id in the AEGIS range 100000-199999.

Nothing here executes model output as code. `value` is emitted only inside a
quoted SecRule operator argument, never as a directive, and is length- and
regex-validated first. This is invariant 3 ("the LLM never emits enforcement
syntax") made concrete.

Dependency-free; no jsonschema needed (the validator is explicit and auditable).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TARGET = {
    "args": "ARGS", "body": "REQUEST_BODY", "uri": "REQUEST_URI",
    "path": "REQUEST_FILENAME", "args_names": "ARGS_NAMES",
    "request_line": "REQUEST_LINE", "all_args": "ARGS|ARGS_NAMES",
    "args_and_body": "ARGS|REQUEST_BODY",
}
OPERATOR = {
    "rx": "@rx", "contains": "@contains", "streq": "@streq",
    "detectSQLi": "@detectSQLi", "detectXSS": "@detectXSS",
    "gt": "@gt", "ge": "@ge",
}
TRANSFORM = {
    "none": "none", "lowercase": "lowercase", "urlDecodeUni": "urlDecodeUni",
    "removeComments": "removeComments", "compressWhitespace": "compressWhitespace",
    "removeWhitespace": "removeWhitespace", "htmlEntityDecode": "htmlEntityDecode",
    "cmdLine": "cmdLine", "normalizePath": "normalizePath", "length": "length",
}
ATTACK_CLASS = {"sqli", "xss", "traversal", "cmdi", "ssrf",
                "credential_stuffing", "user_enumeration", "idor_bola", "scan", "other"}
MECHANISM = {"signature", "input_constraint", "rate_limit"}
METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}

_ID_RE = re.compile(r"^aegis-[a-z0-9_]+-[0-9]+$")


class IRError(ValueError):
    """Raised when IR is invalid. A rejected candidate, never a crash."""


def _safe_text(s, what: str, max_len: int) -> None:
    """Text that will be embedded inside a double-quoted SecRule argument.
    The model is untrusted, so this is the injection boundary: no control
    characters (a newline could start a second directive), no double quote
    (breaks out of the argument), and no odd trailing backslash (escapes the
    closing quote)."""
    s = str(s)
    if len(s) > max_len:
        raise IRError(f"{what} too long")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in s):
        raise IRError(f"{what} contains a control character")
    if '"' in s:
        raise IRError(f"{what} may not contain a double quote")
    if "%{" in s:
        # SecRule operator arguments are macro-expanded (%{REQUEST_HEADERS.x}, %{TX.y}): a value
        # derived from attacker traffic must not read request data back into the rule.
        raise IRError(f"{what} may not contain a macro expansion")
    if any(ch in s for ch in "\u2028\u2029\x85"):
        raise IRError(f"{what} contains a Unicode line separator")
    trailing = len(s) - len(s.rstrip("\\"))
    if trailing % 2 == 1:
        raise IRError(f"{what} ends with an unescaped backslash")


# Constructs Python's `re` accepts but Coraza's engine (Go RE2) does not: lookaround, atomic groups,
# possessive quantifiers, back-references. RE2 is linear-time, which is why the request path can run
# untrusted-length patterns at all (invariant 8); a pattern it cannot compile would be rejected by the
# gateway at reload time and wedge the rule store, so refuse it here.
_NON_RE2_GROUPS = ("(?=", "(?!", "(?<=", "(?<!", "(?>", "(?P=", "(?P>", "(?(")


def _unsupported_by_re2(val: str) -> str | None:
    """Name the first regex construct Go's RE2 lacks, looking only at real syntax: escaped characters
    and the inside of [...] character classes are skipped (`[*+/-]` is not a possessive quantifier)."""
    skel: list[str] = []
    i, n = 0, len(val)
    while i < n:
        c = val[i]
        if c == "\\":
            if i + 1 < n and val[i + 1] in "123456789":
                return "back-reference"
            skel.append("_")
            i += 2
        elif c == "[":
            i += 1
            if i < n and val[i] == "^":
                i += 1
            if i < n and val[i] == "]":      # a leading ] is a literal member
                i += 1
            while i < n and val[i] != "]":
                i += 2 if val[i] == "\\" else 1
            skel.append("C")
            i += 1
        else:
            skel.append(c)
            i += 1
    flat = "".join(skel)
    for g in _NON_RE2_GROUPS:
        if g in flat:
            return f"{g}...)"
    if re.search(r"[*+?}]\+", flat):
        return "possessive quantifier"
    return None


def _check_regex(val: str) -> None:
    try:
        re.compile(val)
    except re.error as e:
        raise IRError(f"match.value is not a valid regex: {e}")
    bad = _unsupported_by_re2(val)
    if bad:
        raise IRError(f"match.value uses {bad}, which the enforcement engine (RE2) does not support")
    if re.search(val, ""):
        raise IRError("match.value matches the empty string, i.e. every request")


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise IRError(msg)


def _in(value, allowed) -> bool:
    """`value in allowed` that is False (not a TypeError) for unhashable values such as lists/dicts."""
    return isinstance(value, str) and value in allowed


def validate(ir: dict) -> None:
    """Raise IRError for anything not on the whitelist. Never any other exception: the IR comes from a
    model, so a wrongly typed field is a rejected candidate, not a crash."""
    try:
        _validate(ir)
    except IRError:
        raise
    except (TypeError, ValueError, AttributeError, KeyError, RecursionError) as e:
        raise IRError(f"malformed IR ({type(e).__name__})") from e


def _validate(ir: dict) -> None:
    _require(isinstance(ir, dict), "IR must be an object")
    _require(isinstance(ir.get("id"), str) and bool(_ID_RE.fullmatch(ir["id"])),
             "id must match aegis-<campaign>-<n>")
    _require(_in(ir.get("attack_class"), ATTACK_CLASS), f"bad attack_class: {ir.get('attack_class')}")
    _require(_in(ir.get("mechanism"), MECHANISM), f"bad mechanism: {ir.get('mechanism')}")
    _require(ir.get("action") == "block", "action must be 'block'")

    ttl = ir.get("ttl_s", 86400)
    _require(isinstance(ttl, int) and not isinstance(ttl, bool) and 60 <= ttl <= 2592000, "ttl_s out of range")

    sc = ir.get("scope", {})
    _require(isinstance(sc, dict), "scope must be an object")
    if "endpoint_prefix" in sc:
        _require(isinstance(sc["endpoint_prefix"], str) and len(sc["endpoint_prefix"]) <= 200,
                 "bad endpoint_prefix")
        _safe_text(sc["endpoint_prefix"], "endpoint_prefix", 200)
    methods = sc.get("methods", [])
    _require(isinstance(methods, list), "scope.methods must be a list")
    for meth in methods:
        _require(_in(meth, METHODS), f"bad method: {meth!r}")

    # Rate-limit rules are stateful and have no payload match; validate the rate
    # block and the (required) scope instead, then return.
    if ir["mechanism"] == "rate_limit":
        rate = ir.get("rate")
        _require(isinstance(rate, dict), "rate_limit needs a rate block")
        _require(isinstance(rate.get("count"), int) and not isinstance(rate["count"], bool)
                 and rate["count"] >= 1, "rate.count >= 1")
        _require(isinstance(rate.get("window_s"), int) and not isinstance(rate["window_s"], bool)
                 and rate["window_s"] >= 1, "rate.window_s >= 1")
        _require(_in(ir.get("key", "actor"), ("actor", "account")), "rate_limit key must be 'actor' or 'account'")
        _require(bool(sc.get("endpoint_prefix")), "rate_limit needs scope.endpoint_prefix")
        return

    m = ir.get("match")
    _require(isinstance(m, dict), "match required")
    _require(_in(m.get("target"), TARGET), f"bad target: {m.get('target')!r}")
    _require(_in(m.get("operator"), OPERATOR), f"bad operator: {m.get('operator')!r}")
    val = m.get("value")
    _require(isinstance(val, (str, int)) and not isinstance(val, bool), "match.value must be a string or integer")
    _require(len(str(val)) <= 500, "match.value too long")
    transforms = m.get("transformations", [])
    _require(isinstance(transforms, list), "match.transformations must be a list")
    for t in transforms:
        _require(_in(t, TRANSFORM), f"bad transformation: {t!r}")
    if m["operator"] == "rx":
        _check_regex(str(val))
    if m["operator"] in ("gt", "ge"):
        _require(str(val).lstrip("-").isdigit(), "gt/ge value must be numeric")

    # Injection boundary for the model-written value (see _safe_text).
    _safe_text(val, "match.value", 500)


def compile_rate(ir: dict) -> dict:
    """Compile a validated rate_limit IR to the gateway-native rate-rule spec
    (NOT a SecRule -- rate limiting is stateful, enforced by the gateway's
    per-actor sliding-window limiter, keyed on the session fingerprint)."""
    validate(ir)
    _require(ir["mechanism"] == "rate_limit", "compile_rate is only for rate_limit")
    sc = ir.get("scope", {})
    return {
        "id": ir["id"], "numeric_id": numeric_id(ir), "attack_class": ir["attack_class"],
        "endpoint_prefix": sc["endpoint_prefix"],
        "methods": sc.get("methods") or ["GET", "POST", "PUT", "DELETE", "PATCH"],
        "count": ir["rate"]["count"], "window_s": ir["rate"]["window_s"],
        "key": ir.get("key", "actor"),
        "ttl_s": ir.get("ttl_s", 86400),
        "description": ir.get("description", f"rate-limit {ir['attack_class']}"),
    }


def numeric_id(ir: dict) -> int:
    """Deterministic numeric id in 100000-199999 from the IR id string.
    Uses a stable hash (not Python's randomized hash()) so a rule keeps its id
    across runs and processes."""
    import hashlib
    h = int(hashlib.md5(ir["id"].encode()).hexdigest()[:8], 16)
    return 100000 + (h % 90000)


def _esc(s: str) -> str:
    # SecRule operator args are double-quoted and we already forbid embedded
    # double quotes (see validate), so the value is emitted verbatim. Do NOT
    # escape backslashes: that would corrupt regex metacharacters (\s, \d, \b).
    return str(s)


def compile_rule(ir: dict, deny: bool = True, numeric: int | None = None) -> str:
    """Compile validated IR to a Coraza SecRule string.

    deny=True  : the rule itself denies (403). Used by the gate's replay tool,
                 which tests one rule in isolation.
    deny=False : the rule only matches and logs (`pass`). Used for the gateway
                 manifest, where the GATEWAY decides per rule mode
                 (off/shadow/canary/enforce) whether a match blocks.
    Either way the rule carries tag aegis-rule:<id> so a match is attributable.

    numeric: the Coraza id to use instead of the id derived from the IR id. The derived ids are a
    90,000-slot hash, so two different rules can share one (89 collisions among 3,990 plausible ids)
    and Coraza refuses a ruleset with a duplicate id; the rule store passes a free one."""
    validate(ir)
    if ir["mechanism"] == "rate_limit":
        raise IRError("rate_limit compilation is deferred to M2b; "
                      "use signature/input_constraint for now")

    rid = numeric_id(ir) if numeric is None else numeric
    if not 100000 <= rid <= 199999:
        raise IRError(f"numeric id {rid} outside the AEGIS range 100000-199999")
    m = ir["match"]
    target = TARGET[m["target"]]
    op = OPERATOR[m["operator"]]
    val = _esc(m["value"])
    # detectSQLi/detectXSS take no argument.
    op_arg = op if m["operator"] in ("detectSQLi", "detectXSS") else f'{op} {val}'
    transforms = m.get("transformations") or ["none"]
    t_actions = ",".join(f"t:{TRANSFORM[t]}" for t in transforms)
    # msg is built only from validated fields; the free-text `description` (which
    # a model may write) is kept in the manifest/memory but never put in the rule.
    msg = f"AEGIS {ir['attack_class']} rule {ir['id']}"

    disposition = "deny,status:403" if deny else "pass"
    base_actions = (f"id:{rid},phase:2,{disposition},log,"
                    f"msg:'{msg}',tag:'aegis',tag:'aegis/{ir['attack_class']}',"
                    f"tag:'aegis-rule:{ir['id']}',{t_actions}")

    sc = ir.get("scope", {})
    chain_conditions = []
    if sc.get("endpoint_prefix"):
        chain_conditions.append(("REQUEST_URI", f'@beginsWith {sc["endpoint_prefix"]}'))
    if sc.get("methods"):
        chain_conditions.append(("REQUEST_METHOD", f'@pm {" ".join(sc["methods"])}'))

    if not chain_conditions:
        return f'SecRule {target} "{op_arg}" "{base_actions}"\n'

    # Chain: first line carries the action + chain; inner lines carry conditions;
    # the final line is the actual match.
    lines = []
    first_t, first_op = chain_conditions[0]
    lines.append(f'SecRule {first_t} "{first_op}" "{base_actions},chain"')
    for t, o in chain_conditions[1:]:
        lines.append(f'    SecRule {t} "{o}" "t:none,chain"')
    lines.append(f'    SecRule {target} "{op_arg}" "{t_actions}"')
    return "\n".join(lines) + "\n"


def compile_file(ir_path: Path) -> str:
    ir = json.loads(ir_path.read_text(encoding="utf-8"))
    return compile_rule(ir)


def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("ir", type=Path, help="IR JSON file")
    p.add_argument("-o", "--out", type=Path, help="write SecRule here (else stdout)")
    args = p.parse_args()
    try:
        rule = compile_file(args.ir)
    except (IRError, json.JSONDecodeError) as e:
        print(f"REJECTED: {e}", file=sys.stderr)
        return 1
    if args.out:
        args.out.write_text(rule, encoding="utf-8")
        print(f"compiled -> {args.out}")
    else:
        sys.stdout.write(rule)
    return 0


if __name__ == "__main__":
    sys.exit(main())
