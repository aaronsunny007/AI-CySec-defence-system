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
                "credential_stuffing", "user_enumeration", "idor_bola", "scan"}
MECHANISM = {"signature", "input_constraint", "rate_limit"}
METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}

_ID_RE = re.compile(r"^aegis-[a-z0-9_]+-[0-9]+$")


class IRError(ValueError):
    """Raised when IR is invalid. A rejected candidate, never a crash."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise IRError(msg)


def validate(ir: dict) -> None:
    _require(isinstance(ir, dict), "IR must be an object")
    _require(bool(_ID_RE.match(ir.get("id", ""))), "id must match aegis-<campaign>-<n>")
    _require(ir.get("attack_class") in ATTACK_CLASS, f"bad attack_class: {ir.get('attack_class')}")
    _require(ir.get("mechanism") in MECHANISM, f"bad mechanism: {ir.get('mechanism')}")
    _require(ir.get("action") == "block", "action must be 'block'")

    m = ir.get("match")
    _require(isinstance(m, dict), "match required")
    _require(m.get("target") in TARGET, f"bad target: {m.get('target')}")
    _require(m.get("operator") in OPERATOR, f"bad operator: {m.get('operator')}")
    val = m.get("value")
    _require(val is not None, "match.value required")
    _require(len(str(val)) <= 500, "match.value too long")
    for t in m.get("transformations", []):
        _require(t in TRANSFORM, f"bad transformation: {t}")
    if m["operator"] == "rx":
        try:
            re.compile(str(val))
        except re.error as e:
            raise IRError(f"match.value is not a valid regex: {e}")
    if m["operator"] in ("gt", "ge"):
        _require(str(val).lstrip("-").isdigit(), "gt/ge value must be numeric")

    sc = ir.get("scope", {})
    _require(isinstance(sc, dict), "scope must be an object")
    if "endpoint_prefix" in sc:
        _require(isinstance(sc["endpoint_prefix"], str) and len(sc["endpoint_prefix"]) <= 200,
                 "bad endpoint_prefix")
        _require('"' not in sc["endpoint_prefix"], "endpoint_prefix may not contain quotes")
    for meth in sc.get("methods", []):
        _require(meth in METHODS, f"bad method: {meth}")

    ttl = ir.get("ttl_s", 86400)
    _require(isinstance(ttl, int) and 60 <= ttl <= 2592000, "ttl_s out of range")

    if ir["mechanism"] == "rate_limit":
        _require(isinstance(ir.get("rate"), dict), "rate_limit needs a rate block")

    # No quotes in the value that could break out of the SecRule operator arg.
    _require('"' not in str(val), "match.value may not contain a double quote")


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


def compile_rule(ir: dict) -> str:
    """Compile validated IR to a Coraza SecRule string. Call validate() first."""
    validate(ir)
    if ir["mechanism"] == "rate_limit":
        raise IRError("rate_limit compilation is deferred to M2b; "
                      "use signature/input_constraint for now")

    rid = numeric_id(ir)
    m = ir["match"]
    target = TARGET[m["target"]]
    op = OPERATOR[m["operator"]]
    val = _esc(m["value"])
    # detectSQLi/detectXSS take no argument.
    op_arg = op if m["operator"] in ("detectSQLi", "detectXSS") else f'{op} {val}'
    transforms = m.get("transformations") or ["none"]
    t_actions = ",".join(f"t:{TRANSFORM[t]}" for t in transforms)
    msg = (ir.get("description") or f"AEGIS {ir['attack_class']} mitigation").replace("'", "")[:200]

    base_actions = (f"id:{rid},phase:2,deny,status:403,log,"
                    f"msg:'{msg}',tag:'aegis',tag:'aegis/{ir['attack_class']}',{t_actions}")

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
