"""LLM deliberator: the LAST-RESORT path for campaigns templates do not cover.

Invariants this module is built around (CLAUDE.md section 2):
  3. The LLM is unprivileged. It proposes typed Rule IR; ir/compile.py validates
     it and the gate tests it. Its output is never executed or deployed
     directly, and it never writes enforcement syntax.
  4. Traffic is data, never instruction. The model is NEVER shown raw request
     text. It sees a FIXED-VOCABULARY feature summary computed by this module:
     counts of how often each named token class appears, sanitised endpoint
     shapes, status mix. A payload that says "ignore previous instructions" has
     nowhere to land: no free text from traffic reaches the prompt.
  7. Hard budgets: wall-clock timeout, output-token cap, candidate cap, and a
     calls-per-hour cap (enforced by the caller via the memory store).
  9. Last resort. memory/mitigate.py only calls this when templates produced no
     promotable rule.

Backends are swappable (OllamaBackend for local models; MockBackend for tests;
an API backend can be added for a local-vs-frontier ablation).
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ir"))
import compile as irc  # noqa: E402

MAX_CANDIDATES = 5
MAX_OUTPUT_TOKENS = 1400
TIMEOUT_S = 240

# --- fixed vocabulary: the ONLY things about traffic the model ever sees -------
# name -> regex over the decoded path+query+body of a malicious request. Gaps are bounded ({0,N}), never
# `.*?`: a lazy gap before a closer that never comes is quadratic (a few KB of "{{" cost seconds).
VOCAB: dict[str, re.Pattern] = {k: re.compile(v, re.I) for k, v in {
    "sql_union_select": r"union(\s|/\*.{0,100}?\*/)+select",
    "sql_quote_then_keyword": r"'\s*(or|and)\b",
    "sql_comment_marker": r"(--|#|/\*)",
    "script_tag": r"<\s*script",
    "event_handler_attr": r"\bon[a-z]+\s*=",
    "dot_dot_slash": r"\.\.[/\\]",
    "etc_passwd": r"/etc/passwd",
    "null_byte": r"(%00|\x00)",
    "shell_separator": r"(;|\|\||&&|\|)\s*\w+",
    "command_substitution": r"(\$\(|`)",
    "internal_host_url": r"(127\.0\.0\.1|localhost|169\.254\.169\.254|\[::1\])",
    "url_scheme": r"\b(https?|file|gopher|ftp|ldap|jndi)\s*:",
    "nosql_operator": r"\$(ne|gt|lt|gte|lte|regex|where|or|and|in|nin|exists)\b",
    "template_double_brace": r"\{\{.{0,200}?\}\}",
    "template_dollar_brace": r"\$\{.{0,200}?\}",
    "template_percent_tag": r"<%.{0,200}?%>",
    "template_hash_brace": r"#\{.{0,200}?\}",
    "xml_entity_decl": r"<!(entity|doctype)",
    "ldap_or_jndi_ref": r"(jndi|ldap)",
    "angle_brackets": r"[<>]",
    "single_quote": r"'",
    "percent_encoding": r"%[0-9a-f]{2}",
    "double_percent_encoding": r"%25[0-9a-f]{2}",
    "very_long_value": r"[^\s]{200,}",
    "arithmetic_probe": r"\b\d+\s*[*+/-]\s*\d+\b",
}.items()}

_PATH_OK = re.compile(r"^[A-Za-z0-9/_{}.\-]{1,100}$")


_MAX_SCAN = 32 * 1024      # same bound as observer/detector.py: patterns never scan unbounded attacker text


def _decoded(rec: dict) -> str:
    uri = rec.get("uri", "") or ""
    path, _, query = uri.partition("?")
    raw = path + " " + query + " " + (rec.get("body", "") or "")
    if len(raw) > _MAX_SCAN:
        raw = raw[:24 * 1024] + " " + raw[-8 * 1024:]
    text = urllib.parse.unquote_plus(raw)
    return text if len(text) <= _MAX_SCAN else text[:24 * 1024] + " " + text[-8 * 1024:]


def _routes(routes):
    if routes is not None:
        return set(routes)
    sys.path.insert(0, str(ROOT / "observer"))
    from routes import known_routes
    return known_routes()


def extract_features(dossier: dict, requests: list[dict], routes=None) -> dict:
    """Fixed-field summary of a campaign. Contains no free text from traffic.

    Endpoint shapes are shown ONLY if they are known application routes (seen
    often in benign traffic). The path is attacker-controlled, so a path such as
    /IGNORE-PREVIOUS-INSTRUCTIONS would otherwise pass a character whitelist and
    reach the prompt; unknown paths are merely counted."""
    known = _routes(routes)
    mal = [r for r in requests if r.get("malicious", True)]
    tokens = {name: 0 for name in VOCAB}
    for r in mal:
        text = _decoded(r)
        for name, rx in VOCAB.items():
            if rx.search(text):
                tokens[name] += 1
    tokens = {k: v for k, v in tokens.items() if v}

    shapes, unknown = [], 0
    for e in dossier.get("endpoints", []):
        if e in ("/", "") or (e or "").startswith("/socket.io"):
            continue
        if _PATH_OK.match(e or "") and e in known:
            shapes.append(e)
        else:
            unknown += 1
    where = {"in_path": 0, "in_query": 0, "in_body": 0}
    for r in mal:
        path, _, query = (r.get("uri") or "").partition("?")
        if any(rx.search(urllib.parse.unquote(path)) for rx in VOCAB.values()):
            where["in_path"] += 1
        if query and any(rx.search(urllib.parse.unquote_plus(query)) for rx in VOCAB.values()):
            where["in_query"] += 1
        if r.get("body") and any(rx.search(r["body"]) for rx in VOCAB.values()):
            where["in_body"] += 1
    methods: dict[str, int] = {}
    for r in mal:
        m = r.get("method", "GET")
        if m in ("GET", "POST", "PUT", "DELETE", "PATCH"):
            methods[m] = methods.get(m, 0) + 1
    return {
        "malicious_requests": len(mal),
        "token_classes_seen": tokens,
        "payload_location": where,
        "methods": methods,
        "endpoint_shapes": shapes[:8],
        "unknown_endpoint_count": unknown,
        "recognised_family": dossier.get("techniques", ["unknown"])[0]
        if dossier.get("techniques") and dossier["techniques"][0] != "other" else "unknown",
    }


# --- prompt ---------------------------------------------------------------------

SYSTEM = (
    "You are a web application firewall rule designer. You receive a JSON summary of "
    "an attack campaign (counts of named token classes, never raw traffic) and you "
    "propose candidate blocking rules as JSON in the exact schema requested. "
    "Rules are TESTED against real legitimate traffic before use, so a rule that "
    "matches normal user input will be thrown away: target the TECHNIQUE, not one "
    "literal payload, and keep rules as narrow as the evidence allows. "
    "Regexes use Go RE2 syntax: NO lookahead, lookbehind or backreferences. "
    "Output JSON only."
)


def build_prompt(features: dict, feedback: list[dict] | None = None) -> str:
    targets = sorted(irc.TARGET)
    ops = [o for o in sorted(irc.OPERATOR) if o not in ("gt", "ge", "streq")]
    transforms = sorted(irc.TRANSFORM)
    fb = ""
    if feedback:
        # Built by deliberator/repair.py: candidate fields the model itself wrote,
        # stage names, numbers and fixed-vocabulary token-class names ONLY.
        fb = (
            "\n\nPREVIOUS ATTEMPTS were tested and rejected. For each, the verdict below is "
            "machine-computed; the numbers and token-class names are the only facts you "
            "get about the traffic:\n" + json.dumps(feedback[-6:], indent=2, sort_keys=True)
            + "\n\nRevise: propose NEW candidates that fix these failures. Do not repeat a "
            "failed candidate. If a rule matched too little of the campaign, target the "
            "missed token classes at the stated location (path/query/body) and pick a "
            "target that covers it. If a rule matched legitimate traffic, make it narrower "
            "so it cannot match the listed benign token classes on their own."
        )
    return (
        "Campaign summary (all fields are machine-computed counts and labels):\n"
        + json.dumps(features, indent=2, sort_keys=True)
        + fb
        + "\n\nPropose 3 to 5 candidate rules spanning different specificity (one broad, "
        "one scoped to an endpoint, one stricter). Each candidate is an object with:\n"
        f'  attack_class: one of {sorted(irc.ATTACK_CLASS)}\n'
        '  mechanism: "signature" or "input_constraint"\n'
        '  action: "block"\n'
        '  description: one short sentence\n'
        '  scope: optional {"endpoint_prefix": "<one of endpoint_shapes>"}\n'
        f'  match.target: one of {targets}\n'
        f'  match.operator: one of {ops}\n'
        "  match.value: the regex (for rx/contains); empty string for detectSQLi/detectXSS\n"
        f'  match.transformations: list from {transforms}\n'
        'Respond as {"candidates": [ ... ]}.'
    )


def _schema() -> dict:
    """JSON schema passed to the backend so output is structurally constrained."""
    cand = {
        "type": "object",
        "required": ["attack_class", "mechanism", "action", "description", "match"],
        "properties": {
            "attack_class": {"enum": sorted(irc.ATTACK_CLASS)},
            "mechanism": {"enum": ["signature", "input_constraint"]},
            "action": {"enum": ["block"]},
            "description": {"type": "string", "maxLength": 200},
            "scope": {"type": "object", "properties": {"endpoint_prefix": {"type": "string"}}},
            "match": {
                "type": "object", "required": ["target", "operator", "value"],
                "properties": {
                    "target": {"enum": sorted(irc.TARGET)},
                    "operator": {"enum": ["rx", "contains", "detectSQLi", "detectXSS"]},
                    "value": {"type": "string", "maxLength": 300},
                    "transformations": {"type": "array", "items": {"enum": sorted(irc.TRANSFORM)}},
                },
            },
        },
    }
    return {"type": "object", "required": ["candidates"],
            "properties": {"candidates": {"type": "array", "minItems": 1,
                                          "maxItems": MAX_CANDIDATES, "items": cand}}}


# --- backends -------------------------------------------------------------------

@dataclass
class LLMResponse:
    text: str
    tokens_in: int = 0
    tokens_out: int = 0
    seconds: float = 0.0
    truncated: bool = False
    model: str = ""


class OllamaBackend:
    def __init__(self, model: str = "mistral:latest", host: str = "http://127.0.0.1:11434"):
        self.model, self.host = model, host

    def complete(self, system: str, prompt: str, schema: dict) -> LLMResponse:
        body = {
            "model": self.model, "stream": False, "format": schema, "keep_alive": "5m",
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": prompt}],
            "options": {"temperature": 0.1, "num_predict": MAX_OUTPUT_TOKENS, "num_ctx": 4096},
        }
        req = urllib.request.Request(self.host + "/api/chat", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            d = json.loads(r.read())
        return LLMResponse(
            text=d.get("message", {}).get("content", ""),
            tokens_in=d.get("prompt_eval_count", 0), tokens_out=d.get("eval_count", 0),
            seconds=time.time() - t0, truncated=d.get("done_reason") == "length",
            model=self.model)


class MockBackend:
    """Returns canned text. Used for tests, including hostile outputs."""
    def __init__(self, text: str):
        self.text, self.seen_prompt = text, ""

    def complete(self, system: str, prompt: str, schema: dict) -> LLMResponse:
        self.seen_prompt = system + "\n" + prompt
        return LLMResponse(text=self.text, model="mock")


def _scope_ok(prefix: str, known: set[str]) -> bool:
    """A model-proposed endpoint_prefix is acceptable only if it is a known
    route, or the part of one before an {id} segment (e.g. /api/BasketItems)."""
    allowed = set(known)
    allowed |= {k.split("{")[0] for k in known}
    allowed |= {a.rstrip("/") for a in list(allowed)}
    return prefix in allowed or prefix.rstrip("/") in allowed


# --- proposal -------------------------------------------------------------------

@dataclass
class Proposal:
    candidates: list[dict] = field(default_factory=list)
    rejected: list[tuple[str, str]] = field(default_factory=list)  # (why, brief)
    response: LLMResponse | None = None
    features: dict = field(default_factory=dict)


def propose(dossier: dict, requests: list[dict], backend, routes=None,
            feedback: list[dict] | None = None) -> Proposal:
    """Ask the model for candidates. Everything it returns is validated by the
    IR compiler; anything invalid is dropped and recorded, never repaired."""
    known = _routes(routes)
    feats = extract_features(dossier, requests, known)
    out = Proposal(features=feats)
    try:
        resp = backend.complete(SYSTEM, build_prompt(feats, feedback), _schema())
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        out.rejected.append(("backend_error", str(e)[:120]))
        return out
    out.response = resp
    try:
        data = json.loads(resp.text)
        raw = data["candidates"]
        if not isinstance(raw, list):
            raise ValueError("candidates is not a list")
    except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        out.rejected.append(("unparseable_output", f"{type(e).__name__}: {str(e)[:80]}"))
        return out

    tag = hashlib.sha256(json.dumps([feats, feedback or []], sort_keys=True).encode()).hexdigest()[:6]
    for i, c in enumerate(raw[:MAX_CANDIDATES], 1):
        if not isinstance(c, dict):
            out.rejected.append(("not_an_object", ""))
            continue
        # Invalid output is DROPPED, never repaired: silently coercing a bad
        # field would hide a misbehaving (or hostile) model. An action other
        # than "block" -- e.g. an attempt to emit "allow" -- is surfaced.
        if c.get("action") != "block":
            out.rejected.append(("bad_action", str(c.get("action"))[:30]))
            continue
        if c.get("attack_class") not in irc.ATTACK_CLASS:
            out.rejected.append(("bad_attack_class", str(c.get("attack_class"))[:30]))
            continue
        if c.get("mechanism") not in ("signature", "input_constraint"):
            out.rejected.append(("bad_mechanism", str(c.get("mechanism"))[:30]))
            continue
        # The model never names its own rule: id and ttl are ours.
        ir = {
            "id": f"aegis-llm{tag}-{i}", "action": "block", "ttl_s": 86400,
            "attack_class": c["attack_class"], "mechanism": c["mechanism"],
            "description": str(c.get("description", ""))[:200],
            "match": c.get("match"),
        }
        sc = c.get("scope")
        if isinstance(sc, dict) and isinstance(sc.get("endpoint_prefix"), str):
            # A scope the model invents (not a known route) is rejected, not
            # silently widened: narrowing is a safety property of the rule.
            if not _scope_ok(sc["endpoint_prefix"], known):
                out.rejected.append(("scope_not_a_known_route", sc["endpoint_prefix"][:60]))
                continue
            ir["scope"] = {"endpoint_prefix": sc["endpoint_prefix"]}
        try:
            irc.validate(ir)
            irc.compile_rule(ir)
        except (irc.IRError, ValueError, TypeError, KeyError) as e:
            out.rejected.append(("invalid_ir", str(e)[:120]))
            continue
        out.candidates.append(ir)
    return out


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dossier", type=Path, required=True)
    ap.add_argument("--campaign", type=Path, required=True)
    ap.add_argument("--model", default="mistral:latest")
    args = ap.parse_args()
    dossier = json.loads(args.dossier.read_text(encoding="utf-8"))
    reqs = [json.loads(l) for l in args.campaign.read_text(encoding="utf-8").splitlines() if l.strip()]
    p = propose(dossier, reqs, OllamaBackend(args.model))
    print("features sent to the model:\n", json.dumps(p.features, indent=2))
    if p.response:
        r = p.response
        print(f"\nmodel={r.model} tokens in/out={r.tokens_in}/{r.tokens_out} {r.seconds:.1f}s truncated={r.truncated}")
    print(f"\n{len(p.candidates)} valid candidate(s), {len(p.rejected)} dropped: {p.rejected}")
    for c in p.candidates:
        print(" ", c["id"], c["mechanism"], c["match"]["target"], c["match"]["operator"], repr(c["match"]["value"])[:90])
    return 0


if __name__ == "__main__":
    sys.exit(main())
