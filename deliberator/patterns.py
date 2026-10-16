"""Pattern-library interface to the LLM (queue item D).

In the free-form interface (llm.propose) the model WRITES a regex. In this one it only
CHOOSES, from fixed vocabularies:

  tokens        1-3 names from llm.VOCAB (the same vetted token classes it is shown counts of)
  location      one of path | query | body | any
  endpoint      optional, one of the endpoint shapes it was shown (or "none")
  attack_class  one of the IR attack classes

We compile the regex ourselves from the library, so the model can no longer emit an invalid
or hostile expression; it can still pick a useless or over-broad combination, which the SAME
gate rejects. It gains no authority (invariant 3); no traffic text reaches the prompt
(invariant 4; the feature summary is llm.extract_features).
"""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ir"))
sys.path.insert(0, str(ROOT / "deliberator"))
import compile as irc  # noqa: E402
import llm  # noqa: E402

LOCATION_TARGET = {"path": "path", "query": "args", "body": "body", "any": "args_and_body"}
MAX_TOKENS_PER_RULE = 3

SYSTEM = (
    "You are a web application firewall rule designer. You receive a JSON summary of an "
    "attack campaign (counts of named token classes, never raw traffic). You do NOT write "
    "regexes: you choose from a fixed library of named token classes and say where they "
    "occur. Rules are TESTED against real legitimate traffic and thrown away if they match "
    "normal user input, so prefer the rarest class that covers the campaign, and combine "
    "classes only when no single one covers it. Output JSON only."
)


def library() -> list[str]:
    return sorted(llm.VOCAB)


def to_ir(tokens: list[str], location: str, endpoint: str | None, attack_class: str,
          tag: str, i: int) -> dict:
    """Deterministic compile of a choice into IR. Raises ValueError on any bad choice."""
    if not tokens or len(tokens) > MAX_TOKENS_PER_RULE or len(set(tokens)) != len(tokens):
        raise ValueError("token list must be 1-3 distinct names")
    for t in tokens:
        if t not in llm.VOCAB:
            raise ValueError("unknown token class")
    if location not in LOCATION_TARGET:
        raise ValueError("bad location")
    if attack_class not in irc.ATTACK_CLASS:
        raise ValueError("bad attack_class")
    parts = [llm.VOCAB[t].pattern for t in tokens]
    value = "(?i)(?:" + "|".join(f"(?:{p})" for p in parts) + ")"
    ir = {"id": f"aegis-pat{tag}-{i}", "action": "block", "ttl_s": 86400,
          "attack_class": attack_class, "mechanism": "signature",
          "description": "pattern-library rule: " + "+".join(tokens) + " in " + location,
          "match": {"target": LOCATION_TARGET[location], "operator": "rx", "value": value,
                    "transformations": ["urlDecodeUni"]}}
    if endpoint:
        ir["scope"] = {"endpoint_prefix": endpoint}
    return ir


def _schema(endpoints: list[str]) -> dict:
    cand = {
        "type": "object", "required": ["attack_class", "tokens", "location"],
        "properties": {
            "attack_class": {"enum": sorted(irc.ATTACK_CLASS)},
            "tokens": {"type": "array", "minItems": 1, "maxItems": MAX_TOKENS_PER_RULE,
                       "items": {"enum": library()}},
            "location": {"enum": sorted(LOCATION_TARGET)},
            "endpoint": {"enum": endpoints + ["none"]},
        },
    }
    return {"type": "object", "required": ["candidates"],
            "properties": {"candidates": {"type": "array", "minItems": 1,
                                          "maxItems": llm.MAX_CANDIDATES, "items": cand}}}


def build_prompt(features: dict, feedback: list[dict] | None = None) -> str:
    fb = ""
    if feedback:
        fb = ("\n\nPREVIOUS ATTEMPTS were tested and rejected (machine-computed verdicts):\n"
              + json.dumps(feedback[-6:], indent=2, sort_keys=True)
              + "\nDo not repeat a rejected combination.")
    return (
        "Campaign summary (machine-computed counts and labels):\n"
        + json.dumps(features, indent=2, sort_keys=True) + fb
        + "\n\nPropose 3 to 5 candidates, each choosing:\n"
        f"  tokens: 1-{MAX_TOKENS_PER_RULE} names from {library()}\n"
        f"  location: one of {sorted(LOCATION_TARGET)}  (where the payload occurs)\n"
        '  endpoint: one of endpoint_shapes, or "none"\n'
        f"  attack_class: one of {sorted(irc.ATTACK_CLASS)}\n"
        'Respond as {"candidates": [ ... ]}.'
    )


def propose(dossier: dict, requests: list[dict], backend, routes=None,
            feedback: list[dict] | None = None) -> llm.Proposal:
    known = llm._routes(routes)
    feats = llm.extract_features(dossier, requests, known)
    out = llm.Proposal(features=feats)
    endpoints = list(feats.get("endpoint_shapes", []))
    try:
        resp = backend.complete(SYSTEM, build_prompt(feats, feedback), _schema(endpoints))
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        out.rejected.append(("backend_error", str(e)[:120]))
        return out
    out.response = resp
    try:
        raw = json.loads(resp.text)["candidates"]
        if not isinstance(raw, list):
            raise ValueError("candidates is not a list")
    except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        out.rejected.append(("unparseable_output", f"{type(e).__name__}: {str(e)[:80]}"))
        return out
    tag = hashlib.sha256(json.dumps([feats, feedback or []], sort_keys=True).encode()).hexdigest()[:6]
    seen: set = set()
    for i, c in enumerate(raw[:llm.MAX_CANDIDATES], 1):
        if not isinstance(c, dict) or not isinstance(c.get("tokens"), list):
            out.rejected.append(("not_an_object", ""))
            continue
        ep = c.get("endpoint")
        ep = None if ep in (None, "", "none") else ep
        if ep is not None and ep not in endpoints:
            out.rejected.append(("endpoint_not_offered", str(ep)[:60]))
            continue
        try:
            ir = to_ir([str(t) for t in c["tokens"]], str(c.get("location")), ep,
                       str(c.get("attack_class")), tag, i)
            irc.validate(ir)
            irc.compile_rule(ir)
        except (ValueError, irc.IRError, TypeError, KeyError) as e:
            out.rejected.append(("invalid_choice", str(e)[:100]))
            continue
        key = json.dumps([sorted(c["tokens"]), ir["match"]["target"], ep])
        if key in seen:
            out.rejected.append(("duplicate", ""))
            continue
        seen.add(key)
        out.candidates.append(ir)
    return out
