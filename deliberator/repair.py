"""Structured gate feedback for the LLM repair loop.

After the gate rejects a model-proposed candidate, the model may be told WHY so it
can try again. The privacy rule is the same as for the first prompt (invariant 4):
the model never sees traffic text. Feedback may contain ONLY
  - the candidate's own fields (the model wrote them),
  - which gate stage failed,
  - numbers (match counts, rates),
  - names from the fixed token vocabulary (llm.VOCAB) with counts,
  - the location class of a payload (path / query / body).
Raw engine error text is NOT forwarded (it could echo arbitrary content); a fixed
message is used instead.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deliberator"))
sys.path.insert(0, str(ROOT / "ir"))
import compile as irc  # noqa: E402
import llm as llm_mod  # noqa: E402

REPLAY = ROOT / "bin" / "replay.exe"
MAX_BENIGN_SAMPLE = 300


def _replay(rule: Path, corpus: Path, indices: int = 0) -> dict:
    cmd = [str(REPLAY), "-rule", str(rule), "-corpus", str(corpus)]
    if indices:
        cmd += ["-indices", str(indices)]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError("replay failed")
    return json.loads(out.stdout.strip().splitlines()[-1])


def token_histogram(records: list[dict]) -> dict[str, int]:
    """Counts, per fixed-vocabulary token class, of how many records contain it."""
    hist: dict[str, int] = {}
    for r in records:
        text = llm_mod._decoded(r)
        for name, rx in llm_mod.VOCAB.items():
            if rx.search(text):
                hist[name] = hist.get(name, 0) + 1
    return dict(sorted(hist.items(), key=lambda kv: -kv[1]))


def _location_counts(records: list[dict]) -> dict[str, int]:
    loc = {"in_path": 0, "in_query": 0, "in_body": 0}
    for r in records:
        path, _, query = (r.get("uri") or "").partition("?")
        if any(rx.search(urllib.parse.unquote(path)) for rx in llm_mod.VOCAB.values()):
            loc["in_path"] += 1
        if query and any(rx.search(urllib.parse.unquote_plus(query)) for rx in llm_mod.VOCAB.values()):
            loc["in_query"] += 1
        if r.get("body") and any(rx.search(r["body"]) for rx in llm_mod.VOCAB.values()):
            loc["in_body"] += 1
    return loc


def _write(records: list[dict], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps({"method": r.get("method", "GET"), "uri": r.get("uri", ""),
                                "body": r.get("body", ""),
                                "content_type": r.get("content_type", "application/json")}) + "\n")


def feedback_for(ir: dict, failed_stage: str, campaign: list[dict], benign_corpus: Path) -> dict:
    """One feedback entry for a rejected candidate. Safe to put in a prompt."""
    m = ir["match"]
    fb: dict = {
        "candidate": {"target": m["target"], "operator": m["operator"], "value": m["value"],
                      "transformations": m.get("transformations", []),
                      "scope": (ir.get("scope") or {}).get("endpoint_prefix")},
        "failed_stage": failed_stage,
    }
    if failed_stage in ("compile", "engine_load"):
        fb["problem"] = ("the rule could not be loaded; use Go RE2 regex syntax (no lookahead, "
                         "lookbehind or backreferences) and valid fields")
        return fb

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        rule = td / "r.conf"
        rule.write_text(irc.compile_rule(ir), encoding="utf-8")
        if failed_stage == "attack_replay":
            mal = [r for r in campaign if r.get("malicious", True)]
            camp = td / "c.jsonl"
            _write(mal, camp)
            res = _replay(rule, camp, indices=100000)
            hit = set(res.get("matched_idx", []))
            missed = [r for i, r in enumerate(mal) if i not in hit]
            fb["campaign_requests_matched"] = f"{res['matched']} of {res['total']}"
            fb["missed_token_classes"] = token_histogram(missed)
            fb["missed_payload_location"] = _location_counts(missed)
        elif failed_stage == "benign_replay":
            res = _replay(rule, benign_corpus, indices=MAX_BENIGN_SAMPLE)
            want = set(res.get("matched_idx", []))
            sample: list[dict] = []
            n = -1
            with benign_corpus.open(encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    n += 1
                    if n in want:
                        try:
                            sample.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
                    if n >= max(want, default=-1):
                        break
            fb["benign_traffic_matched"] = f"{res['matched']} of {res['total']}"
            fb["benign_false_positive_rate_pct"] = round(res["rate"] * 100, 4)
            fb["allowed_false_positive_rate_pct"] = 0.01
            fb["token_classes_in_matched_benign_requests"] = token_histogram(sample)
        elif failed_stage == "mutation":
            fb["problem"] = "blocked too few re-encoded / re-cased variants of the campaign; generalise the technique"
        else:
            fb["problem"] = f"failed stage {failed_stage}"
    return fb
