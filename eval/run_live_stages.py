"""Live gate stages 5 and 6 -- experiments.

E1  good rule (aegis-sqli-3)   shadow -> canary -> promoted to enforce
E2  overfit rule (any ')       shadow stage must REJECT it
E3  fault injection            the overfit rule is forced straight into canary,
                               bypassing every earlier stage, to prove stage 6's
                               automatic rollback works on its own. This is a
                               chaos test of the safety net, NOT a promotion path.

All on one range boot (rules change by hot reload). Ground truth (attack UA) is
used only to REPORT harm, never by the stages.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("gate", "deliberator", "ir", "eval"):
    sys.path.insert(0, str(ROOT / p))
import rulestore                      # noqa: E402
import generate as deliberator        # noqa: E402
import live_stages as LS              # noqa: E402
from rangectl import Range            # noqa: E402

OVERFIT = {  # an "any apostrophe" rule: what an overfit/naive responder deploys
    "id": "aegis-naiveapos-1", "attack_class": "sqli", "mechanism": "input_constraint",
    "action": "block", "description": "block any apostrophe in query args (overfit)",
    "match": {"target": "args", "operator": "rx", "value": "'", "transformations": ["urlDecodeUni"]},
}


def show(label: str, res: dict) -> dict:
    print(f"\n== {label}: {'PROMOTED to enforce' if res['promoted'] else 'NOT promoted'}")
    for s in res["stages"]:
        print(f"   [{'PASS' if s.passed else 'FAIL'}] {s.stage}: {s.detail}")
    return {"label": label, "promoted": res["promoted"],
            "stages": [{"stage": s.stage, "passed": s.passed, "detail": s.detail,
                        "numbers": s.numbers} for s in res["stages"]]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--exp", default="e1,e2,e3")
    ap.add_argument("--shadow-s", type=float, default=45)
    ap.add_argument("--canary-s", type=float, default=60)
    ap.add_argument("--pct", type=int, default=25)
    ap.add_argument("--rps", type=float, default=60)
    args = ap.parse_args()
    corpus = next((ROOT / "data" / "benign_corpus").glob("benign_*detect*.jsonl"))
    good = next(c for c in deliberator.candidates_for("sqli", {"endpoints": ["/rest/products/search"]})
                if c["id"] == "aegis-sqli-3")
    exps = args.exp.split(",")
    out = []

    rulestore.clear()
    with Range(mode="enforce"):
        if "e1" in exps:
            res = LS.live_pipeline(good, corpus, "sqli", args.shadow_s, args.canary_s, args.pct)
            out.append(show("E1 good rule", res))
            rulestore.clear(); time.sleep(1)
        if "e2" in exps:
            res = LS.live_pipeline(OVERFIT, corpus, "sqli", args.shadow_s, args.canary_s, args.pct)
            out.append(show("E2 overfit rule via the full pipeline", res))
            rulestore.clear(); time.sleep(1)
        if "e3" in exps:
            res = LS.live_pipeline(OVERFIT, corpus, "sqli", args.shadow_s, args.canary_s,
                                   args.pct, skip_shadow=True)
            out.append(show("E3 fault injection: overfit rule straight into canary", res))
            rulestore.clear()
    p = ROOT / "logs" / "live_stages_summary.json"
    p.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nsummary -> {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
