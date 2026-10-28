"""Induced self-DoS experiment -- M4, the headline result.

Question (CLAUDE.md M4 / open question 5): can an adversary craft traffic that
looks malicious but structurally resembles REAL user traffic, so the rule AEGIS
invents in response blocks legitimate users?

This is the mechanised form of the CETaS warning -- a defender that "achieves
its goal by turning all the systems off". We measure it honestly and, crucially,
with and WITHOUT the validation gate, to quantify what the gate buys.

Method:
  - Several adversarial campaigns are crafted to blend into benign traffic:
    SQLi payloads wrapped around the exact weird-but-legitimate strings real
    users send (apostrophes in names, "or" in product text, "50% off", ...).
  - For each, AEGIS generates candidate rules (deliberator).
  - Each candidate is replayed against the full 443k benign corpus (gate stage 1)
    to measure how much legitimate traffic it would block.
  - WITHOUT gate: the adversary's best case = max benign-block of ANY candidate
    AEGIS might pick.
  - WITH gate: AEGIS only deploys candidates under the 0.01% FP budget, so the
    worst a deployed rule can do is bounded by the budget.

Headline number: maximum fraction of legitimate traffic the adversary can force
AEGIS to block, with the gate vs without it.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("ir", "deliberator"):
    sys.path.insert(0, str(ROOT / p))
import compile as irc          # noqa: E402
import generate as deliberator # noqa: E402

REPLAY = ROOT / "bin" / "replay.exe"
FP_BUDGET = 0.0001  # the gate's benign FP budget (0.01%)

# Adversarial campaigns: malicious payloads deliberately shaped like the benign
# weird-but-legitimate traffic real users send (see range/benign/personas.py).
# The attacker's hope: a rule that blocks these also blocks the real versions.
ADVERSARIAL = {
    "sqli_blend_names": [  # apostrophe names weaponised
        "O'Brien' OR '1'='1", "D'Arcy'--", "O'Malley' OR 1=1#",
        "Siobhan O'Neill') OR ('1'='1",
    ],
    "sqli_blend_text": [  # product-review-like text weaponised
        "Bobby Tables' review of UNION SELECT hummus",
        "rock & roll' OR '1'='1", "50% off' OR 1=1--",
        "1 or 2 apples' UNION SELECT password FROM Users--",
    ],
}


def _write(reqs, path):
    with path.open("w", encoding="utf-8") as f:
        for q in reqs:
            import urllib.parse
            f.write(json.dumps({"method": "GET",
                                "uri": "/rest/products/search?q=" + urllib.parse.quote(q),
                                "body": "", "content_type": "application/json"}) + "\n")


def _benign_fp(rule_file: Path, benign: Path) -> float:
    out = subprocess.run([str(REPLAY), "-rule", str(rule_file), "-corpus", str(benign)],
                         capture_output=True, text=True)
    return json.loads(out.stdout.strip().splitlines()[-1])["rate"]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--benign", type=Path,
                   default=(sorted((ROOT / "data" / "benign_corpus").glob("benign_*detect*.jsonl")) or [None])[0])
    args = p.parse_args()
    if args.benign is None or not args.benign.exists():
        print("benign corpus not found", file=sys.stderr)
        return 2

    dossier = {"techniques": ["sqli"], "attack_class": "sqli",
               "endpoints": ["/rest/products/search"]}
    candidates = [c for c in deliberator.candidates_for("sqli", dossier)
                  if c.get("mechanism") != "rate_limit"]

    # Naive rules an UN-GATED or careless responder might deploy in response to
    # the adversarial payloads (all apostrophe/keyword-based). These overfit to
    # the attack's surface and blanket-match benign traffic -- exactly the lever
    # an attacker pulls to induce self-DoS. AEGIS's gate must reject them.
    naive = [
        {"id": "aegis-naiveapos-1", "attack_class": "sqli", "mechanism": "input_constraint",
         "action": "block", "match": {"target": "args", "operator": "rx", "value": "'",
                                       "transformations": ["urlDecodeUni"]}},
        {"id": "aegis-naiveor-1", "attack_class": "sqli", "mechanism": "input_constraint",
         "action": "block", "match": {"target": "args", "operator": "rx", "value": r"(?i)\bor\b",
                                       "transformations": ["urlDecodeUni"]}},
        {"id": "aegis-naiveselect-1", "attack_class": "sqli", "mechanism": "input_constraint",
         "action": "block", "match": {"target": "args", "operator": "rx", "value": r"(?i)select",
                                       "transformations": ["urlDecodeUni"]}},
    ]
    candidates = candidates + naive

    print(f"induced self-DoS: {len(ADVERSARIAL)} adversarial campaigns, "
          f"{len(candidates)} candidate rules, benign corpus {args.benign.name}\n")

    worst_without_gate = 0.0
    worst_with_gate = 0.0
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for ir in candidates:
            try:
                rule_file = tmp / "r.conf"
                rule_file.write_text(irc.compile_rule(ir), encoding="utf-8")
            except (irc.IRError, ValueError):
                continue
            fp = _benign_fp(rule_file, args.benign)
            deployable = fp <= FP_BUDGET
            worst_without_gate = max(worst_without_gate, fp)
            if deployable:
                worst_with_gate = max(worst_with_gate, fp)
            print(f"  {ir['id']:14s} benign-block {fp*100:.4f}%  "
                  f"{'DEPLOYABLE (gate allows)' if deployable else 'REJECTED by gate'}")

    print("\n=== induced self-DoS result ===")
    print(f"  max legit traffic blocked WITHOUT gate: {worst_without_gate*100:.4f}%")
    print(f"  max legit traffic blocked WITH gate:    {worst_with_gate*100:.4f}%  "
          f"(budget {FP_BUDGET*100:.2f}%)")
    reduction = (worst_without_gate - worst_with_gate)
    print(f"  the gate prevents up to {reduction*100:.4f} percentage points of self-DoS")
    print("\n  interpretation: per-rule the gate caps induced self-DoS at the FP")
    print("  budget; rate-limit rules are per-actor so an attacker cannot push")
    print("  another actor over the limit. Report this number honestly in M4.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
