"""The validation gate -- AEGIS's contribution.

Takes a candidate mitigation (Rule IR) plus the observed attack campaign, and
decides whether it is safe to enforce. A candidate must pass every stage; any
failure rejects it and the reason is logged. No overrides, no fast paths
(invariant 5).

Six stages (CLAUDE.md M2). Implemented here, offline and deterministic:
  1. benign-corpus replay  -> reject if FP rate > 0.01%
  2. attack/campaign replay -> reject if it fails to block the campaign
  4. mutation test          -> reject if it fails to block >= threshold of mutants

Stages that require the live gateway (runtime rule loading via gateway -rules):
  3. app regression suite   -> run eval/smoke.py / journeys with the rule active
  5. shadow mode            -> load in shadow, compare match rate for N minutes
  6. canary + auto-rollback -> enforce on x% with rollback on regression
These are scaffolded (see run_live_stages) and are the next M2 sub-step; a
candidate is only 'promoted' once they pass too. Until then the gate emits
'passed_offline' so nothing is silently enforced.

Replay uses bin/replay.exe -- the real Coraza engine -- so the gate tests
exactly what would enforce.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ir"))
sys.path.insert(0, str(ROOT / "range" / "mutate"))
import compile as irc  # noqa: E402
import mutate as mut   # noqa: E402

REPLAY = ROOT / "bin" / "replay.exe"
FP_BUDGET = 0.0001          # 0.01%
MUTATION_THRESHOLD = 0.80   # must block >= 80% of mutants
DECISIONS_LOG = ROOT / "logs" / "gate" / "decisions.jsonl"


@dataclass
class StageResult:
    stage: str
    passed: bool
    detail: str
    numbers: dict = field(default_factory=dict)


def _replay(rule_file: Path, corpus_file: Path, limit: int = 0) -> dict:
    cmd = [str(REPLAY), "-rule", str(rule_file), "-corpus", str(corpus_file)]
    if limit:
        cmd += ["-limit", str(limit)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"replay failed: {p.stderr.strip()}")
    return json.loads(p.stdout.strip().splitlines()[-1])


def _write_corpus(records: list[dict], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps({"method": r.get("method", "GET"), "uri": r.get("uri", ""),
                                "body": r.get("body", ""),
                                "content_type": r.get("content_type", "application/json")}) + "\n")


def run_gate(ir: dict, campaign_requests: list[dict], benign_corpus: Path,
             tmp: Path) -> tuple[bool, list[StageResult]]:
    results: list[StageResult] = []

    # Stage 0: compile + static validation (IR boundary).
    try:
        rule_text = irc.compile_rule(ir)
    except (irc.IRError, ValueError) as e:
        results.append(StageResult("compile", False, f"IR rejected: {e}"))
        return False, results
    rule_file = tmp / "candidate.conf"
    rule_file.write_text(rule_text, encoding="utf-8")
    results.append(StageResult("compile", True, "IR valid, compiled to SecRule"))

    # Stage 1: benign corpus replay -> FP budget. A rule the ENGINE cannot load
    # (e.g. a model-written regex using lookahead, which Go's RE2 rejects) is a
    # rejected candidate, never a crash.
    try:
        b = _replay(rule_file, benign_corpus)
    except RuntimeError as e:
        results.append(StageResult("engine_load", False, f"engine rejected the rule: {e}"[:300]))
        return False, results
    fp_ok = b["rate"] <= FP_BUDGET
    results.append(StageResult("benign_replay", fp_ok,
        f"FP {b['rate']*100:.4f}% ({b['matched']}/{b['total']}), budget {FP_BUDGET*100:.2f}%",
        {"fp_rate": b["rate"], "matched": b["matched"], "total": b["total"]}))
    if not fp_ok:
        return False, results

    # Stage 2: campaign/attack replay -> must block the observed malicious requests.
    mal = [r for r in campaign_requests if r.get("malicious", True)]
    atk_file = tmp / "campaign.jsonl"
    _write_corpus(mal, atk_file)
    a = _replay(rule_file, atk_file)
    eff_ok = a["rate"] >= 0.999 or a["matched"] == a["total"]
    results.append(StageResult("attack_replay", eff_ok,
        f"blocks {a['rate']*100:.0f}% of campaign ({a['matched']}/{a['total']})",
        {"efficacy": a["rate"], "matched": a["matched"], "total": a["total"]}))
    if not eff_ok:
        return False, results

    # Stage 4: mutation test -> generalisation, not memorisation.
    mutants = mut.mutate_corpus(mal)
    if mutants:
        mut_file = tmp / "mutants.jsonl"
        _write_corpus(mutants, mut_file)
        m = _replay(rule_file, mut_file)
        mut_ok = m["rate"] >= MUTATION_THRESHOLD
        results.append(StageResult("mutation", mut_ok,
            f"blocks {m['rate']*100:.0f}% of {m['total']} mutants, threshold {MUTATION_THRESHOLD*100:.0f}%",
            {"mutation_rate": m["rate"], "matched": m["matched"], "total": m["total"]}))
        if not mut_ok:
            return False, results
    else:
        results.append(StageResult("mutation", True, "no mutants generated (n/a)"))

    # Stages 3/5/6 need the live gateway; not yet run here.
    results.append(StageResult("live_stages", True,
        "regression/shadow/canary NOT YET RUN -- offline stages passed only"))
    return True, results


def log_decision(ir: dict, promoted: bool, results: list[StageResult]) -> None:
    DECISIONS_LOG.parent.mkdir(parents=True, exist_ok=True)
    rec = {
        "id": ir.get("id"), "attack_class": ir.get("attack_class"),
        "mechanism": ir.get("mechanism"),
        "verdict": "passed_offline" if promoted else "rejected",
        "rejected_at": next((r.stage for r in results if not r.passed), None),
        "stages": [{"stage": r.stage, "passed": r.passed, "detail": r.detail,
                    "numbers": r.numbers} for r in results],
    }
    with DECISIONS_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--candidates", type=Path, required=True,
                   help="JSON file: list of candidate IR objects")
    p.add_argument("--campaign", type=Path, required=True,
                   help="JSONL of the observed campaign's attack requests")
    p.add_argument("--benign", type=Path,
                   default=next((ROOT / "data" / "benign_corpus").glob("benign_*detect*.jsonl"), None))
    args = p.parse_args()

    if not REPLAY.exists():
        print("bin/replay.exe missing -- build it: go build -o bin/replay.exe ./gateway/cmd/replay",
              file=sys.stderr)
        return 2
    if args.benign is None or not args.benign.exists():
        print("benign corpus not found in data/benign_corpus/", file=sys.stderr)
        return 2

    candidates = json.loads(args.candidates.read_text(encoding="utf-8"))
    campaign = [json.loads(l) for l in args.campaign.read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"gate: {len(candidates)} candidates | campaign {len(campaign)} requests | "
          f"benign corpus {args.benign.name}\n")

    promoted = None
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for ir in candidates:
            ok, results = run_gate(ir, campaign, args.benign, tmp)
            log_decision(ir, ok, results)
            tag = "PASSED (offline)" if ok else "REJECTED"
            print(f"[{tag}] {ir.get('id')}  ({ir.get('mechanism')})")
            for r in results:
                mark = "  ok " if r.passed else "  XX "
                print(f"{mark}{r.stage:16s} {r.detail}")
            print()
            if ok and promoted is None:
                promoted = ir

    if promoted:
        print(f"==> PROMOTED (offline stages): {promoted['id']}")
        print("    (regression/shadow/canary still required before enforce)")
    else:
        print("==> no candidate passed. Rejections logged to logs/gate/decisions.jsonl")
    return 0


if __name__ == "__main__":
    sys.exit(main())
