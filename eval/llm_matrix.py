"""LLM ablation: model x (one-shot vs repair loop) x novel campaigns.

For each combination a FRESH memory database is used, so a rule learned on one
campaign can never generalise onto another and contaminate the comparison. Every
candidate still goes through the full offline gate; "success" means the gate
promoted a rule.

    python eval/llm_matrix.py --models mistral:latest qwen2.5-coder:7b --rounds 1 3

Results are appended to logs/llm_matrix.jsonl as they complete (interrupt-safe)
and summarised at the end. Temperature is 0.1 but the models are not
deterministic, so each cell is ONE sample: read small differences as noise.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("memory", "deliberator", "gate", "ir", "observer"):
    sys.path.insert(0, str(ROOT / p))
from store import Memory          # noqa: E402
from mitigate import mitigate     # noqa: E402
import llm as llm_mod             # noqa: E402

RESULTS = ROOT / "logs" / "llm_matrix.jsonl"
CAMPAIGNS = ["ssti", "nosqli", "xxe", "jndi"]


def done_keys() -> set[tuple]:
    if not RESULTS.exists():
        return set()
    return {(r["model"], r["rounds"], r["campaign"])
            for r in map(json.loads, RESULTS.read_text(encoding="utf-8").splitlines() if RESULTS.exists() else [])
            if r.get("completed")}


def run_one(model: str, rounds: int, campaign: str, benign: Path) -> dict:
    d = json.loads((ROOT / "data" / "attack_corpus" / f"novel_{campaign}.json").read_text(encoding="utf-8"))
    db = ROOT / "memory" / "_matrix.db"
    db.unlink(missing_ok=True)                      # fresh memory per run
    mem = Memory(db)
    t0 = time.time()
    res = mitigate(d["dossier"], d["requests"], benign, mem,
                   llm=llm_mod.OllamaBackend(model), llm_rounds=rounds, max_llm_per_hour=99)
    info = res.get("llm") or {}
    stages: dict[str, int] = {}
    for g in info.get("gate", []):
        if not g["ok"]:
            stages[g["rejected_at"]] = stages.get(g["rejected_at"], 0) + 1
    out = {"model": model, "rounds": rounds, "campaign": campaign,
           "promoted": res["source"] == "llm", "rule": res.get("rule"),
           "promoted_in_round": info.get("promoted_in_round"),
           "candidates_gated": len(info.get("gate", [])), "rejected_at": stages,
           "dropped_invalid": len(info.get("dropped", [])),
           # why candidates were dropped before reaching the gate (reason codes only)
           "dropped_reasons": sorted({d[0] for d in info.get("dropped", [])}),
           "rounds_detail": [{"round": x["round"], "valid": x["valid"],
                              "dropped": [d[0] for d in x["dropped"]],
                              "tokens_in": x["tokens_in"], "tokens_out": x["tokens_out"],
                              "llm_s": x["llm_s"]} for x in info.get("rounds", [])],
           "llm_calls": len(info.get("rounds", [])), "tokens_in": info.get("tokens_in", 0),
           "tokens_out": info.get("tokens_out", 0), "llm_s": info.get("llm_s", 0),
           "wall_s": round(time.time() - t0, 1), "completed": True}
    mem.close()
    db.unlink(missing_ok=True)
    return out


def summarise() -> None:
    rows = [json.loads(l) for l in RESULTS.read_text(encoding="utf-8").splitlines() if l.strip()]
    rows = [r for r in rows if r.get("completed")]
    print("\n=== LLM ablation (one sample per cell; a rule is 'promoted' only if the gate passed it) ===")
    combos = sorted({(r["model"], r["rounds"]) for r in rows})
    camps = sorted({r["campaign"] for r in rows})
    head = f"{'model':24s} {'mode':10s} " + " ".join(f"{c:>8s}" for c in camps) + "   promoted  llm_s  tokens"
    print(head)
    for m, rd in combos:
        cells, ok, secs, toks = [], 0, 0.0, 0
        for c in camps:
            r = next((x for x in rows if (x["model"], x["rounds"], x["campaign"]) == (m, rd, c)), None)
            if r is None:
                cells.append("       -")
                continue
            ok += r["promoted"]
            secs += r["llm_s"]
            toks += r["tokens_in"] + r["tokens_out"]
            cells.append(f"{('R' + str(r['promoted_in_round'])) if r['promoted'] else 'no':>8s}")
        mode = "one-shot" if rd == 1 else f"repair x{rd}"
        print(f"{m:24s} {mode:10s} " + " ".join(cells) + f"   {ok}/{len(camps)}     {secs:5.0f}  {toks}")
    print("\n(R1/R2/R3 = promoted in that round; 'no' = nothing passed the gate)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--models", nargs="+", default=["mistral:latest"])
    ap.add_argument("--rounds", nargs="+", type=int, default=[1, 3])
    ap.add_argument("--campaigns", nargs="+", default=CAMPAIGNS)
    args = ap.parse_args()
    benign = next((ROOT / "data" / "benign_corpus").glob("benign_*detect*.jsonl"))
    RESULTS.parent.mkdir(exist_ok=True)
    seen = done_keys()
    for model in args.models:
        for rounds in args.rounds:
            for camp in args.campaigns:
                if (model, rounds, camp) in seen:
                    print(f"skip (done): {model} rounds={rounds} {camp}")
                    continue
                print(f"run: {model} rounds={rounds} {camp} ...", flush=True)
                r = run_one(model, rounds, camp, benign)
                with RESULTS.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(r) + chr(10))
                print(f"   promoted={r['promoted']} (round {r['promoted_in_round']}) "
                      f"gated={r['candidates_gated']} rejected_at={r['rejected_at']} "
                      f"calls={r['llm_calls']} llm_s={r['llm_s']} wall_s={r['wall_s']}", flush=True)
    summarise()
    return 0


if __name__ == "__main__":
    sys.exit(main())
