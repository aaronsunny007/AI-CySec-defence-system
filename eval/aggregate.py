"""Aggregate replicate end-to-end runs into mean / sd / range / 95% CI tables.

    python eval/aggregate.py logs/rep/e2e_*.json  --title "Juice Shop"
    python eval/aggregate.py logs/rep/app2_*.json --title "BookNook"

A run that never enforced a rule is counted as a failure (reported as k/n enforced), not
dropped and not averaged in as zero. Intervals are Student-t on the runs that DID enforce, so
they are wide for small n; with n < 3 only the range is meaningful.
"""

from __future__ import annotations

import json
import math
import statistics
import sys
from pathlib import Path

T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262}


def stats(xs: list[float]) -> dict:
    n = len(xs)
    if n == 0:
        return {"n": 0}
    m = statistics.mean(xs)
    out = {"n": n, "mean": round(m, 1), "min": round(min(xs), 1), "max": round(max(xs), 1)}
    if n >= 2:
        sd = statistics.stdev(xs)
        h = T95.get(n - 1, 1.96) * sd / math.sqrt(n)
        out.update(sd=round(sd, 1), ci95=[round(m - h, 1), round(m + h, 1)])
    return out


def fmt(s: dict) -> str:
    if not s["n"]:
        return "-"
    if "ci95" in s:
        return f"{s['mean']} (95% CI {s['ci95'][0]}-{s['ci95'][1]}; range {s['min']}-{s['max']}; n={s['n']})"
    return f"{s['mean']} (n={s['n']})"


def aggregate(paths: list[Path]) -> dict:
    runs = [json.loads(p.read_text(encoding="utf-8")) for p in paths]
    by_class: dict[str, dict] = {}
    for r in runs:
        for ph in r["phases"]:
            if ph["label"] != "first":
                continue
            c = by_class.setdefault(ph["campaign"], {"enforce": [], "detect": [], "synth": [], "runs": 0,
                                                     "pre_reached": [], "post_reached": [], "post_aegis": [],
                                                     "obj_before": [], "obj_after": []})
            c["runs"] += 1
            if ph["enforce_after_onset_s"] is not None:
                c["enforce"].append(ph["enforce_after_onset_s"])
            if ph["detect_after_onset_s"] is not None:
                c["detect"].append(ph["detect_after_onset_s"])
            if ph["mitigation_ttm_s"] is not None:
                c["synth"].append(ph["mitigation_ttm_s"])
            c["pre_reached"].append(ph["before_enforcement"]["reached_app"])
            c["post_reached"].append(ph["after_enforcement"]["reached_app"])
            c["post_aegis"].append(ph["after_enforcement"]["blocked_by_aegis_rule"])
            c["obj_before"].append(ph["objective_met_runs_before"])
            c["obj_after"].append(ph["objective_met_runs_after"])
    out = {"n_runs": len(runs), "classes": {}}
    for k, c in by_class.items():
        out["classes"][k] = {
            "enforced": f"{len(c['enforce'])}/{c['runs']}",
            "time_to_enforce_s": stats(c["enforce"]), "time_to_detect_s": stats(c["detect"]),
            "synthesis_s": stats(c["synth"]),
            "attacker_requests_reaching_app_before": stats(c["pre_reached"]),
            "attacker_requests_reaching_app_after": stats(c["post_reached"]),
            "attacker_requests_blocked_by_aegis_after": stats(c["post_aegis"]),
            "valid_login_runs_before": stats(c["obj_before"]), "valid_login_runs_after": stats(c["obj_after"]),
        }
    out["benign_requests_total"] = sum(r["benign"]["requests"] for r in runs)
    out["benign_blocked_by_aegis_total"] = sum(r["benign"]["blocked_by_aegis_rule"] for r in runs)
    out["false_triggers_per_run"] = [r["controller"]["false_triggers_on_benign_actors"] for r in runs]
    out["rejected_live_total"] = sum(len(r["controller"].get("rejected_live", [])) for r in runs)
    out["log_gaps"] = [r.get("log_gaps_over_60s") for r in runs]
    return out


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    title = "runs"
    if "--title" in sys.argv:
        title = sys.argv[sys.argv.index("--title") + 1]
        args = [a for a in args if a != title]
    agg = aggregate([Path(a) for a in args])
    print(f"### {title}: {agg['n_runs']} replicate runs\n")
    print("| class | enforced | detect (s) | time to enforce (s) | synthesis (s) | attacker reached app, before / after |")
    print("|---|---|---|---|---|---|")
    for k, c in agg["classes"].items():
        print(f"| {k} | {c['enforced']} | {fmt(c['time_to_detect_s'])} | {fmt(c['time_to_enforce_s'])} | "
              f"{fmt(c['synthesis_s'])} | {c['attacker_requests_reaching_app_before']['mean']} / "
              f"{c['attacker_requests_reaching_app_after']['mean']} |")
    print(f"\nbenign requests {agg['benign_requests_total']}, blocked by an AEGIS rule: "
          f"{agg['benign_blocked_by_aegis_total']}; live-stage rejections: {agg['rejected_live_total']}; "
          f"false triggers per run: {agg['false_triggers_per_run']}; log gaps: {agg['log_gaps']}")
    print("\n" + json.dumps(agg, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
