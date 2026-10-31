"""Adaptive adversary vs (a) CRS alone and (b) the closed AEGIS loop.

The red agent (range/attacks/adaptive.py) observes only HTTP status codes and adapts: re-encodes
payloads, rotates its identity, slows down, and learns the rate-limit quota. Same agent, same
seed and budget in both arms; benign traffic (Playwright journeys + replayed corpus requests)
runs throughout. Per goal we report, from the gateway's own log:

  attacker outcome   objective met / valid credentials harvested, attack requests that reached
                     the app, requests until the first block
  observer           how many of the attacker's identities the detector flagged, and whether
                     it attributed the right technique (the controller never sees ground truth)
  AEGIS work         rules the controller promoted, and what each took
  safety             benign requests blocked by an AEGIS rule (total, and the worst 60-second
                     window), journeys broken by the defence

    python eval/adaptive_run.py --arms crs closed --goals credential_stuffing sqli command_injection
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("eval", "gate", "observer", "range/attacks"):
    sys.path.insert(0, str(ROOT / p))
import e2e_live as E                         # noqa: E402
import rulestore                             # noqa: E402
from actors import actor_key                 # noqa: E402
from adaptive import RedAgent                # noqa: E402
from rangectl import Range, _kill_pid                   # noqa: E402
from traffic import ReplayDriver             # noqa: E402

PY = sys.executable
TECH = {"credential_stuffing": "credential_stuffing", "sqli": "sqli", "command_injection": "cmdi"}
SUMMARY = ROOT / "logs" / "adaptive_summary.json"


def score(goal: str, rep, recs: list[dict], events: list[dict], t0: float, t1: float) -> dict:
    gt = f"attack:{goal}"
    atk = [r for r in recs if r.get("gt_label") == gt and t0 <= r["_t"] <= t1 + 3]
    idents = {actor_key(r) for r in atk}
    tech = TECH[goal]
    detected = {e["actor"] for e in events if e["event"] == "campaign_detected" and e["t"] >= t0
                and e["actor"] in idents}
    right = {e["actor"] for e in events if e["event"] == "campaign_detected" and e["t"] >= t0
             and e["actor"] in idents and e["technique"] == tech}
    first_aegis = next((i for i, r in enumerate(sorted(atk, key=lambda x: x["_t"]), 1)
                        if E.aegis_blocked(r)), None)
    return {
        "goal": goal, "agent": rep.__dict__,
        "gateway_view": {
            "attack_requests": len(atk), "identities_seen": len(idents),
            "blocked_by_aegis_rule": sum(1 for r in atk if E.aegis_blocked(r)),
            "blocked_by_crs": sum(1 for r in atk if r.get("blocked") and not E.aegis_blocked(r)),
            "reached_app": sum(1 for r in atk if not r.get("blocked")),
            "first_aegis_block_at_request": first_aegis,
        },
        "observer": {"identities_flagged": len(detected), "flagged_with_right_technique": len(right),
                     "campaign_events": sum(1 for e in events if e["event"] == "campaign_detected"
                                            and e["t"] >= t0)},
        "aegis_rules_enforced": [e["rule"] for e in events if e["event"] == "enforced" and e["t"] >= t0],
        "rejected_live": [e["rule"] for e in events if e["event"] == "rejected_live" and e["t"] >= t0],
        "bypass_events": sum(1 for e in events if e["event"] == "rule_bypassed" and e["t"] >= t0),
    }


def benign_harm(recs: list[dict]) -> dict:
    ben = sorted((r for r in recs if r.get("gt_label") == "benign"), key=lambda r: r["_t"])
    hit = [r for r in ben if E.aegis_blocked(r)]
    per_min: Counter = Counter(int(r["_t"] // 60) for r in ben)
    hit_min: Counter = Counter(int(r["_t"] // 60) for r in hit)
    worst = max((hit_min[m] / per_min[m] for m in hit_min if per_min[m] >= 50), default=0.0)
    return {"benign_requests": len(ben), "blocked_by_aegis_rule": len(hit),
            "fraction": round(len(hit) / len(ben), 6) if ben else 0.0,
            "worst_60s_window_fraction": round(worst, 6),
            "samples": [{"uri": r["uri"][:70], "m": r.get("aegis_matches")} for r in hit[:4]]}


def run_arm(arm: str, goals: list[str], args) -> dict:
    log = ROOT / "logs" / "gateway" / f"adaptive_{arm}.jsonl"
    events_f = ROOT / "logs" / "controller" / f"adaptive_{arm}_events.jsonl"
    stop = ROOT / "logs" / "controller" / f"adaptive_{arm}_stop"
    db = ROOT / "memory" / f"adaptive_{arm}.db"
    for f in (log, events_f, stop, db):
        f.unlink(missing_ok=True)
    rulestore.clear()
    corpus = [f for f in sorted((ROOT / "data" / "benign_corpus").glob("benign_*detect*.jsonl")) if not f.name.startswith("benign_00")][0]
    m1 = ROOT / "logs" / "gateway" / "m1_episode.jsonl"
    runs: list[dict] = []
    run_start = time.time()
    procs: list[subprocess.Popen] = []
    with Range(mode="enforce", log=str(log.relative_to(ROOT))):
        replay = ReplayDriver(corpus, rps=args.rps).start()
        procs.append(subprocess.Popen(
            [PY, str(ROOT / "range" / "benign" / "generate.py"), "--workers", "3", "--fast",
             "--duration", "120", "--seed", "901"], cwd=ROOT,
            stdout=open(ROOT / "logs" / f"adaptive_{arm}_journeys.out", "w"), stderr=subprocess.STDOUT))
        if arm == "closed":
            cmd = [PY, str(ROOT / "controller" / "loop.py"), "--log", str(log), "--events", str(events_f),
                   "--db", str(db), "--shadow-s", str(args.shadow_s), "--canary-s", str(args.canary_s),
                   "--stop-file", str(stop)]
            if m1.exists():
                cmd += ["--benign-actors", str(m1)]
            procs.append(subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT))
        try:
            time.sleep(args.warmup_s)
            for g in goals:
                t0 = time.time()
                print(f"[{arm}] {g}: red agent starts (budget {args.budget})", flush=True)
                rep = RedAgent(g, budget=args.budget, pace=args.pace, seed=args.seed,
                               log=ROOT / "logs" / "attacks" / f"adaptive_{arm}.jsonl").run()
                t1 = time.time()
                print(f"[{arm}] {g}: done in {rep.seconds}s  requests={rep.requests} blocked={rep.blocked} "
                      f"passed={rep.passed} objective_met={rep.objective_met} "
                      f"valid_found={len(rep.valid_found)} identities={rep.identities}", flush=True)
                runs.append({"goal": g, "t0": t0, "t1": t1, "rep": rep})
                time.sleep(args.settle_s)
        finally:
            stop.parent.mkdir(parents=True, exist_ok=True)
            stop.write_text("stop")
            time.sleep(4)
            replay.stop()
            final_rules = rulestore.load()["rules"]
            for pr in procs:
                _kill_pid(pr.pid)
    time.sleep(2)
    E.LOG = log
    recs = E.load_log()
    for r in recs:
        r["_t"] = E._ts(r["ts"])
    E.EVENTS = events_f
    events = E.read_events()
    jr = [json.loads(l) for l in (ROOT / "logs" / "benign" / "journeys.jsonl").read_text(encoding="utf-8").splitlines()
          if l.strip()]
    jr = [j for j in jr if j["t_start"] >= run_start]
    ts_sorted = sorted(r["_t"] for r in recs)
    return {"arm": arm,
            "goals": [score(x["goal"], x["rep"], recs, events, x["t0"], x["t1"]) for x in runs],
            "benign": benign_harm(recs),
            "journeys": {"n": len(jr), "failed": sum(1 for j in jr if not j["ok"]),
                         "broken_by_defence": sum(1 for j in jr if not j["ok"] and j.get("cause") == "defence")},
            "log_gaps_over_60s": [round(b - a) for a, b in zip(ts_sorted, ts_sorted[1:]) if b - a > 60][:5],
            "controller_events": dict(Counter(e["event"] for e in events)),
            "final_rules": [{"id": r["id"], "mode": r["mode"]} for r in final_rules]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--arms", nargs="+", default=["crs", "closed"], choices=["crs", "closed"])
    ap.add_argument("--goals", nargs="+", default=["credential_stuffing", "sqli", "command_injection"],
                    choices=list(TECH))
    ap.add_argument("--budget", type=int, default=260)
    ap.add_argument("--pace", type=float, default=0.5)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--rps", type=float, default=40)
    ap.add_argument("--shadow-s", type=float, default=20)
    ap.add_argument("--canary-s", type=float, default=30)
    ap.add_argument("--warmup-s", type=float, default=75)
    ap.add_argument("--settle-s", type=float, default=10)
    args = ap.parse_args()
    out = {"config": vars(args), "arms": []}
    for arm in args.arms:
        out["arms"].append(run_arm(arm, args.goals, args))
        SUMMARY.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
