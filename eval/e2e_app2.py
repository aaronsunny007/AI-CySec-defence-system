"""Generalisation test: the autonomous loop on a SECOND, different target app (BookNook).

1. (once) capture a benign corpus for BookNook through the gateway in detect mode
   -> data/benign_corpus/booknook_corpus.jsonl  (this is what the gate's FP check replays)
2. boot BookNook behind the gateway in enforce mode with CRS, run benign users continuously,
   start the controller (separate process), and for each class start a persistent attacker.
   Nothing is retuned for this app: same detector, same templates, same gate, same stages.

    python eval/e2e_app2.py --classes sqli command_injection credential_stuffing
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("eval", "gate", "observer", "range/attacks", "range/app2"):
    sys.path.insert(0, str(ROOT / p))
import e2e_live as E                         # noqa: E402
import attacks as A2                         # noqa: E402
import benign as B2                          # noqa: E402
import rulestore                             # noqa: E402
from rangectl import Range                   # noqa: E402

PY = sys.executable
CORPUS = ROOT / "data" / "benign_corpus" / "booknook_corpus.jsonl"
LOG = ROOT / "logs" / "gateway" / "app2.jsonl"
EVENTS = ROOT / "logs" / "controller" / "app2_events.jsonl"
STOP = ROOT / "logs" / "controller" / "app2_stop"
DB = ROOT / "memory" / "app2.db"
SUMMARY = ROOT / "logs" / "app2_summary.json"


def capture(n: int) -> None:
    CORPUS.parent.mkdir(parents=True, exist_ok=True)
    CORPUS.unlink(missing_ok=True)
    rulestore.clear()
    with Range(mode="detect", log=str(CORPUS.relative_to(ROOT)), app="booknook"):
        ths, counter = B2.run(n, 0, 8, 7)
        for t in ths:
            t.join()
    lines = sum(1 for _ in CORPUS.open(encoding="utf-8"))
    print(f"captured {lines} benign requests -> {CORPUS}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--classes", nargs="+", default=["sqli", "command_injection", "credential_stuffing"])
    ap.add_argument("--capture-requests", type=int, default=30000)
    ap.add_argument("--recapture", action="store_true")
    ap.add_argument("--shadow-s", type=float, default=20)
    ap.add_argument("--canary-s", type=float, default=30)
    ap.add_argument("--warmup-s", type=float, default=60)
    ap.add_argument("--max-wait", type=float, default=420)
    ap.add_argument("--after-s", type=float, default=40)
    args = ap.parse_args()

    if args.recapture or not CORPUS.exists():
        capture(args.capture_requests)

    E.C = A2                                   # the attacker thread uses these campaigns
    E.RULE_PREFIX = dict(E.RULE_PREFIX)
    E.LOG, E.EVENTS = LOG, EVENTS
    for f in (LOG, EVENTS, DB, STOP):
        f.unlink(missing_ok=True)
    (ROOT / "logs" / "attacks").mkdir(exist_ok=True)
    rulestore.clear()

    phases: list[dict] = []
    t_run = time.time()
    stop_b = threading.Event()
    with Range(mode="enforce", log=str(LOG.relative_to(ROOT)), app="booknook"):
        ths, _ = B2.run(0, 3600, 4, 11, stop_b)
        ctl = subprocess.Popen(
            [PY, str(ROOT / "controller" / "loop.py"), "--log", str(LOG), "--events", str(EVENTS), "--db", str(DB),
             "--benign-corpus", str(CORPUS), "--shadow-s", str(args.shadow_s), "--canary-s", str(args.canary_s),
             "--stop-file", str(STOP)], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        try:
            time.sleep(args.warmup_s)
            for c in args.classes:
                phases.append(E.run_phase("first", c, args))
        finally:
            STOP.write_text("stop")
            time.sleep(4)
            stop_b.set()
            final = rulestore.load()["rules"]
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(ctl.pid)], capture_output=True, check=False)
    time.sleep(2)

    recs = E.load_log()
    events = E.read_events()
    res = E.analyse(phases, recs, events, t_run, [])
    res["target"] = "BookNook (second app)"
    res["final_rules"] = [{"id": r["id"], "mode": r["mode"]} for r in final]
    res["config"] = {"shadow_s": args.shadow_s, "canary_s": args.canary_s, "wall_s": round(time.time() - t_run)}
    SUMMARY.write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    print(json.dumps(res, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
