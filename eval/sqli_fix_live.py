"""Live re-run after the SQLi template fix (docs/M4-RESULTS.md found `aegis-sqli-3` blocking a
real user's password `7ggq|;]3,p'#`).

One range boot, the autonomous controller as its own process, benign journeys + corpus replay,
the adaptive SQLi red agent, AND a witness that sends the two known-harmed benign requests
(login + registration with that password) every few seconds from rotating benign identities.
Reported: whether the controller enforced a SQLi rule, what the attacker got through, and
how many benign requests (witness and background) an AEGIS rule blocked.

    python eval/sqli_fix_live.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("eval", "gate", "observer", "range/attacks"):
    sys.path.insert(0, str(ROOT / p))
import e2e_live as E                         # noqa: E402
import rulestore                             # noqa: E402
from adaptive import RedAgent                # noqa: E402
from rangectl import Range                   # noqa: E402
from traffic import ReplayDriver             # noqa: E402

PY = sys.executable
LOG = ROOT / "logs" / "gateway" / "sqlifix.jsonl"
EVENTS = ROOT / "logs" / "controller" / "sqlifix_events.jsonl"
STOP = ROOT / "logs" / "controller" / "sqlifix_stop"
DB = ROOT / "memory" / "sqlifix.db"
OUT = ROOT / "logs" / "sqlifix_summary.json"


class Witness:
    """Sends the known hard-negative benign requests on a schedule; counts 403s."""
    def __init__(self):
        self.recs = [json.loads(l) for l in (ROOT / "data" / "hard_negatives.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        self.sent = 0
        self.status: dict[int, int] = {}
        self.stop = threading.Event()
        self.th = threading.Thread(target=self._loop, daemon=True)

    def _loop(self):
        n = 0
        while not self.stop.is_set():
            for r in self.recs:
                req = urllib.request.Request("http://127.0.0.1:8080" + r["uri"], data=r["body"].encode(),
                                             method=r["method"], headers={
                                                 "Content-Type": r["content_type"],
                                                 "Cookie": f"aegis_vid=benign-hardneg-{n % 10}",
                                                 "User-Agent": "Mozilla/5.0 (witness)"})
                try:
                    code = urllib.request.urlopen(req, timeout=15).status
                except urllib.error.HTTPError as e:
                    code = e.code
                except OSError:
                    continue
                self.sent += 1
                self.status[code] = self.status.get(code, 0) + 1
            n += 1
            self.stop.wait(4)

    def start(self):
        self.th.start()
        return self

    def finish(self):
        self.stop.set()
        self.th.join(timeout=30)


def main() -> int:
    for f in (LOG, EVENTS, STOP, DB):
        f.unlink(missing_ok=True)
    rulestore.clear()
    corpus = next((ROOT / "data" / "benign_corpus").glob("benign_*detect*.jsonl"))
    m1 = ROOT / "logs" / "gateway" / "m1_episode.jsonl"
    run_start = time.time()
    procs = []
    with Range(mode="enforce", log=str(LOG.relative_to(ROOT))):
        replay = ReplayDriver(corpus, rps=40).start()
        procs.append(subprocess.Popen([PY, str(ROOT / "range" / "benign" / "generate.py"), "--workers", "3",
                                       "--fast", "--duration", "120", "--seed", "902"], cwd=ROOT,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT))
        cmd = [PY, str(ROOT / "controller" / "loop.py"), "--log", str(LOG), "--events", str(EVENTS),
               "--db", str(DB), "--shadow-s", "20", "--canary-s", "30", "--stop-file", str(STOP)]
        if m1.exists():
            cmd += ["--benign-actors", str(m1)]
        procs.append(subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT))
        wit = None
        try:
            time.sleep(75)
            wit = Witness().start()
            t0 = time.time()
            rep = RedAgent("sqli", budget=150, pace=0.3, seed=1,
                           log=ROOT / "logs" / "attacks" / "sqlifix.jsonl").run()
            t1 = time.time()
            print(f"agent done in {rep.seconds}s requests={rep.requests} blocked={rep.blocked} "
                  f"passed={rep.passed} identities={rep.identities}", flush=True)
            time.sleep(60)          # keep the witness running while the rule is enforcing
        finally:
            if wit:
                wit.finish()
            STOP.write_text("stop")
            time.sleep(4)
            replay.stop()
            final = rulestore.load()["rules"]
            for pr in procs:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pr.pid)], capture_output=True, check=False)
    time.sleep(2)
    E.LOG, E.EVENTS = LOG, EVENTS
    recs = E.load_log()
    for r in recs:
        r["_t"] = E._ts(r["ts"])
    events = E.read_events()
    ben = [r for r in recs if r.get("gt_label") == "benign"]
    hit = [r for r in ben if E.aegis_blocked(r)]
    atk = [r for r in recs if r.get("gt_label") == "attack:sqli"]
    enforced = [e for e in events if e["event"] == "enforced"]
    ts = sorted(r["_t"] for r in recs)
    res = {
        "enforced_rules": [e["rule"] for e in enforced],
        "agent": rep.__dict__ | {"timeline": rep.timeline[:6]},
        "attack_requests": len(atk), "attack_blocked_by_aegis": sum(1 for r in atk if E.aegis_blocked(r)),
        "attack_blocked_by_crs": sum(1 for r in atk if r.get("blocked") and not E.aegis_blocked(r)),
        "attack_reached_app": sum(1 for r in atk if not r.get("blocked")),
        "benign_requests": len(ben), "benign_blocked_by_aegis": len(hit),
        "benign_blocked_samples": [{"uri": r["uri"], "body": (r.get("body") or "")[:80], "m": r.get("aegis_matches")} for r in hit[:5]],
        "witness_sent": wit.sent, "witness_status_counts": wit.status,
        "witness_aegis_blocked": sum(1 for r in ben if E.aegis_blocked(r) and "7ggq" in (r.get("body") or "")),
        "controller_events": {k: sum(1 for e in events if e["event"] == k) for k in sorted({e["event"] for e in events})},
        "log_gaps_over_60s": [round(b - a) for a, b in zip(ts, ts[1:]) if b - a > 60][:5],
        "final_rules": [{"id": r["id"], "mode": r["mode"]} for r in final],
        "wall_s": round(time.time() - run_start),
    }
    OUT.write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    print(json.dumps(res, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
