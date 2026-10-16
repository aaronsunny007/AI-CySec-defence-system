"""End-to-end test of the autonomous loop: no human after `start`.

One range boot (Juice Shop behind the gateway in ENFORCE mode, CRS on). Benign
traffic runs the whole time (real Playwright journeys + replayed corpus requests). The
controller (controller/loop.py) runs as its own process, tailing the gateway log. For each
attack class a persistent attacker (a fresh actor every few seconds, spoofed browser UA)
starts; nothing else is done by anyone. We then measure, from the gateway's own log:

  - time from campaign onset to detection, and to ENFORCEMENT of an AEGIS rule
  - attacker requests that reached the app before enforcement / were blocked after
  - benign requests blocked by an AEGIS rule (must be 0) and legitimate journeys broken
  - whether the controller flagged any benign actor (false triggers)
  - a SECOND exposure with the rule store wiped (cold): memory should skip regeneration

Ground truth (the gateway's range-only gt_label) is used ONLY here, to score. The
controller never reads it.

    python eval/e2e_live.py --classes command_injection credential_stuffing sqli
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("eval", "gate", "observer", "range/attacks"):
    sys.path.insert(0, str(ROOT / p))
import campaigns as C                      # noqa: E402
import rulestore                           # noqa: E402
from actors import actor_key               # noqa: E402
from client import Actor                   # noqa: E402
from rangectl import Range                 # noqa: E402
from traffic import ReplayDriver           # noqa: E402

PY = sys.executable
LOG = ROOT / "logs" / "gateway" / "e2e.jsonl"
EVENTS = ROOT / "logs" / "controller" / "e2e_events.jsonl"
DB = ROOT / "memory" / "e2e.db"
STOP = ROOT / "logs" / "controller" / "e2e_stop"
SUMMARY = ROOT / "logs" / "e2e_summary.json"
RULE_PREFIX = {"command_injection": "aegis-cmdi-", "credential_stuffing": "aegis-credential_stuffing-",
               "sqli": "aegis-sqli-", "xss": "aegis-xss-", "path_traversal": "aegis-traversal-"}


def _ts(iso: str) -> float:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def read_events() -> list[dict]:
    if not EVENTS.exists():
        return []
    out = []
    for l in EVENTS.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(l))
        except json.JSONDecodeError:
            pass
    return out


class Attacker:
    """Persistent attacker: runs the campaign with a FRESH identity every `gap_s` seconds."""

    def __init__(self, campaign: str, pace: float = 0.25, gap_s: float = 4.0):
        self.campaign, self.pace, self.gap = campaign, pace, gap_s
        self.runs: list[dict] = []
        self.stop = threading.Event()
        self.th = threading.Thread(target=self._loop, daemon=True)

    def _loop(self) -> None:
        sink = open(ROOT / "logs" / "attacks" / "e2e_attacks.jsonl", "a", encoding="utf-8")
        while not self.stop.is_set():
            a = Actor(base="http://127.0.0.1:8080", campaign=self.campaign, attack_class=self.campaign,
                      user_agent=C.user_agent_for(self.campaign), out=sink)
            t0 = time.time()
            try:
                res = C.CAMPAIGNS[self.campaign](a, self.pace)
            except Exception as e:                      # a broken campaign is data, not a crash
                res = {"objective_met": False, "evidence": f"error {e!r}"}
            self.runs.append({"t_start": t0, "t_end": time.time(), "fired": a.fired,
                              "blocked": a.blocked_count, "objective_met": bool(res["objective_met"]),
                              "evidence": res.get("evidence", "")})
            self.stop.wait(self.gap)
        sink.close()

    def start(self):
        self.th.start()
        return self

    def finish(self):
        self.stop.set()
        self.th.join(timeout=120)


def wait_enforced(prefix: str, since: float, timeout: float) -> dict | None:
    end = time.time() + timeout
    while time.time() < end:
        for e in read_events():
            if (e["t"] >= since and e["event"] in ("enforced", "already_enforcing")
                    and str(e.get("rule", "")).startswith(prefix)):
                return e
        time.sleep(1.0)
    return None


def run_phase(label: str, campaign: str, args) -> dict:
    prefix = RULE_PREFIX[campaign]
    t_start = time.time()
    print(f"[{label}] {campaign}: attacker starts (no human action from here)", flush=True)
    atk = Attacker(campaign).start()
    enf = wait_enforced(prefix, t_start, args.max_wait)
    t_enf = enf["t"] if enf else None
    print(f"[{label}] {campaign}: " + (f"enforced after {t_enf - t_start:.0f}s ({enf['event']}, {enf['rule']})"
                                      if enf else f"NOT enforced within {args.max_wait}s"), flush=True)
    time.sleep(args.after_s)                                # keep attacking after enforcement
    atk.finish()
    return {"label": label, "campaign": campaign, "t_start": t_start, "t_end": time.time(),
            "enforced_event": enf, "attacker_runs": atk.runs}


# ---- analysis (ground truth from the gateway log is used here and only here) ----

def load_log() -> list[dict]:
    out = []
    for l in LOG.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(l))
        except json.JSONDecodeError:
            pass
    return out


def aegis_blocked(rec: dict) -> bool:
    return any(m.endswith("|blocked") for m in rec.get("aegis_matches") or [])


def analyse(phases: list[dict], recs: list[dict], events: list[dict], run_start: float,
            journeys: list[dict]) -> dict:
    for r in recs:
        r["_t"] = _ts(r["ts"])
    out: dict = {"phases": [], "controller": {}, "benign": {}}
    ts_sorted = sorted(r["_t"] for r in recs)
    # a machine suspend mid-run silently invalidates wall-clock measurements: detect it
    out["log_gaps_over_60s"] = [{"at": round(a), "gap_s": round(b - a)}
                                for a, b in zip(ts_sorted, ts_sorted[1:]) if b - a > 60][:5]
    for ph in phases:
        gt = f"attack:{ph['campaign']}"
        atk = [r for r in recs if r.get("gt_label") == gt and ph["t_start"] <= r["_t"] <= ph["t_end"] + 5]
        onset = min((r["_t"] for r in atk), default=None)
        t_enf = ph["enforced_event"]["t"] if ph["enforced_event"] else None
        tech = {"command_injection": "cmdi"}.get(ph["campaign"], ph["campaign"])
        det = next((e for e in events if e["event"] == "campaign_detected" and e["technique"] == tech
                    and e["t"] >= ph["t_start"]), None)
        mit = next((e for e in events if e["event"] == "mitigation" and e["technique"] == tech
                    and e["t"] >= ph["t_start"]), None)
        pre = [r for r in atk if t_enf is None or r["_t"] < t_enf]
        post = [r for r in atk if t_enf is not None and r["_t"] >= t_enf]

        def split(rs):
            ab = sum(1 for r in rs if aegis_blocked(r))
            cb = sum(1 for r in rs if r.get("blocked") and not aegis_blocked(r))
            return {"total": len(rs), "blocked_by_aegis_rule": ab, "blocked_by_crs": cb,
                    "reached_app": len(rs) - ab - cb}
        runs = ph["attacker_runs"]
        ok_pre = sum(1 for x in runs if x["objective_met"] and (t_enf is None or x["t_end"] < t_enf))
        ok_post = sum(1 for x in runs if x["objective_met"] and t_enf is not None and x["t_start"] >= t_enf)
        out["phases"].append({
            "label": ph["label"], "campaign": ph["campaign"], "enforced": bool(t_enf),
            "rule": ph["enforced_event"]["rule"] if t_enf else None,
            "enforce_event": ph["enforced_event"]["event"] if t_enf else None,
            "detect_after_onset_s": round(det["t"] - onset, 1) if det and onset else None,
            "detector_ttd_s": round(det["ttd_s"], 1) if det else None,
            "mitigation_source": mit["source"] if mit else None,
            "mitigation_ttm_s": mit["ttm_s"] if mit else None,
            "enforce_after_onset_s": round(t_enf - onset, 1) if t_enf and onset else None,
            "before_enforcement": split(pre), "after_enforcement": split(post),
            "attacker_runs": len(runs), "objective_met_runs_before": ok_pre,
            "objective_met_runs_after": ok_post,
        })
    # ---- benign side
    ben = [r for r in recs if r.get("gt_label") == "benign"]
    ben_aegis = [r for r in ben if aegis_blocked(r)]
    ben_crs = [r for r in ben if r.get("blocked") and not aegis_blocked(r)]
    out["benign"] = {
        "requests": len(ben), "blocked_by_aegis_rule": len(ben_aegis),
        "blocked_by_crs": len(ben_crs),
        "aegis_blocked_samples": [{"uri": r["uri"][:80], "m": r.get("aegis_matches")} for r in ben_aegis[:5]],
        "journeys": len(journeys), "journeys_failed": sum(1 for j in journeys if not j["ok"]),
        "journeys_broken_by_defence": sum(1 for j in journeys if not j["ok"] and j.get("cause") == "defence"),
        "journeys_failed_other": {c: sum(1 for j in journeys if not j["ok"] and j.get("cause") == c)
                                  for c in ("app", "script")},
    }
    # ---- controller behaviour
    gt_of: dict[str, str] = {}
    for r in recs:
        gt_of.setdefault(actor_key(r), r.get("gt_label") or "")
    detected = [e for e in events if e["event"] == "campaign_detected"]
    false_trig = [e for e in detected if not gt_of.get(e["actor"], "").startswith("attack:")]
    out["controller"] = {
        "campaigns_detected": len(detected), "false_triggers_on_benign_actors": len(false_trig),
        "false_trigger_samples": [{"technique": e["technique"], "actor_gt": gt_of.get(e["actor"], "?"),
                                   "n": e["n_requests"]} for e in false_trig[:5]],
        "events_by_type": {k: sum(1 for e in events if e["event"] == k)
                           for k in sorted({e["event"] for e in events})},
        "errors": [e for e in events if e["event"] in ("error", "live_error")][:5],
        "rejected_live": [e for e in events if e["event"] == "rejected_live"],
        "fraction_reaching_llm": 0.0,
    }
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--classes", nargs="+", default=["command_injection", "credential_stuffing", "sqli"],
                    choices=list(RULE_PREFIX))
    ap.add_argument("--shadow-s", type=float, default=20)
    ap.add_argument("--canary-s", type=float, default=30)
    ap.add_argument("--rps", type=float, default=40)
    ap.add_argument("--warmup-s", type=float, default=75)
    ap.add_argument("--max-wait", type=float, default=420)
    ap.add_argument("--after-s", type=float, default=40)
    ap.add_argument("--no-cold", action="store_true", help="skip the cold second exposure")
    ap.add_argument("--journey-workers", type=int, default=3)
    args = ap.parse_args()

    corpus = sorted((ROOT / "data" / "benign_corpus").glob("benign_*detect*.jsonl"))[0]
    m1 = ROOT / "logs" / "gateway" / "m1_episode.jsonl"
    for f in (LOG, EVENTS, DB, STOP):
        f.unlink(missing_ok=True)
    (ROOT / "logs" / "attacks").mkdir(exist_ok=True)
    rulestore.clear()

    phases: list[dict] = []
    run_start = time.time()
    procs: list[subprocess.Popen] = []
    with Range(mode="enforce", log=str(LOG.relative_to(ROOT))):
        replay = ReplayDriver(corpus, rps=args.rps).start()
        journeys = subprocess.Popen(
            [PY, str(ROOT / "range" / "benign" / "generate.py"), "--workers", str(args.journey_workers),
             "--fast", "--duration", "120", "--seed", "900"], cwd=ROOT,
            stdout=open(ROOT / "logs" / "e2e_journeys.out", "w"), stderr=subprocess.STDOUT)
        procs.append(journeys)
        ctl_cmd = [PY, str(ROOT / "controller" / "loop.py"), "--log", str(LOG), "--events", str(EVENTS),
                   "--db", str(DB), "--shadow-s", str(args.shadow_s), "--canary-s", str(args.canary_s),
                   "--stop-file", str(STOP)]
        if m1.exists():
            ctl_cmd += ["--benign-actors", str(m1)]
        ctl = subprocess.Popen(ctl_cmd, cwd=ROOT, stdout=open(ROOT / "logs" / "e2e_controller.out", "w"),
                               stderr=subprocess.STDOUT)
        procs.append(ctl)
        try:
            print(f"warm-up {args.warmup_s:.0f}s of benign traffic ...", flush=True)
            time.sleep(args.warmup_s)
            for c in args.classes:
                phases.append(run_phase("first", c, args))
            if not args.no_cold:
                for c in args.classes:
                    rulestore.clear()               # rule store wiped: same campaign, cold
                    time.sleep(3)
                    phases.append(run_phase("cold-repeat", c, args))
        finally:
            STOP.parent.mkdir(parents=True, exist_ok=True)
            STOP.write_text("stop")
            time.sleep(4)
            replay.stop()
            final_rules = rulestore.load()["rules"]
            for pr in procs:                         # only processes started here, by PID
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pr.pid)],
                               capture_output=True, check=False)
        time.sleep(2)

    recs = load_log()
    events = read_events()
    jr = [json.loads(l) for l in (ROOT / "logs" / "benign" / "journeys.jsonl").read_text(encoding="utf-8").splitlines()
          if l.strip()]
    jr = [j for j in jr if j["t_start"] >= run_start]
    res = analyse(phases, recs, events, run_start, jr)
    res["config"] = {"shadow_s": args.shadow_s, "canary_s": args.canary_s, "canary_pct": 25,
                     "replay_rps": args.rps, "journey_workers": args.journey_workers,
                     "wall_s": round(time.time() - run_start)}
    res["final_rules"] = [{"id": r["id"], "mode": r["mode"]} for r in final_rules]
    SUMMARY.write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
