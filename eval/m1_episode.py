"""M1 re-evaluation: campaign detection with corrected ground truth.

Phase 1 (standard)  benign journeys + all 8 attack campaigns x2, spoofed browser UA,
                    gateway in DETECT mode so campaigns run to completion.
                    Reports per-campaign detection AND correct attribution (did the
                    detector name the right technique?), time-to-detect, and the
                    false-positive rate over benign actors.
Phase 2 (evasion)   the rate-shaped campaigns re-run slow-and-low, deliberately
                    under the detector's thresholds. This measures the evasion
                    margin the M1 write-up only asserted.

Ground truth is the gateway's range-only gt_label (never the user-agent). The
detector itself reads neither.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("eval", "observer"):
    sys.path.insert(0, str(ROOT / p))
from rangectl import Range                                   # noqa: E402
from actors import reconstruct                               # noqa: E402
from detector import detect, ground_truth                    # noqa: E402

PY = sys.executable
LOG = ROOT / "logs" / "gateway" / "m1_episode.jsonl"
EXPECT = {"sqli": "sqli", "xss": "xss", "path_traversal": "traversal",
          "command_injection": "cmdi", "ssrf": "ssrf", "user_enumeration": "user_enumeration",
          "idor_bola": "idor_bola", "credential_stuffing": "credential_stuffing"}


def window(offset: int) -> Path:
    data = LOG.read_bytes()[offset:]
    out = Path(tempfile.mkdtemp()) / "w.jsonl"
    out.write_bytes(data)
    return out


def score(path: Path) -> dict:
    actors = reconstruct(path)
    per: dict[str, dict] = {}
    ben_total = ben_flag = 0
    ttds = []
    for a in actors.values():
        if len(a.requests) < 3:
            continue
        gt = ground_truth(a.requests[0].raw) or ""
        findings = detect(a)
        if gt.startswith("attack:"):
            camp = gt.split(":", 1)[1]
            d = per.setdefault(camp, {"actors": 0, "detected": 0, "attributed": 0, "ttd_s": []})
            d["actors"] += 1
            if findings:
                d["detected"] += 1
                if EXPECT.get(camp) in {f.technique for f in findings}:
                    d["attributed"] += 1
                    d["ttd_s"].append(round(min(f.ttd_s for f in findings if f.technique == EXPECT[camp]), 1))
                    ttds.append(d["ttd_s"][-1])
        elif gt == "benign":
            ben_total += 1
            ben_flag += bool(findings)
    ttds.sort()
    return {"per_campaign": per, "benign_actors": ben_total, "benign_flagged": ben_flag,
            "ttd_p50": ttds[len(ttds) // 2] if ttds else None,
            "ttd_p90": ttds[min(int(len(ttds) * .9), len(ttds) - 1)] if ttds else None,
            "ttd_within_30s": (sum(t <= 30 for t in ttds) / len(ttds)) if ttds else None}


def show(title: str, r: dict) -> None:
    print(f"\n=== {title} ===")
    tot = det = att = 0
    for c, d in sorted(r["per_campaign"].items()):
        tot += d["actors"]; det += d["detected"]; att += d["attributed"]
        print(f"  {c:20s} actors {d['actors']}  detected {d['detected']}  correctly attributed "
              f"{d['attributed']}  ttd {d['ttd_s']}")
    print(f"  TOTAL attack actors {tot}: detected {det} ({100*det/max(tot,1):.0f}%), "
          f"correctly attributed {att} ({100*att/max(tot,1):.0f}%)")
    print(f"  benign actors {r['benign_actors']}: false-flagged {r['benign_flagged']} "
          f"({100*r['benign_flagged']/max(r['benign_actors'],1):.2f}%)")
    if r["ttd_p50"] is not None:
        print(f"  time-to-detect (attributed): p50 {r['ttd_p50']}s p90 {r['ttd_p90']}s "
              f"within 30s: {100*r['ttd_within_30s']:.0f}%")


def attacks(only: list[str] | None, pace: float, out_log: Path) -> None:
    cmd = [PY, str(ROOT / "range" / "attacks" / "run.py"), "--pace", str(pace), "--ua", "browser",
           "--log", str(out_log)]
    if only:
        cmd += ["--only", *only]
    subprocess.run(cmd, cwd=ROOT, capture_output=True)


def main() -> int:
    alog = ROOT / "logs" / "attacks" / "m1_episode_attacks.jsonl"
    result = {}
    with Range(mode="detect", log=str(LOG.relative_to(ROOT))):
        off = LOG.stat().st_size if LOG.exists() else 0
        print("phase 1: benign journeys + all 8 campaigns x2 ...", flush=True)
        b = subprocess.Popen([PY, str(ROOT / "range" / "benign" / "generate.py"), "--workers", "4",
                              "--fast", "--journeys", "160", "--seed", "500"], cwd=ROOT,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        attacks(None, 0.1, alog)
        attacks(None, 0.1, alog)
        b.wait()
        time.sleep(2)
        result["standard"] = score(window(off))

        off2 = LOG.stat().st_size
        print("phase 2: slow-and-low evasion (stuffing 15s/try, enumeration 20s/probe) ...", flush=True)
        # run.py halves the pace for stuffing, so pace 30 -> 15 s between attempts
        t1 = subprocess.Popen([PY, str(ROOT / "range" / "attacks" / "run.py"), "--pace", "30",
                               "--ua", "browser", "--only", "credential_stuffing",
                               "--log", str(alog)], cwd=ROOT, stdout=subprocess.DEVNULL)
        t2 = subprocess.Popen([PY, str(ROOT / "range" / "attacks" / "run.py"), "--pace", "20",
                               "--ua", "browser", "--only", "user_enumeration",
                               "--log", str(alog)], cwd=ROOT, stdout=subprocess.DEVNULL)
        t1.wait(); t2.wait()
        time.sleep(2)
        result["slow_and_low"] = score(window(off2))

    show("PHASE 1 standard campaigns (detect mode, spoofed browser UA)", result["standard"])
    show("PHASE 2 slow-and-low evasion", result["slow_and_low"])
    (ROOT / "logs" / "m1_episode_summary.json").write_text(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
