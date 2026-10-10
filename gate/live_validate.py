"""Gate stage 3 (live regression) + a live efficacy check.

Offline replay (gate.py) proves a candidate on stored traffic. This stage
proves it on the LIVE stack: the candidate rule is actually enforced in the
gateway (CRS + candidate) and we measure, against real live traffic, whether
it (a) blocks the attack and (b) breaks any legitimate journey that CRS alone
did not already break.

Controlled design -- two live runs with the same benign seed:
    A) gateway enforce, CRS only
    B) gateway enforce, CRS + candidate
The candidate's live regression = journeys broken in B that were fine in A.
That isolates the candidate from CRS's own (already-measured) breakage.

    .venv\\Scripts\\python gate\\live_validate.py --rule rules/generated/promoted.conf \\
        --class sqli --journeys 60

Needs bin/gateway.exe and the range scripts. Writes a verdict; the candidate is
cleared for enforcement only if the attack is blocked live AND it breaks zero
benign journeys beyond CRS.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable


def ps(script: str, *args: str) -> None:
    subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File",
                    str(ROOT / "range" / script), *args], check=False, cwd=ROOT)


def wait_up(url: str, seconds: int) -> bool:
    for _ in range(seconds):
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except urllib.error.HTTPError:
            return True
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    return False


def line_count(p: Path) -> int:
    return sum(1 for _ in p.open(encoding="utf-8")) if p.exists() else 0


def run_benign(journeys: int, seed: int) -> dict:
    jpath = ROOT / "logs" / "benign" / "journeys.jsonl"
    before = line_count(jpath)
    subprocess.run([PY, str(ROOT / "range" / "benign" / "generate.py"),
                    "--workers", "4", "--fast", "--journeys", str(journeys),
                    "--seed", str(seed)], check=False, cwd=ROOT)
    rows = []
    with jpath.open(encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= before and line.strip():
                rows.append(json.loads(line))
    # key a journey by (persona name + journey + first steps) is unreliable;
    # instead compare aggregate broken-by-defence counts at the same seed.
    broken = sum(1 for r in rows if not r["ok"] and r.get("cause") == "defence")
    return {"journeys": len(rows), "broken_by_defence": broken,
            "ok": sum(r["ok"] for r in rows)}


def run_attack(attack_class: str) -> dict:
    apath = ROOT / "logs" / "attacks" / "requests.jsonl"
    before = line_count(apath)
    subprocess.run([PY, str(ROOT / "range" / "attacks" / "run.py"),
                    "--only", attack_class, "--pace", "0.1"], check=False, cwd=ROOT)
    rows = []
    with apath.open(encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= before and line.strip():
                rows.append(json.loads(line))
    mal = [r for r in rows if r.get("malicious")]
    blocked = sum(1 for r in mal if r["blocked"])
    return {"malicious": len(mal), "blocked": blocked,
            "block_rate": blocked / len(mal) if mal else 0}


def cycle(rule: str | None, journeys: int, seed: int, attack_class: str) -> dict:
    ps("stop.ps1")
    if rule:
        ps("start.ps1", "-Mode", "enforce", "-Rules", rule)
    else:
        ps("start.ps1", "-Mode", "enforce")
    if not wait_up("http://localhost:8080", 60):
        raise RuntimeError("gateway did not come up")
    benign = run_benign(journeys, seed)
    attack = run_attack(attack_class)
    ps("stop.ps1")
    return {"benign": benign, "attack": attack}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--rule", type=Path, required=True, help="compiled candidate .conf")
    p.add_argument("--class", dest="cls", required=True, help="attack class to fire live")
    p.add_argument("--journeys", type=int, default=60)
    p.add_argument("--seed", type=int, default=2024)
    args = p.parse_args()

    if not args.rule.exists():
        print(f"rule not found: {args.rule}", file=sys.stderr)
        return 2

    print("=== A) CRS only (control) ===")
    a = cycle(None, args.journeys, args.seed, args.cls)
    print(f"  benign broken-by-defence: {a['benign']['broken_by_defence']}/{a['benign']['journeys']}"
          f"   attack blocked: {a['attack']['blocked']}/{a['attack']['malicious']}")

    print("=== B) CRS + candidate ===")
    b = cycle(str(args.rule), args.journeys, args.seed, args.cls)
    print(f"  benign broken-by-defence: {b['benign']['broken_by_defence']}/{b['benign']['journeys']}"
          f"   attack blocked: {b['attack']['blocked']}/{b['attack']['malicious']}")

    added_breakage = b["benign"]["broken_by_defence"] - a["benign"]["broken_by_defence"]
    attack_gain = b["attack"]["block_rate"] - a["attack"]["block_rate"]
    print("\n=== live verdict ===")
    print(f"  candidate's added benign breakage: {added_breakage} journeys")
    print(f"  candidate's attack-block gain over CRS: {attack_gain*100:+.0f}%")
    cleared = added_breakage <= 0 and b["attack"]["block_rate"] >= 0.99
    print(f"  CLEARED FOR ENFORCEMENT: {cleared}")
    if not cleared and added_breakage > 0:
        print("  (candidate broke benign journeys CRS did not -> reject)")
    if not cleared and b["attack"]["block_rate"] < 0.99:
        print("  (candidate did not block the attack live -> reject)")

    out = {"ts": time.strftime("%Y-%m-%d %H:%M"), "rule": str(args.rule),
           "attack_class": args.cls, "control": a, "candidate": b,
           "added_breakage": added_breakage, "cleared": cleared}
    log = ROOT / "logs" / "gate" / "live_validation.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(out, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
