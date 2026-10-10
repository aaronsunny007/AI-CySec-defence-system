"""Stateful rate-limit evaluator + gate stages for rate_limit candidates.

A signature rule is a per-request decision, so the gate replays it request by
request (gate.py + bin/replay.exe). A rate limit is a PER-ACTOR, OVER-TIME
decision, so it is validated differently: replay each actor's request stream
through a sliding window and see whom it would block.

This same sliding-window logic is mirrored in the Go gateway (rate limiter), so
what the gate validates is what enforces.

Gate decision for a rate_limit candidate (over a combined benign+attack stream
with actors, timestamps and -- for ground truth only -- tool user-agents):
  - benign FP : fraction of BENIGN actors that would have a request blocked.
                Budget: 0 (blocking a real user is the harm we must avoid).
  - efficacy  : fraction of the targeted ATTACK actors that get rate-limited.

Ground truth (attack vs benign) uses the tool user-agent, exactly as in M1;
the limiter itself keys only on actor + endpoint + time.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ir"))
sys.path.insert(0, str(ROOT / "observer"))
import compile as irc        # noqa: E402
from actors import reconstruct  # noqa: E402
from detector import is_attack_actor  # noqa: E402


def _matches(req, spec: dict) -> bool:
    if not req.path.startswith(spec["endpoint_prefix"]):
        return False
    if spec.get("methods") and req.method not in spec["methods"]:
        return False
    return True


def blocked_count(requests, spec: dict) -> int:
    """How many of an actor's in-scope requests the sliding window would block.
    A request is blocked when MORE than `count` in-scope requests have arrived
    within the trailing `window_s` seconds (the (count+1)-th and beyond)."""
    win: deque = deque()
    blocked = 0
    for r in requests:
        if not _matches(r, spec):
            continue
        win.append(r.ts)
        while (r.ts - win[0]).total_seconds() > spec["window_s"]:
            win.popleft()
        if len(win) > spec["count"]:
            blocked += 1
    return blocked


def evaluate(stream_path: Path, spec: dict) -> dict:
    actors = reconstruct(stream_path)
    benign_actors = benign_blocked = 0
    attack_actors = attack_blocked = 0
    attack_class = spec["attack_class"]
    for a in actors.values():
        bc = blocked_count(a.requests, spec)
        if is_attack_actor(a):
            # Only score actors of the class this rule targets. The class comes
            # from the range-only gt_label (attack:<campaign>), not the UA.
            gt = a.requests[0].raw.get("gt_label") or ""
            if gt == f"attack:{attack_class}":
                attack_actors += 1
                attack_blocked += bc > 0
        else:
            benign_actors += 1
            benign_blocked += bc > 0
    return {
        "benign_actors": benign_actors, "benign_blocked": benign_blocked,
        "benign_fp_rate": benign_blocked / benign_actors if benign_actors else 0,
        "attack_actors": attack_actors, "attack_blocked": attack_blocked,
        "attack_block_rate": attack_blocked / attack_actors if attack_actors else 0,
    }


def validate_candidate(ir: dict, stream_path: Path) -> tuple[bool, list[dict]]:
    stages: list[dict] = []
    try:
        spec = irc.compile_rate(ir)
    except (irc.IRError, ValueError) as e:
        return False, [{"stage": "compile", "passed": False, "detail": f"IR rejected: {e}"}]
    stages.append({"stage": "compile", "passed": True,
                   "detail": f"rate spec: >{spec['count']} reqs/{spec['window_s']}s "
                             f"to {spec['endpoint_prefix']} {spec['methods']}"})

    r = evaluate(stream_path, spec)
    # Stage 1: benign FP -- must break zero real users.
    fp_ok = r["benign_blocked"] == 0
    stages.append({"stage": "benign_actors", "passed": fp_ok,
                   "detail": f"benign actors rate-limited: {r['benign_blocked']}/{r['benign_actors']}"
                             f" ({r['benign_fp_rate']*100:.2f}%)", "numbers": r})
    if not fp_ok:
        return False, stages
    # Stage 2: efficacy -- must stop the attack actors of this class.
    eff_ok = r["attack_actors"] > 0 and r["attack_block_rate"] >= 0.99
    stages.append({"stage": "attack_actors", "passed": eff_ok,
                   "detail": f"attack actors stopped: {r['attack_blocked']}/{r['attack_actors']}"})
    return eff_ok, stages


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--candidates", type=Path, required=True)
    p.add_argument("--stream", type=Path, required=True,
                   help="combined benign+attack gateway log (actors+ts+UA)")
    args = p.parse_args()
    candidates = json.loads(args.candidates.read_text(encoding="utf-8"))
    print(f"rate gate: {len(candidates)} candidate(s) | stream {args.stream.name}\n")
    decisions = ROOT / "logs" / "gate" / "decisions.jsonl"
    decisions.parent.mkdir(parents=True, exist_ok=True)
    promoted = None
    for ir in candidates:
        if ir.get("mechanism") != "rate_limit":
            continue
        ok, stages = validate_candidate(ir, args.stream)
        tag = "PASSED (offline)" if ok else "REJECTED"
        print(f"[{tag}] {ir['id']}")
        for s in stages:
            print(f"  {'ok ' if s['passed'] else 'XX '}{s['stage']:16s} {s['detail']}")
        print()
        with decisions.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"id": ir["id"], "attack_class": ir["attack_class"],
                                "mechanism": "rate_limit",
                                "verdict": "passed_offline" if ok else "rejected",
                                "stages": stages}, ensure_ascii=False) + "\n")
        if ok and promoted is None:
            promoted = ir
    print(f"==> {'PROMOTED (offline): ' + promoted['id'] if promoted else 'no candidate passed'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
