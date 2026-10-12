"""Run attack campaigns against the local range and report what happened.

    python range/attacks/run.py --list
    python range/attacks/run.py                       # all 8 campaigns
    python range/attacks/run.py --only sqli idor_bola --pace 0.3
    python range/attacks/run.py --base http://localhost:8080 --log logs/attacks/requests.jsonl

Reports, per campaign: requests fired, how many the gateway returned 403 for,
and whether the campaign's objective was met. In -mode enforce a high block
rate with objective_met=False is the gateway doing its job; in -mode detect
nothing is blocked (score coverage from the gateway's own log instead).

This is the attack half of the eval. It does not reset the app -- the harness
(eval/) is responsible for ordering: reset -> benign warmup -> attack -> measure.
All targets are the local range only.
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import campaigns as C  # noqa: E402
from client import Actor  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def gateway_up(base: str) -> bool:
    try:
        urllib.request.urlopen(base, timeout=5)
        return True
    except urllib.error.HTTPError:
        return True  # any HTTP response means it is listening
    except (urllib.error.URLError, OSError):
        return False


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--base", default="http://127.0.0.1:8080")
    p.add_argument("--log", type=Path, default=ROOT / "logs" / "attacks" / "requests.jsonl")
    p.add_argument("--only", nargs="+", choices=list(C.CAMPAIGNS))
    p.add_argument("--pace", type=float, default=0.2,
                   help="seconds between requests within a campaign")
    p.add_argument("--ua", choices=["browser", "tool"], default="browser",
                   help="browser = spoofed browser UA (default, the honest case); "
                        "tool = announce the scanner (CRS blocks those on UA alone)")
    p.add_argument("--list", action="store_true")
    args = p.parse_args()

    if args.list:
        for name in C.CAMPAIGNS:
            print(name)
        return 0

    if not gateway_up(args.base):
        print(f"gateway not reachable at {args.base} -- start the range first", file=sys.stderr)
        return 2

    names = args.only or list(C.CAMPAIGNS)
    args.log.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    with args.log.open("a", encoding="utf-8") as out:
        for name in names:
            actor = Actor(base=args.base, campaign=name, attack_class=name,
                          user_agent=C.user_agent_for(name, args.ua), out=out)
            result = C.CAMPAIGNS[name](actor, args.pace)
            rows.append((name, actor, result))
            flag = "OBJECTIVE MET" if result["objective_met"] else "contained/failed"
            print(f"{name:22s} fired={actor.fired:3d}  403={actor.blocked_count:3d}  "
                  f"{flag}" + (f"  [{result['evidence']}]" if result["evidence"] else ""))

    fired = sum(a.fired for _, a, _ in rows)
    blocked = sum(a.blocked_count for _, a, _ in rows)
    met = sum(r["objective_met"] for _, _, r in rows)
    print(f"\n{len(rows)} campaigns | requests {fired} | 403 {blocked} "
          f"({100 * blocked / fired:.0f}%) | objectives met {met}/{len(rows)}")
    print(f"detail -> {args.log}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
