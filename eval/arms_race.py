"""Adaptive adversary arms race -- M4.

A red agent that changes technique over time; AEGIS must mitigate each new move.
We replay a sequence of campaigns (new techniques, a variant, a repeat) through
the mitigation loop and measure:
  - coverage: did AEGIS mitigate every move?
  - memory effect: time-to-mitigate per move, and the source
    (fresh / generalised / reused) -- so the adversary's REPEAT and VARIANT
    moves are met faster than the first time, which is the point of M3 under
    adversarial pressure.

Uses recorded attack traffic per class (logs/attacks/requests.jsonl). Signature
classes go through the full gate; this is the closed loop under an adversary who
does not stand still.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("memory", "observer", "ir", "deliberator", "gate"):
    sys.path.insert(0, str(ROOT / p))
from store import Memory          # noqa: E402
from mitigate import mitigate     # noqa: E402

CLASS_OF = {"sqli": "sqli", "xss": "xss", "path_traversal": "traversal",
            "command_injection": "cmdi", "ssrf": "ssrf"}


def load_campaign(attack_log: Path, campaign_name: str) -> tuple[dict, list[dict]]:
    rows = [json.loads(l) for l in attack_log.read_text(encoding="utf-8").splitlines() if l.strip()]
    # The attack log is cumulative (every run appends), so use ONE run only: the
    # most recent actor of this campaign. Mixing runs would drag in rows labelled
    # under older versions of the campaign (e.g. before a mislabel was fixed).
    of_class = [r for r in rows if r["attack_class"] == campaign_name]
    last_actor = of_class[-1]["actor"] if of_class else None
    mal = [r for r in of_class if r["actor"] == last_actor and r.get("malicious")]
    cls = CLASS_OF.get(campaign_name, campaign_name)
    endpoints = sorted({("/".join("{id}" if p.isdigit() else p
                                  for p in r["uri"].split("?")[0].split("/")))
                        for r in mal})
    dossier = {"techniques": [cls], "attack_class": cls, "endpoints": endpoints}
    return dossier, mal


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--attack-log", type=Path, default=ROOT / "logs" / "attacks" / "requests.jsonl")
    p.add_argument("--benign", type=Path,
                   default=(sorted((ROOT / "data" / "benign_corpus").glob("benign_*detect*.jsonl")) or [None])[0])
    p.add_argument("--db", type=Path, default=ROOT / "memory" / "armsrace.db")
    args = p.parse_args()

    if args.db.exists():
        args.db.unlink()  # fresh memory: the adversary starts against a naive AEGIS
    mem = Memory(args.db)

    # The adversary's moves: new technique, new technique, a VARIANT of move 1,
    # another new technique, then a REPEAT of move 1.
    moves = [
        ("move 1: SQLi", "sqli", None),
        ("move 2: XSS", "xss", None),
        ("move 3: path traversal", "path_traversal", None),
        ("move 4: SQLi VARIANT (union-only, search)", "sqli", "variant"),
        ("move 5: SQLi REPEAT (move 1 again)", "sqli", "repeat"),
    ]

    print(f"arms race: {len(moves)} adversary moves vs AEGIS (memory starts empty)\n")
    results = []
    for label, campaign_name, kind in moves:
        dossier, mal = load_campaign(args.attack_log, campaign_name)
        if kind == "variant":
            mal = [r for r in mal if "UNION" in (r["uri"] + r["body"]).upper()]
            dossier = {**dossier, "endpoints": ["/rest/products/search"]}
        r = mitigate(dossier, mal, args.benign, mem)
        results.append((label, r))
        print(f"  {label:42s} -> {r['source']:12s} {r['ttm_s']*1000:8.1f} ms  rule={r['rule']}")

    mitigated = sum(1 for _, r in results if r["source"] != "none")
    print(f"\ncoverage: {mitigated}/{len(results)} moves mitigated")
    fresh = [r for _, r in results if r["source"] == "fresh"]
    reused = [r for _, r in results if r["source"] in ("reused", "generalised")]
    if fresh and reused:
        avg_fresh = sum(r["ttm_s"] for r in fresh) / len(fresh)
        avg_reuse = sum(r["ttm_s"] for r in reused) / len(reused)
        print(f"avg time-to-mitigate: fresh {avg_fresh*1000:.0f} ms vs "
              f"reused/generalised {avg_reuse*1000:.1f} ms "
              f"({avg_fresh/avg_reuse:.0f}x faster under repeat/variant pressure)")
    print("memory:", json.dumps(mem.stats()))
    mem.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
