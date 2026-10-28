"""Build data/idor_ceilings.json: for each id-bearing endpoint, the most distinct object ids any ONE benign
actor was seen touching in the curated benign corpora.

    python eval/idor_baseline.py data/benign_corpus/benign_diverse_detect.jsonl [more corpora ...]

The observer's IDOR/BOLA detector (observer/detector.py) flags an actor that walks 4+ distinct ids on one
endpoint. That is right for private objects (/rest/basket/{id}: a normal user touches exactly one) and wrong
for public browsing (/rest/products/{id}/reviews: a shopper legitimately opens several products), which
produced ~90 false campaigns per Juice Shop run. This file records, per endpoint, what real benign actors do,
and the detector requires an actor to go well past it.

This is OFFLINE, curated data produced by a script a person runs (CLAUDE.md invariant 6): nothing the
detector sees at runtime changes it, so an attacker cannot talk it into a higher ceiling.
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "observer"))
import actors as A  # noqa: E402

OUT = ROOT / "data" / "idor_ceilings.json"


def main(paths: list[str]) -> int:
    ceil: dict[str, int] = collections.defaultdict(int)
    n_actors = 0
    for p in paths:
        for a in A.reconstruct(Path(p)).values():
            n_actors += 1
            by = collections.defaultdict(set)
            for r in a.requests:
                ids = [s for s in r.path.split("/") if s.isdigit()]
                if ids:
                    by[r.endpoint].update(ids)
            for ep, ids in by.items():
                ceil[ep] = max(ceil[ep], len(ids))
    doc = {"_note": "max distinct ids one benign actor touched per endpoint; see eval/idor_baseline.py",
           "_sources": [Path(p).name for p in paths], "_actors": n_actors,
           "ceilings": dict(sorted(ceil.items()))}
    OUT.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    print(f"{n_actors} actors -> {OUT.relative_to(ROOT)}")
    for ep, c in doc["ceilings"].items():
        print(f"  {ep:45s} {c}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
