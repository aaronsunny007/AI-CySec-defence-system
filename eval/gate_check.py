"""Offline gate check of the template candidates for one class against captured evidence.

    python eval/gate_check.py --log logs/gateway/app2.jsonl --label attack:sqli --tech sqli \
        --corpus data/benign_corpus/booknook_corpus.jsonl --endpoints /api/books /api/login

Evidence = the requests the observer's own signature matches for the last attacker identity in the
log (exactly what the controller feeds the gate). Prints every candidate's per-stage verdict.
"""
import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("ir", "deliberator", "gate", "memory", "observer"):
    sys.path.insert(0, str(ROOT / p))
from actors import Actor, actor_key, to_request  # noqa: E402
from detector import evidence                      # noqa: E402
import generate as g                               # noqa: E402
import gate as gm                                  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--log", type=Path, required=True)
ap.add_argument("--label", required=True)
ap.add_argument("--tech", required=True)
ap.add_argument("--corpus", type=Path, required=True)
ap.add_argument("--endpoints", nargs="*", default=[])
a = ap.parse_args()
recs = [json.loads(l) for l in a.log.open(encoding="utf-8") if f'"gt_label":"{a.label}"' in l]
key = actor_key(recs[-1])
act = Actor(key=key, requests=[to_request(r) for r in recs if actor_key(r) == key])
ev = evidence(act, a.tech)
reqs = [{"method": r.method, "uri": r.raw["uri"], "body": r.body,
         "content_type": r.raw.get("content_type") or "application/json"} for r in ev]
print(f"{len(reqs)} evidence requests from identity {key}")
for c in g.candidates_for(a.tech if a.tech != "cmdi" else "cmdi", {"endpoints": a.endpoints}):
    ok, res = gm.run_gate(c, reqs, a.corpus, Path(tempfile.mkdtemp()))
    print(c["id"], "PASS" if ok else "REJECT", [(r.stage, r.passed, r.detail[:70]) for r in res if r.stage != "compile"][-3:])
