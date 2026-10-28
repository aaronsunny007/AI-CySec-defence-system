"""Can the pattern library solve these campaigns AT ALL?  (diagnostic for item D)

Enumerates every choice the model could make (1-3 token classes x 4 locations, endpoint
unscoped) and sends each one through the SAME gate. A cheap Python prefilter (does the
combination match every campaign request anywhere in path+query+body?) only skips choices
that provably cannot pass the attack-replay stage. If no choice passes, a 0/N model result
says nothing about the model: the library, not the model, is the ceiling.

    python eval/pattern_oracle.py [campaign ...]
"""
import itertools
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("memory", "deliberator", "gate", "ir", "observer"):
    sys.path.insert(0, str(ROOT / p))
import gate as gatemod  # noqa: E402
import llm              # noqa: E402
import patterns         # noqa: E402

CAMPAIGNS = sys.argv[1:] or ["ssti", "nosqli", "xxe", "jndi"]


def main() -> int:
    benign = sorted((ROOT / "data" / "benign_corpus").glob("benign_*detect*.jsonl"))[0]
    names = patterns.library()
    out = {}
    for camp in CAMPAIGNS:
        d = json.loads((ROOT / "data" / "attack_corpus" / f"novel_{camp}.json").read_text(encoding="utf-8"))
        reqs = d["requests"]
        texts = [llm._decoded(r) for r in reqs]
        cover = {n: [bool(llm.VOCAB[n].search(t)) for t in texts] for n in names}
        pre, passed, stage = 0, [], {}
        for k in (1, 2, 3):
            for combo in itertools.combinations(names, k):
                if not all(any(cover[n][i] for n in combo) for i in range(len(reqs))):
                    continue
                for loc in ("query", "body", "any"):      # 'path' cannot hold these payloads
                    pre += 1
                    ir = patterns.to_ir(list(combo), loc, None, "other", "orc", pre)
                    with tempfile.TemporaryDirectory() as td:
                        ok, res = gatemod.run_gate(ir, reqs, benign, Path(td))
                    rej = next((r.stage for r in res if not r.passed), None)
                    stage[rej or "PASS"] = stage.get(rej or "PASS", 0) + 1
                    if ok:
                        passed.append((list(combo), loc))
        out[camp] = {"prefilter_survivors": pre, "gate_outcomes": stage, "passing": passed[:10],
                     "n_passing": len(passed)}
        print(camp, json.dumps(out[camp]), flush=True)
        # one file per campaign so an interrupted sweep keeps what it finished
        (ROOT / "docs" / "data" / f"pattern_oracle_{camp}.json").write_text(
            json.dumps(out[camp], indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
