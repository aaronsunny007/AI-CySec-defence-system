"""False-positive audit of every template candidate against a benign corpus.

    python eval/fp_audit.py data/benign_corpus/benign_diverse_detect.jsonl [more corpora ...]

For each signature candidate of each class: how many corpus rows it matches, how many DISTINCT
requests those are, and examples. Reading raw rows hides the problem when the corpus is mostly
repeats (see docs/E2E-RESULTS.md: 443k rows, ~4.1k distinct non-socket.io requests), so both are shown.
"""

from __future__ import annotations

import os
import collections
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("ir", "deliberator"):
    sys.path.insert(0, str(ROOT / p))
import compile as irc          # noqa: E402
import generate as g           # noqa: E402

REPLAY = ROOT / "bin" / ("replay.exe" if os.name == "nt" else "replay")
EP = {"endpoints": ["/rest/products/search", "/rest/user/login"]}


def corpus_stats(path: Path) -> tuple[int, int]:
    seen = set()
    n = 0
    with path.open(encoding="utf-8") as f:
        for line in f:
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            n += 1
            seen.add((r.get("method"), r.get("uri"), r.get("body") or ""))
    return n, len(seen)


def audit(path: Path) -> list[dict]:
    rows, distinct = corpus_stats(path)
    print(f"\n=== {path.name}: {rows} rows, {distinct} distinct requests")
    out = []
    for cls in ("sqli", "xss", "traversal", "cmdi", "ssrf"):
        for ir in g.candidates_for(cls, EP):
            if ir["mechanism"] == "rate_limit":
                continue
            with tempfile.TemporaryDirectory() as td:
                rf = Path(td) / "r.conf"
                rf.write_text(irc.compile_rule(ir), encoding="utf-8")
                o = subprocess.run([str(REPLAY), "-rule", str(rf), "-corpus", str(path), "-indices", "100000", "-samples", "0"],
                                   capture_output=True, text=True)
            if o.returncode != 0:
                print(ir["id"], "ENGINE ERROR", o.stderr.strip()[:100])
                continue
            res = json.loads(o.stdout.strip().splitlines()[-1])
            idx = set(res.get("matched_idx", []))
            ex = collections.Counter()
            if idx:
                with path.open(encoding="utf-8") as f:
                    for i, line in enumerate(f):
                        if i in idx:
                            r = json.loads(line)
                            ex[(r.get("method"), (r.get("uri") or "")[:70], (r.get("body") or "")[:70])] += 1
            rec = {"rule": ir["id"], "rows_matched": res["matched"], "rate_rows": res["rate"],
                   "distinct_matched": len(ex), "examples": [list(k) + [v] for k, v in ex.most_common(3)]}
            out.append(rec)
            flag = "" if res["matched"] == 0 else "  <-- FP"
            print(f"{ir['id']:20s} rows {res['matched']:6d} ({res['rate']*100:.4f}%)  distinct {len(ex):5d}{flag}")
            for k, v in ex.most_common(2):
                print("      e.g.", v, "x", k)
    return out


def main() -> int:
    res = {}
    for a in sys.argv[1:]:
        res[Path(a).name] = audit(Path(a))
    (ROOT / "docs" / "data" / "fp_audit.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
