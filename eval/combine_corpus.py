"""Build the gate's benign corpus: every benign_*_detect.jsonl, de-duplicated by (method, URI, body),
without /socket.io polls.

    python eval/combine_corpus.py

Why distinct: the original corpus has 443k rows but ~4.1k distinct non-socket.io requests, so a
false-positive RATE over raw rows is dominated by repeated page loads. Over distinct requests, the
0.01% budget means "at most ~1 in 10,000 distinct benign request shapes may be blocked", which is the
claim we actually want. Output: data/benign_corpus/benign_00_combined_detect.jsonl (sorts first, so
every default-corpus lookup picks it).
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
d = ROOT / "data" / "benign_corpus"
out = d / "benign_00_combined_detect.jsonl"
srcs = [p for p in sorted(d.glob("benign_*detect*.jsonl")) if p.name != out.name]
seen = set()
per = {}
rows = 0
with out.open("w", encoding="utf-8") as fo:
    for p in srcs:
        kept = 0
        with p.open(encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                uri = r.get("uri") or ""
                if not uri.startswith("/") or uri.startswith("/socket.io"):
                    continue
                k = (r.get("method"), uri, r.get("body") or "")
                if k in seen:
                    continue
                seen.add(k)
                fo.write(line if line.endswith("\n") else line + "\n")
                kept += 1
        per[p.name] = kept
        rows += kept
print(f"{rows} distinct benign requests -> {out.name}")
for k, v in per.items():
    print(f"  {v:7d} from {k}")
sys.exit(0)
