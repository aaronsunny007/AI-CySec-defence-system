"""Capture a diverse benign corpus through the gateway in detect mode (CRS verdicts logged, nothing blocked).

    python eval/diverse_capture.py --requests 60000 --out data/benign_corpus/benign_diverse_detect.jsonl
"""
import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT / "gate"))
sys.path.insert(0, str(ROOT / "range" / "benign"))
import diverse                       # noqa: E402
from rangectl import Range           # noqa: E402
import rulestore                     # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--requests", type=int, default=2000)
ap.add_argument("--threads", type=int, default=8)
ap.add_argument("--seed", type=int, default=1)
ap.add_argument("--out", type=Path, default=ROOT / "data" / "benign_corpus" / "benign_diverse_detect.jsonl")
a = ap.parse_args()
a.out = a.out.resolve()
a.out.unlink(missing_ok=True)
rulestore.clear()
t0 = time.time()
with Range(mode="detect", log=str(a.out.relative_to(ROOT))):
    ths, counter = diverse.run(a.requests, 0, a.threads, a.seed)
    for t in ths:
        t.join()
    print(f"driver sent ~{counter[0]} requests in {time.time()-t0:.0f}s", flush=True)
    time.sleep(3)
print("lines:", sum(1 for _ in a.out.open(encoding="utf-8")))
