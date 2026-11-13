"""Offline (no range needed): how many benign actors does the detector flag when actors are real visitor sessions
versus the replay driver's random pseudo-users? Same detector, same requests."""
import json, random, sys, tempfile, collections
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "observer"))
import actors as A, detector as D  # noqa: E402

def flagged(actors):
    by = collections.Counter(); n = 0; total = 0
    for a in actors.values():
        if len(a.requests) < 3:
            continue
        total += 1
        f = D.detect(a)
        if f:
            n += 1
            for x in f:
                by[x.technique] += 1
    return total, n, dict(by)

def load(path):
    return [r for r in A.iter_records(path)]

def pseudo(recs, users, rps, seed, n):
    rng = random.Random(seed)
    t0 = datetime(2026, 11, 1, tzinfo=timezone.utc)
    out = []
    for i in range(n):
        r = dict(rng.choice(recs))
        r["session"] = f"benign-replay-{rng.randrange(users)}"
        r["ts"] = (t0 + timedelta(seconds=i / rps)).isoformat().replace("+00:00", "Z")
        out.append(r)
    return out

def run(recs):
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    return flagged(A.reconstruct(Path(f.name)))

div = ROOT / "data" / "benign_corpus" / "benign_diverse_detect.jsonl"
recs = load(div)
print("benign_diverse requests:", len(recs))
print("A real visitor sessions:", run(recs))
ok = [r for r in recs if (r.get("uri") or "").startswith("/") and not (r.get("uri") or "").startswith("/socket.io")]
for seed in (1, 2, 3):
    print(f"B random pseudo-users (200 users, 25 rps, 24000 req, seed {seed}):", run(pseudo(ok, 200, 25, seed, 24000)))
