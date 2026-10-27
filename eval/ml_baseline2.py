"""A stronger static ML-WAF baseline (spec baseline 3), trained on REAL public attack data.

The first baseline (ml_baseline.py) was a hashed n-gram logistic regression trained on attacks from
my own generator, which says more about my generator than about ML-WAFs. This one:

  * trains on the public HttpParamsDataset (github.com/Morzeux/HttpParamsDataset: 19,304 benign values
    from CSIC-2010 and 11,763 attack values made with sqlmap, XSSYA, Vega and FuzzDB: SQLi, XSS,
    command injection, path traversal), wrapped as ordinary requests, PLUS the benign requests of all
    four of our corpora (Juice Shop, diverse sessions, BookNook, DVWA);
  * uses two stronger models: character TF-IDF (2-5-grams) + logistic regression, and gradient-boosted
    trees (sklearn HistGradientBoosting) over engineered payload features; the ensemble takes the max;
  * sets the threshold on a validation split of benign requests so at most 0.01 % of raw benign rows
    are flagged (AEGIS's own budget), exactly as in the first baseline;
  * tests on the REAL campaign requests our scripts send (and their mutants), on four families never
    trained, on the behavioural campaigns, and on a held-out slice of the public dataset (sanity check).

Dataset location: ~/tools/_downloads/httpparams/payload_full.csv (not committed; see docs/ML-BASELINE.md).
Run with the system python (numpy/scipy/sklearn): python eval/ml_baseline2.py
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import re
import sys
import urllib.parse
from pathlib import Path

import numpy as np
from scipy import sparse
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT / "range" / "mutate"))
import ml_baseline as M1       # noqa: E402  (loaders, normaliser, split)
import mutate as mut           # noqa: E402

DATASET = Path.home() / "tools" / "_downloads" / "httpparams" / "payload_full.csv"
KEYWORDS = ["select", "union", "insert", "update", "delete", "drop", "sleep", "benchmark", "or ", "and ", "where",
            "from", "exec", "script", "alert", "onerror", "onload", "javascript", "../", "..\\", "/etc/", "passwd",
            "whoami", "cat ", "ls ", "ping", "curl", "wget", "http://", "https://", "file://", "<!", "${", "{{", "%00"]


def wrap(value: str) -> dict:
    return {"method": "GET", "uri": "/search?q=" + urllib.parse.quote(value, safe=""), "body": ""}


def engineered(text: str) -> list[float]:
    n = max(len(text), 1)
    ch = lambda cs: sum(text.count(c) for c in cs)       # noqa: E731
    ent = 0.0
    for c in set(text):
        p = text.count(c) / n
        ent -= p * math.log2(p)
    f = [len(text), ch("'"), ch('"'), ch(";"), ch("|"), ch("&"), ch("<"), ch(">"), ch("()"), ch("="), ch("-"), ch("#"),
         ch("/"), ch("\\"), ch("%"), ch("`"), ch("$"), ch("{}"), ch("\n\r"),
         sum(c.isdigit() for c in text) / n, sum(not c.isalnum() and not c.isspace() for c in text) / n,
         sum(c.isspace() for c in text) / n, ent]
    f += [text.count(k) for k in KEYWORDS]
    return f


def load_dataset():
    rows = []
    with DATASET.open(encoding="utf-8", errors="replace", newline="") as fh:
        for r in csv.DictReader(fh):
            v = r.get("payload") or ""
            lab = (r.get("attack_type") or r.get("label") or "").strip()
            if v:
                rows.append((v, lab))
    return rows


def main() -> int:
    if not DATASET.exists():
        print("dataset missing:", DATASET)
        return 1
    ds = load_dataset()
    labs = sorted({l for _, l in ds})
    print("dataset:", len(ds), "values; labels:", {l: sum(1 for _, x in ds if x == l) for l in labs}, flush=True)

    # --- benign: all four corpora, distinct requests with multiplicity, hash-split 30/30/40 ----------
    corp = ROOT / "data" / "benign_corpus"
    paths = [corp / "benign_00_combined_detect.jsonl", corp / "booknook_corpus.jsonl", corp / "dvwa_corpus.jsonl"]
    tr, va, te = [], [], []
    for p in paths:
        if p.exists():
            a, b, c = M1.load_benign(p)
            tr += a
            va += b
            te += c
            print(f"benign {p.name}: distinct train/val/test = {len(a)}/{len(b)}/{len(c)}", flush=True)

    # --- dataset: hash split too; train on 60 %, hold out 40 % -------------------------------------------
    def part(v: str) -> int:
        return 0 if hashlib.md5(v.encode("utf-8", "replace")).digest()[0] < 153 else 1
    d_tr = [(wrap(v), l) for v, l in ds if part(v) == 0]
    d_te = [(wrap(v), l) for v, l in ds if part(v) == 1]
    is_norm = lambda l: l.startswith("norm")         # noqa: E731

    train_recs = [dict(r, w=min(r["w"], 20)) for r in tr] + [dict(r, w=1) for r, _ in d_tr]
    ytrain = np.array([0] * len(tr) + [0 if is_norm(l) else 1 for _, l in d_tr], dtype=np.int8)
    wtrain = np.array([min(r["w"], 20) for r in tr] + [1.0] * len(d_tr), dtype=np.float64)
    wtrain[ytrain == 1] *= max(1.0, wtrain[ytrain == 0].sum() / max(1, wtrain[ytrain == 1].sum()))   # balance classes
    texts = [M1.norm(r["method"], r["uri"], r.get("body", "")) for r in train_recs]
    print("train docs:", len(texts), "attacks:", int(ytrain.sum()), flush=True)

    tfidf = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), max_features=250000, sublinear_tf=True, lowercase=False,
                            dtype=np.float32)
    Xt = tfidf.fit_transform(texts)
    lr = LogisticRegression(C=8.0, max_iter=400, solver="liblinear")
    lr.fit(Xt, ytrain, sample_weight=wtrain)
    E = np.array([engineered(t) for t in texts], dtype=np.float32)
    hgb = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1, max_leaf_nodes=31, random_state=1)
    hgb.fit(E, ytrain, sample_weight=wtrain)

    def score(recs):
        tx = [M1.norm(r["method"], r["uri"], r.get("body", "")) for r in recs]
        if not tx:
            return np.array([])
        s1 = lr.decision_function(tfidf.transform(tx))
        s2 = hgb.predict_proba(np.array([engineered(t) for t in tx], dtype=np.float32))[:, 1]
        s2 = np.log(np.clip(s2, 1e-6, 1 - 1e-6) / (1 - np.clip(s2, 1e-6, 1 - 1e-6)))
        return {"tfidf+lr": s1, "gbdt": s2, "ensemble(max)": np.maximum(s1, s2)}

    sva = score(va)
    wva = np.array([r["w"] for r in va], dtype=np.float64)
    wte = np.array([r["w"] for r in te], dtype=np.float64)
    ste = score(te)
    thr, thr_lax, fp = {}, {}, {}
    for m in sva:
        def wthr(budget, m=m):
            order = np.argsort(-sva[m])
            cum = np.cumsum(wva[order]) / wva.sum()
            k = int(np.searchsorted(cum, budget, side="right"))
            return float(sva[m][order][k]) if k < len(order) else float(sva[m].min())
        thr[m], thr_lax[m] = wthr(1e-4), wthr(1e-3)
        fp[m] = float(wte[ste[m] > thr[m]].sum() / wte.sum())
        print(f"{m:15s} threshold {thr[m]:7.2f}: test benign FP at the 0.01% threshold = {fp[m]*100:.4f}% of raw rows, "
              f"{float((ste[m] > thr[m]).mean())*100:.2f}% of distinct", flush=True)

    def rate(recs):
        if not recs:
            return {m: (float("nan"), float("nan")) for m in thr}
        s = score(recs)
        return {m: (float((s[m] > thr[m]).mean()), float((s[m] > thr_lax[m]).mean())) for m in thr}

    rows = []
    # sanity: held-out slice of the public dataset, per attack type
    for l in labs:
        if not is_norm(l):
            rows.append((f"held-out public dataset: {l}", rate([r for r, x in d_te if x == l])))
    camps = M1.campaign_requests(ROOT / "logs" / "attacks" / "m1_episode_attacks.jsonl")
    for c in ("sqli", "xss", "path_traversal", "command_injection", "ssrf"):
        reqs = camps.get(c, [])
        rows.append((f"REAL campaign requests: {c}", rate(reqs)))
        rows.append((f"  ...their mutants: {c}", rate(mut.mutate_corpus(reqs))))
    for fam in ("ssti", "nosqli", "xxe", "jndi"):
        d = json.loads((ROOT / "data" / "attack_corpus" / f"novel_{fam}.json").read_text(encoding="utf-8"))
        rows.append((f"NOVEL family (never trained): {fam}", rate(d["requests"])))
    for c in ("credential_stuffing", "idor_bola", "user_enumeration"):
        rows.append((f"behavioural campaign, per request: {c}", rate(camps.get(c, []))))

    out = {"dataset": "Morzeux/HttpParamsDataset (payload_full.csv)", "benign_distinct": {"train": len(tr), "validation": len(va), "test": len(te)},
           "fp_test_raw_rows_at_0.01pct_threshold": fp, "rows": []}
    hdr = f"\n{'what':52s}" + "".join(f"{m:>22s}" for m in thr)
    print(hdr)
    print(" " * 52 + "".join(f"{'@0.01% / @0.1% FP':>22s}" for _ in thr))
    for w, r in rows:
        print(f"{w:52s}" + "".join(f"{r[m][0]*100:12.1f}% /{r[m][1]*100:6.1f}%" for m in thr))
        out["rows"].append({"what": w, **{m: {"at_fp_0.01pct": r[m][0], "at_fp_0.1pct": r[m][1]} for m in thr}})
    (ROOT / "docs" / "data" / "ml_baseline2.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
