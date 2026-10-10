"""Baseline episode orchestrator for M0.

Runs one full episode against the CRS baseline and writes the number the whole
project is measured against:

    "OWASP CRS alone stops X% of attack campaigns at Y% false-positive rate
     on our benign corpus, breaking Z% of legitimate user journeys."

An episode:
  1. reset state           -- restart the range (Juice Shop reloads its DB)
  2. benign warmup         -- run N journeys in ENFORCE mode; measure journeys
                              broken BY THE DEFENCE (safety)
  3. attack                -- run the 8 campaigns in ENFORCE mode; measure
                              campaigns contained + request block rate (security)
  4. false positives       -- scan the saved benign corpus for would-block
                              (the honest FP rate; corpus was collected in detect)
  5. system                -- inline WAF latency from the corpus
  6. write eval/metrics.jsonl (append) and docs/BASELINE.md

Usage:
    python eval/baseline.py --journeys 300
    python eval/baseline.py --no-reset --journeys 100   # range already enforcing

Orchestrates the PowerShell range scripts and the venv Python; run it with the
venv interpreter:  .venv\\Scripts\\python eval\\baseline.py
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable  # the venv python running this
THRESHOLD = 5        # CRS inbound anomaly threshold (matches gateway default)


def ps(script: str, *args: str) -> None:
    subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File",
                    str(ROOT / "range" / script), *args], check=False, cwd=ROOT)


def wait_up(url: str, seconds: int) -> bool:
    for _ in range(seconds):
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except urllib.error.HTTPError:
            return True
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    return False


def tail_new(path: Path, since: int) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= since and line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return rows


def line_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(encoding="utf-8") as f:
        return sum(1 for _ in f)


def newest_corpus() -> Path | None:
    d = ROOT / "data" / "benign_corpus"
    files = sorted(d.glob("benign_*detect*.jsonl"))
    return files[-1] if files else None


def fp_from_corpus(path: Path) -> dict:
    n = 0
    fp = 0
    fp_no_push = 0
    lat = []
    by_rule: Counter = Counter()
    with path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("user_agent") == "aegis-smoke/0.1":
                continue
            n += 1
            if r.get("waf_us") is not None:
                lat.append(r["waf_us"])
            if r.get("anomaly_score", 0) >= THRESHOLD:
                fp += 1
                if not str(r.get("uri", "")).startswith("/socket.io"):
                    fp_no_push += 1
                for rid in r.get("rule_ids", []):
                    by_rule[rid] += 1
    lat.sort()
    def pct(p): return lat[min(int(len(lat) * p), len(lat) - 1)] if lat else 0
    return {
        "benign_requests": n,
        "fp": fp, "fp_rate": fp / n if n else 0,
        "fp_no_push": fp_no_push, "fp_rate_no_push": fp_no_push / n if n else 0,
        "waf_us_p50": pct(0.50), "waf_us_p95": pct(0.95), "waf_us_p99": pct(0.99),
        "top_rules": by_rule.most_common(6),
    }


def run_benign(journeys: int) -> dict:
    before = line_count(ROOT / "logs" / "benign" / "journeys.jsonl")
    subprocess.run([PY, str(ROOT / "range" / "benign" / "generate.py"),
                    "--workers", "4", "--fast", "--journeys", str(journeys),
                    "--seed", "777"], check=False, cwd=ROOT)
    rows = tail_new(ROOT / "logs" / "benign" / "journeys.jsonl", before)
    broken_defence = sum(1 for r in rows if not r["ok"] and r.get("cause") == "defence")
    broken_app = sum(1 for r in rows if not r["ok"] and r.get("cause") == "app")
    return {
        "journeys": len(rows),
        "ok": sum(r["ok"] for r in rows),
        "broken_by_defence": broken_defence,
        "broken_by_app": broken_app,
        "pct_broken_by_defence": broken_defence / len(rows) if rows else 0,
    }


def run_attacks() -> dict:
    before = line_count(ROOT / "logs" / "attacks" / "requests.jsonl")
    subprocess.run([PY, str(ROOT / "range" / "attacks" / "run.py"), "--pace", "0.1"],
                   check=False, cwd=ROOT)
    rows = tail_new(ROOT / "logs" / "attacks" / "requests.jsonl", before)
    by_campaign: dict[str, dict] = {}
    for r in rows:
        c = by_campaign.setdefault(r["campaign"], {"fired": 0, "blocked": 0})
        c["fired"] += 1
        c["blocked"] += bool(r["blocked"])
    # A malicious request is "stopped" if blocked; recon steps are benign.
    mal = [r for r in rows if r.get("malicious")]
    mal_blocked = sum(1 for r in mal if r["blocked"])
    # A campaign is "contained" if its exploit/exfil stages were fully blocked.
    contained = 0
    for c, rs in {c: [r for r in rows if r["campaign"] == c] for c in by_campaign}.items():
        exploit = [r for r in rs if r["stage"] in ("exploit", "exfil") and r.get("malicious")]
        if exploit and all(r["blocked"] for r in exploit):
            contained += 1
    return {
        "campaigns": len(by_campaign),
        "campaigns_contained": contained,
        "pct_campaigns_contained": contained / len(by_campaign) if by_campaign else 0,
        "malicious_requests": len(mal),
        "malicious_blocked": mal_blocked,
        "malicious_block_rate": mal_blocked / len(mal) if mal else 0,
        "per_campaign": by_campaign,
    }


def write_baseline(m: dict) -> None:
    b = m["benign"]
    a = m["attacks"]
    s = m["safety_fp"]
    doc = f"""# BASELINE — OWASP CRS alone

**This is the denominator of every claim in AEGIS.** Generated by
`eval/baseline.py`. Do not edit by hand; re-run the harness.

| Field | Value |
|---|---|
| Date | {m['ts']} |
| Config | OWASP CRS {m['config']['crs']} on Coraza {m['config']['coraza']}, paranoia {m['config']['pl']}, anomaly threshold {m['config']['threshold']} |
| Target | OWASP Juice Shop {m['config']['app']} |
| Mode | enforce |

## The number

> **OWASP CRS alone contains {a['pct_campaigns_contained']*100:.0f}% of attack campaigns
> ({a['campaigns_contained']}/{a['campaigns']}) and blocks {a['malicious_block_rate']*100:.0f}% of malicious requests,
> at a {s['fp_rate']*100:.3f}% false-positive rate on {s['benign_requests']:,} benign requests
> ({s['fp_rate_no_push']*100:.3f}% excluding the socket.io push channel),
> breaking {b['pct_broken_by_defence']*100:.2f}% of legitimate user journeys.**

Spec budgets: FP ≤ 0.01%; legitimate journeys broken = 0; inline p99 ≤ 1 ms.

## Security — attacks (enforce mode)

| Campaign | fired | blocked (403) |
|---|---|---|
""" + "\n".join(
        f"| {c} | {d['fired']} | {d['blocked']} |" for c, d in sorted(a["per_campaign"].items())
    ) + f"""

Campaigns contained (all exploit/exfil requests blocked): **{a['campaigns_contained']}/{a['campaigns']}**.
Malicious requests blocked: **{a['malicious_blocked']}/{a['malicious_requests']}** ({a['malicious_block_rate']*100:.1f}%).

## Safety — false positives (benign corpus, {s['benign_requests']:,} requests)

- FP rate: **{s['fp_rate']*100:.3f}%** ({s['fp']:,} requests) — **{s['fp_rate']/0.0001:.0f}× over the 0.01% budget**
- Excluding socket.io push channel: **{s['fp_rate_no_push']*100:.3f}%** ({s['fp_no_push']:,})
- Legitimate journeys broken by the defence (enforce warmup, {b['journeys']} journeys): **{b['broken_by_defence']}** ({b['pct_broken_by_defence']*100:.2f}%); by app bug: {b['broken_by_app']}
- Top false-positive rules: {', '.join(f'{r}×{n}' for r, n in s['top_rules'])}

## System

- Inline WAF latency: p50 **{s['waf_us_p50']/1000:.2f} ms**, p95 **{s['waf_us_p95']/1000:.2f} ms**, p99 **{s['waf_us_p99']/1000:.2f} ms** — budget p99 ≤ 1 ms.

## How this is beaten

AEGIS must raise campaign containment and the malicious block rate **while
driving FP rate under 0.01% and journeys-broken to 0**. The gap between "blocks
attacks" (CRS already does, mostly) and "does not break the app" (CRS fails
badly here) is the thesis.
"""
    (ROOT / "docs" / "BASELINE.md").write_text(doc, encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--journeys", type=int, default=300, help="benign warmup journeys")
    p.add_argument("--no-reset", action="store_true", help="range already up in enforce mode")
    args = p.parse_args()

    corpus = newest_corpus()
    if corpus is None:
        print("no benign corpus in data/benign_corpus/ -- collect it first", file=sys.stderr)
        return 2

    if not args.no_reset:
        print("[1/6] resetting range (enforce mode)...")
        ps("stop.ps1")
        ps("start.ps1", "-Mode", "enforce")
    if not wait_up("http://localhost:8080", 60):
        print("range not reachable at :8080", file=sys.stderr)
        return 2

    print(f"[2/6] benign warmup ({args.journeys} journeys, enforce)...")
    benign = run_benign(args.journeys)
    print(f"      {benign['ok']}/{benign['journeys']} ok, "
          f"broken by defence: {benign['broken_by_defence']}")

    print("[3/6] attack campaigns (enforce)...")
    attacks = run_attacks()
    print(f"      contained {attacks['campaigns_contained']}/{attacks['campaigns']}, "
          f"malicious block rate {attacks['malicious_block_rate']*100:.0f}%")

    print(f"[4-5/6] false positives + latency from corpus ({corpus.name})...")
    safety = fp_from_corpus(corpus)
    print(f"      FP {safety['fp_rate']*100:.3f}%  p99 {safety['waf_us_p99']/1000:.2f} ms")

    metrics = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "episode": "baseline-crs",
        "config": {"crs": "4.25", "coraza": "3.8.1", "pl": 1, "threshold": THRESHOLD,
                   "app": "20.2.0", "corpus": corpus.name},
        "benign": benign, "attacks": attacks, "safety_fp": safety,
    }
    print("[6/6] writing metrics.jsonl + docs/BASELINE.md ...")
    with (ROOT / "eval" / "metrics.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(metrics, ensure_ascii=False) + "\n")
    write_baseline(metrics)
    print("\nBASELINE written to docs/BASELINE.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
