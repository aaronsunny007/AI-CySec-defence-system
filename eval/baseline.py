"""Baseline episode orchestrator (M0) -- OWASP CRS alone.

One range boot in ENFORCE mode, then:
  1. benign warmup      real Playwright journeys; count journeys broken BY THE DEFENCE
  2. attacks, browser   attackers send a spoofed browser user-agent   <- HEADLINE
  3. attacks, tool      attackers announce themselves (sqlmap, nuclei, ...)
  4. FP + latency       from the saved 443k benign corpus (detect-mode capture)

Why two attacker modes: CRS rule 913100 blocks ANY request from a known scanner
user-agent -- even a harmless GET /. An earlier baseline used announcing
attackers only, so "CRS blocked it" partly meant "CRS read the name tag". Real
attackers spoof the UA, so the browser-UA run is the honest headline; the tool-UA
run is kept (and its harmless-request blocks counted) to show the confound.

Writes eval/metrics.jsonl and docs/BASELINE.md.

    .venv\\Scripts\\python eval\\baseline.py --journeys 300
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))
from rangectl import Range  # noqa: E402

PY = sys.executable
THRESHOLD = 5  # CRS inbound anomaly threshold (gateway default)
LINE = re.compile(r"^(\w+)\s+fired=\s*(\d+)\s+403=\s*(\d+)\s+(OBJECTIVE MET|contained/failed)")


def line_count(p: Path) -> int:
    return sum(1 for _ in p.open(encoding="utf-8")) if p.exists() else 0


def rows_since(p: Path, n: int) -> list[dict]:
    out = []
    if p.exists():
        with p.open(encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i >= n and line.strip():
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return out


def newest_corpus() -> Path | None:
    files = sorted((ROOT / "data" / "benign_corpus").glob("benign_*detect*.jsonl"))
    return files[-1] if files else None


def fp_from_corpus(path: Path) -> dict:
    n = fp = fp_no_push = 0
    lat, by_rule = [], Counter()
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
    pct = lambda p: lat[min(int(len(lat) * p), len(lat) - 1)] if lat else 0
    return {"benign_requests": n, "fp": fp, "fp_rate": fp / n if n else 0,
            "fp_no_push": fp_no_push, "fp_rate_no_push": fp_no_push / n if n else 0,
            "waf_us_p50": pct(.5), "waf_us_p95": pct(.95), "waf_us_p99": pct(.99),
            "top_rules": by_rule.most_common(6)}


def run_benign(journeys: int) -> dict:
    jp = ROOT / "logs" / "benign" / "journeys.jsonl"
    before = line_count(jp)
    subprocess.run([PY, str(ROOT / "range" / "benign" / "generate.py"), "--workers", "4",
                    "--fast", "--journeys", str(journeys), "--seed", "777"], check=False, cwd=ROOT)
    rows = rows_since(jp, before)
    bd = sum(1 for r in rows if not r["ok"] and r.get("cause") == "defence")
    ba = sum(1 for r in rows if not r["ok"] and r.get("cause") == "app")
    return {"journeys": len(rows), "ok": sum(r["ok"] for r in rows), "broken_by_defence": bd,
            "broken_by_app": ba, "pct_broken_by_defence": bd / len(rows) if rows else 0}


def run_attacks(ua: str) -> dict:
    log = ROOT / "logs" / "attacks" / "requests.jsonl"
    before = line_count(log)
    out = subprocess.run([PY, str(ROOT / "range" / "attacks" / "run.py"), "--pace", "0.1",
                          "--ua", ua], capture_output=True, text=True, cwd=ROOT,
                         encoding="utf-8", errors="replace")
    objective = {}
    for ln in out.stdout.splitlines():
        m = LINE.match(ln.strip())
        if m:
            objective[m.group(1)] = m.group(4) == "OBJECTIVE MET"
    rows = rows_since(log, before)
    per = {}
    for c in sorted({r["campaign"] for r in rows}):
        rs = [r for r in rows if r["campaign"] == c]
        mal = [r for r in rs if r.get("malicious")]
        recon = [r for r in rs if not r.get("malicious")]
        expl = [r for r in mal if r["stage"] in ("exploit", "exfil")]
        per[c] = {"fired": len(rs), "malicious": len(mal),
                  "malicious_blocked": sum(bool(r["blocked"]) for r in mal),
                  "recon": len(recon), "recon_blocked": sum(bool(r["blocked"]) for r in recon),
                  "contained": bool(expl) and all(r["blocked"] for r in expl),
                  "objective_met": objective.get(c)}
    mal_n = sum(v["malicious"] for v in per.values())
    mal_b = sum(v["malicious_blocked"] for v in per.values())
    n = len(per)
    return {
        "ua_mode": ua, "campaigns": n, "per_campaign": per,
        "campaigns_contained": sum(v["contained"] for v in per.values()),
        "malicious_requests": mal_n, "malicious_blocked": mal_b,
        "malicious_block_rate": mal_b / mal_n if mal_n else 0,
        "attack_success_rate": sum(bool(v["objective_met"]) for v in per.values()) / n if n else 0,
        "recon_requests": sum(v["recon"] for v in per.values()),
        "recon_blocked": sum(v["recon_blocked"] for v in per.values()),
    }


def table(a: dict) -> str:
    head = "| Campaign | malicious blocked | harmless recon blocked | contained | attacker objective met |\n|---|---|---|---|---|\n"
    body = "\n".join(
        f"| {c} | {d['malicious_blocked']}/{d['malicious']} | {d['recon_blocked']}/{d['recon']} "
        f"| {'yes' if d['contained'] else 'no'} | {'yes' if d['objective_met'] else 'no'} |"
        for c, d in sorted(a["per_campaign"].items()))
    return head + body


def write_baseline(m: dict) -> None:
    b, s, hb, ht = m["benign"], m["safety_fp"], m["attacks_browser"], m["attacks_tool"]
    doc = f"""# BASELINE — OWASP CRS alone

**The denominator of every AEGIS claim.** Generated by `eval/baseline.py`; do not
edit by hand — re-run the harness.

| Field | Value |
|---|---|
| Date | {m['ts']} |
| Config | OWASP CRS {m['config']['crs']} on Coraza {m['config']['coraza']}, paranoia {m['config']['pl']}, anomaly threshold {m['config']['threshold']}, untuned |
| Target | OWASP Juice Shop {m['config']['app']} |
| Mode | enforce |

## The number

> **Against attackers who spoof a browser user-agent, OWASP CRS alone contains
> {hb['campaigns_contained']}/{hb['campaigns']} attack campaigns
> ({hb['campaigns_contained']/hb['campaigns']*100:.0f}%) and blocks
> {hb['malicious_block_rate']*100:.0f}% of malicious requests; the attacker still meets
> their objective in {hb['attack_success_rate']*100:.0f}% of campaigns. It does so at a
> {s['fp_rate']*100:.3f}% false-positive rate on {s['benign_requests']:,} benign requests
> ({s['fp_rate_no_push']*100:.3f}% excluding the socket.io push channel), breaking
> {b['pct_broken_by_defence']*100:.1f}% of legitimate user journeys.**

Spec budgets: FP <= 0.01%; legitimate journeys broken = 0; inline p99 <= 1 ms.

### Why two attacker modes (a correction)

An earlier baseline used attack tools that announce themselves (`sqlmap`, `Nuclei`,
...). CRS rule **913100** blocks *any* request from a known scanner user-agent,
including a harmless `GET /`, so those numbers partly measured "CRS read the name
tag", not "CRS recognised the attack". Attackers who matter spoof the UA, so the
**browser-UA run is the headline**. The tool-UA run is kept to show the size of the
confound: it blocked {ht['recon_blocked']}/{ht['recon_requests']} harmless recon requests on UA alone;
the browser-UA run blocked {hb['recon_blocked']}/{hb['recon_requests']}.

## Security — attackers with a spoofed browser UA (headline)

{table(hb)}

Campaigns contained: **{hb['campaigns_contained']}/{hb['campaigns']}**. Malicious requests blocked:
**{hb['malicious_blocked']}/{hb['malicious_requests']}** ({hb['malicious_block_rate']*100:.1f}%).
Attack success rate (objective met): **{hb['attack_success_rate']*100:.0f}%**.

## Security — attackers that announce a scanner UA (naive case)

{table(ht)}

Campaigns contained: {ht['campaigns_contained']}/{ht['campaigns']}; malicious blocked
{ht['malicious_blocked']}/{ht['malicious_requests']} ({ht['malicious_block_rate']*100:.1f}%);
attack success rate {ht['attack_success_rate']*100:.0f}%.

## Safety — false positives ({s['benign_requests']:,} benign requests, detect-mode capture)

- FP rate: **{s['fp_rate']*100:.3f}%** ({s['fp']:,} requests) — **{s['fp_rate']/0.0001:.0f}x over the 0.01% budget**
- Excluding the socket.io push channel: **{s['fp_rate_no_push']*100:.3f}%** ({s['fp_no_push']:,})
- Legitimate journeys broken by the defence (enforce, {b['journeys']} journeys): **{b['broken_by_defence']}** ({b['pct_broken_by_defence']*100:.2f}%); by the app's own bugs: {b['broken_by_app']}
- Top false-positive rules: {', '.join(f'{r}x{n}' for r, n in s['top_rules'])}

## System

- Inline WAF latency: p50 **{s['waf_us_p50']/1000:.2f} ms**, p95 **{s['waf_us_p95']/1000:.2f} ms**, p99 **{s['waf_us_p99']/1000:.2f} ms** (budget p99 <= 1 ms).

## Caveats

- Eight attack campaigns we wrote, one app, one run. Percentages over 8 campaigns move in 12.5-point steps.
- "Attacker objective met" is judged by simple response checks in `range/attacks/campaigns.py`; where the app has no vulnerable sink (e.g. OS command injection) it is correctly "no".
- The benign corpus predates the per-actor visitor cookie, so FP is per-request, not per-actor.
"""
    (ROOT / "docs" / "BASELINE.md").write_text(doc, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--journeys", type=int, default=300)
    args = ap.parse_args()
    corpus = newest_corpus()
    if corpus is None:
        print("no benign corpus in data/benign_corpus/", file=sys.stderr)
        return 2

    with Range(mode="enforce"):
        print(f"[1/4] benign warmup, {args.journeys} journeys (enforce) ...", flush=True)
        benign = run_benign(args.journeys)
        print(f"      {benign['ok']}/{benign['journeys']} ok, broken by defence: "
              f"{benign['broken_by_defence']}", flush=True)
        print("[2/4] attacks, spoofed browser UA (headline) ...", flush=True)
        hb = run_attacks("browser")
        print(f"      contained {hb['campaigns_contained']}/{hb['campaigns']}, "
              f"malicious blocked {hb['malicious_blocked']}/{hb['malicious_requests']}, "
              f"attacker success {hb['attack_success_rate']*100:.0f}%", flush=True)
        print("[3/4] attacks, announced scanner UA (naive) ...", flush=True)
        ht = run_attacks("tool")
        print(f"      contained {ht['campaigns_contained']}/{ht['campaigns']}, "
              f"malicious blocked {ht['malicious_blocked']}/{ht['malicious_requests']}, "
              f"harmless recon blocked on UA: {ht['recon_blocked']}/{ht['recon_requests']}", flush=True)

    print(f"[4/4] false positives + latency from corpus ({corpus.name}) ...", flush=True)
    safety = fp_from_corpus(corpus)
    print(f"      FP {safety['fp_rate']*100:.3f}%  p99 {safety['waf_us_p99']/1000:.2f} ms", flush=True)

    metrics = {"ts": time.strftime("%Y-%m-%d %H:%M"), "episode": "baseline-crs-v2",
               "config": {"crs": "4.25", "coraza": "3.8.1", "pl": 1, "threshold": THRESHOLD,
                          "app": "20.2.0", "corpus": corpus.name},
               "benign": benign, "attacks_browser": hb, "attacks_tool": ht, "safety_fp": safety}
    with (ROOT / "eval" / "metrics.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(metrics, ensure_ascii=False) + "\n")
    write_baseline(metrics)
    print("\nBASELINE written to docs/BASELINE.md", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
