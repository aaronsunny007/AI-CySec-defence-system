"""Normalise ModSecurity JSON audit records into AEGIS request records.

Reads the raw audit log written by the WAF (one JSON object per line) and
writes one flat, stable-schema JSON object per request. Everything downstream
(benign corpus, baseline numbers, campaign detection) reads this format, so the
schema is the contract -- change it deliberately.

Usage:
    python observer/normalise.py                       # whole log -> data/requests.jsonl
    python observer/normalise.py --follow              # keep tailing
    python observer/normalise.py --in X --out Y

Malformed lines are counted and skipped, never fatal: the observer must not
fall over because an attacker sent something strange.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Iterator, TextIO

SCHEMA_VERSION = 1

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IN = ROOT / "logs" / "modsec" / "audit.jsonl"
DEFAULT_OUT = ROOT / "data" / "requests.jsonl"

# CRS 949110 / 980170 messages carry the total inbound anomaly score.
_SCORE_RE = re.compile(r"Total Score:\s*(\d+)")


def is_detection_rule(rule_id: str) -> bool:
    """Same filter as gateway/main.go isDetectionRule: CRS 911xxx-948xxx and
    Coraza 200002+ are detections; setup (900-910xxx), score evaluation and
    reporting (949/959/980xxx) say nothing about *what* was detected."""
    try:
        n = int(rule_id)
    except ValueError:
        return False
    return 911000 <= n < 949000 or 200002 <= n < 200100


def normalise(raw: dict) -> dict:
    """Map one ModSecurity v3 JSON audit record to an AEGIS request record."""
    tx = raw.get("transaction", {})
    req = tx.get("request", {}) or {}
    resp = tx.get("response", {}) or {}
    headers = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
    messages = tx.get("messages") or []

    rule_ids: list[str] = []
    tags: set[str] = set()
    anomaly_score = 0
    for m in messages:
        d = m.get("details", {}) or {}
        rid = str(d.get("ruleId", ""))
        score = _SCORE_RE.search(m.get("message", "") + " " + d.get("data", ""))
        if score:
            anomaly_score = max(anomaly_score, int(score.group(1)))
        if is_detection_rule(rid):
            rule_ids.append(rid)
            tags.update(t for t in d.get("tags", []) if t.startswith("attack-"))

    status = resp.get("http_code")
    body = req.get("body") or ""
    return {
        "v": SCHEMA_VERSION,
        "ts": tx.get("time_stamp"),
        "id": tx.get("unique_id"),
        "client_ip": tx.get("client_ip"),
        "client_port": tx.get("client_port"),
        "method": req.get("method"),
        "uri": req.get("uri"),
        "http_version": req.get("http_version"),
        "host": headers.get("host"),
        "user_agent": headers.get("user-agent"),
        "content_type": headers.get("content-type"),
        "cookie_present": "cookie" in headers,
        "auth_present": "authorization" in headers,
        "body": body,
        "body_len": len(body),
        "status": status,
        # The CRS image returns 403 when the anomaly threshold is exceeded.
        "blocked": status == 403 and anomaly_score > 0,
        "anomaly_score": anomaly_score,
        "rule_ids": sorted(set(rule_ids)),
        "attack_tags": sorted(tags),
    }


def _read_lines(fh: TextIO, follow: bool) -> Iterator[str]:
    while True:
        line = fh.readline()
        if line:
            yield line
        elif follow:
            time.sleep(0.2)
        else:
            return


def run(src: Path, dst: Path, follow: bool) -> tuple[int, int]:
    dst.parent.mkdir(parents=True, exist_ok=True)
    ok = bad = 0
    with src.open("r", encoding="utf-8", errors="replace") as fin, \
            dst.open("w", encoding="utf-8") as fout:
        for line in _read_lines(fin, follow):
            line = line.strip()
            if not line:
                continue
            try:
                rec = normalise(json.loads(line))
            except (json.JSONDecodeError, AttributeError, TypeError, ValueError):
                bad += 1
                continue
            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
            ok += 1
            if follow:
                fout.flush()
    return ok, bad


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--in", dest="src", type=Path, default=DEFAULT_IN)
    p.add_argument("--out", dest="dst", type=Path, default=DEFAULT_OUT)
    p.add_argument("--follow", action="store_true", help="keep tailing the audit log")
    args = p.parse_args(argv)

    if not args.src.exists():
        print(f"audit log not found: {args.src} (is the range up?)", file=sys.stderr)
        return 1
    try:
        ok, bad = run(args.src, args.dst, args.follow)
    except KeyboardInterrupt:
        return 0
    print(f"normalised {ok} records, skipped {bad} malformed -> {args.dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
