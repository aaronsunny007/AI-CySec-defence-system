"""Campaign detection: decide, from BEHAVIOUR, which actors are attacking.

Heuristics first (per CLAUDE.md M1: "Heuristics and clustering first. ML only
if the simple version is measurably insufficient."). Each detector keys on the
*shape* of an actor's request sequence, never on the user-agent or the grouping
key -- so it catches campaigns whose individual requests are unremarkable
(credential stuffing, IDOR/BOLA walks, user enumeration), which per-request WAF
rules miss by design.

A campaign is emitted as a dossier: actor, timeline, targeted endpoints,
payload family, app responses, suspected objective, confidence, and whether the
traffic was individually unremarkable (max CRS score below threshold).

Each detector reports the moment it would have fired (time-to-detect = that
request's timestamp minus the campaign's first suspicious request), so M1's
acceptance (>=90% within 30s) is measurable.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from actors import Actor, Request, reconstruct  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CRS_THRESHOLD = 5

# --- payload signatures (behavioural, independent of CRS) ----------------------
SIGS = {
    # Comment markers and tautologies count only in injection context (after a
    # quote or paren). A bare `--` or `1=1` matched ordinary text ("late -- but
    # worth it", "1=1 perfect apples") AND socket.io session ids (which contain
    # `--`): 0.0755% of the 443k benign requests before this change.
    "sqli": re.compile(r"('|%27)\s*\)*\s*(or|and)\s|union\s+select|('|%27|\))\s*(--|#)|"
                       r"\bselect\b.+\bfrom\b|sqlite_master", re.I),
    "xss": re.compile(r"<script|onerror\s*=|onload\s*=|<svg|<iframe|javascript:", re.I),
    "traversal": re.compile(r"\.\./|\.\.%2f|%2e%2e|/etc/passwd|\.\.\\|%00|%2500", re.I),
    "cmdi": re.compile(r";\s*(cat|id|whoami|ls|ping)\b|\|\s*(whoami|id|cat)\b|\$\(|`.*`|&&\s*(ping|cat)", re.I),
    "ssrf": re.compile(r"(https?|file|gopher)://(127\.0\.0\.1|localhost|169\.254\.169\.254|\[::1\]|0\.0\.0\.0)", re.I),
}

# Thresholds (tunable; measured on benign to keep FP low).
T = {
    "injection_min": 2,       # suspicious payloads from one actor
    "window_s": 60.0,         # correlation window for rate-based rules
    "stuffing_min": 6,        # login POSTs in window
    "enum_min": 4,            # distinct accounts probed
    "idor_min": 4,            # distinct object ids walked on one endpoint
    "scan_endpoints": 25,     # distinct endpoints (recon/fuzzing)
    "scan_err_rate": 0.30,    # ...AND this fraction of 4xx: real fuzzing misses
}

OBJECTIVE = {
    "sqli": "bypass auth / extract database via SQL injection",
    "xss": "inject executing script (XSS)",
    "traversal": "read files outside the web root",
    "cmdi": "execute OS commands",
    "ssrf": "make the server fetch an internal/metadata URL",
    "credential_stuffing": "find valid credentials by replaying many pairs",
    "user_enumeration": "learn which accounts exist",
    "idor_bola": "access other users' objects by walking ids",
    "scan": "map the application (fuzzing / forced browsing)",
}


@dataclass
class Finding:
    technique: str
    onset: str
    detected_at: str
    ttd_s: float
    evidence: str


@dataclass
class Dossier:
    actor: str
    ground_truth_ua: str
    start: str
    end: str
    n_requests: int
    techniques: list[str]
    suspected_objective: str
    confidence: float
    individually_unremarkable: bool  # max CRS score < threshold
    endpoints: list[str]
    status_mix: dict
    findings: list[dict] = field(default_factory=list)


def _decoded(r: Request) -> str:
    return urllib.parse.unquote_plus(r.query + " " + r.body)


def detect(actor: Actor) -> list[Finding]:
    """Run all behavioural detectors over one actor's time-sorted requests."""
    out: list[Finding] = []
    reqs = actor.requests
    if not reqs:
        return out

    # --- injection family (sqli/xss/traversal/cmdi/ssrf) ---
    fam_hits: dict[str, list[Request]] = {}
    for r in reqs:
        text = _decoded(r)
        for fam, rx in SIGS.items():
            if rx.search(text) or rx.search(r.path):
                fam_hits.setdefault(fam, []).append(r)
    for fam, hits in fam_hits.items():
        need = 1 if fam == "ssrf" else T["injection_min"]
        if len(hits) >= need:
            onset, trig = hits[0].ts, hits[need - 1].ts
            out.append(Finding(fam, onset.isoformat(), trig.isoformat(),
                               (trig - onset).total_seconds(),
                               f"{len(hits)} requests matching {fam} signature"))

    # --- credential stuffing: many logins in a window ---
    logins = [r for r in reqs if r.method == "POST" and r.path == "/rest/user/login"]
    out += _rate_rule(logins, T["stuffing_min"], "credential_stuffing",
                      lambda rs: f"{len(rs)} login attempts within {T['window_s']:.0f}s")

    # --- user enumeration: distinct accounts probed at enum endpoints ---
    enum_eps = ("/rest/user/security-question", "/rest/user/reset-password",
                "/rest/user/whoami")
    enum = [r for r in reqs if any(r.path.startswith(e) for e in enum_eps)
            or (r.method == "POST" and r.path == "/rest/user/login")]
    emails = _distinct_window(enum, lambda r: _email_of(r))
    if emails and len(emails[0]) >= T["enum_min"]:
        first = emails[1]
        out.append(Finding("user_enumeration", first[0].isoformat(), first[1].isoformat(),
                           (first[1] - first[0]).total_seconds(),
                           f"{len(emails[0])} distinct accounts probed"))

    # --- IDOR / BOLA: walking object ids on one endpoint ---
    by_ep: dict[str, list[Request]] = {}
    for r in reqs:
        if any(p.isdigit() for p in r.path.split("/")):
            by_ep.setdefault(r.endpoint, []).append(r)
    for ep, rs in by_ep.items():
        ids = {p for r in rs for p in r.path.split("/") if p.isdigit()}
        if len(ids) >= T["idor_min"]:
            onset, trig = rs[0].ts, rs[min(T["idor_min"], len(rs)) - 1].ts
            out.append(Finding("idor_bola", onset.isoformat(), trig.isoformat(),
                               (trig - onset).total_seconds(),
                               f"{len(ids)} distinct ids on {ep}"))

    # --- scan / forced browsing: high endpoint fan-out WITH an error storm ---
    # Fan-out alone is normal (an SPA hits many /api endpoints on load); what
    # marks fuzzing is guessing paths that do not exist -> many 4xx.
    eps = {r.endpoint for r in reqs}
    errs = sum(1 for r in reqs if r.status in (400, 404))
    err_rate = errs / len(reqs)
    if (len(eps) >= T["scan_endpoints"] and err_rate >= T["scan_err_rate"]
            and actor.duration_s <= T["window_s"] * 3):
        out.append(Finding("scan", reqs[0].ts.isoformat(), reqs[-1].ts.isoformat(),
                           actor.duration_s,
                           f"{len(eps)} endpoints, {err_rate*100:.0f}% 4xx"))
    return out


def evidence(actor: Actor, technique: str) -> list[Request]:
    """The requests that made the detector fire for an injection family: the ones
    matching that family's signature. These (not the actor's recon traffic) are the
    'malicious requests' a candidate rule must block."""
    rx = SIGS.get(technique)
    if rx is None:
        return []
    return [r for r in actor.requests if rx.search(_decoded(r)) or rx.search(r.path)]


def _email_of(r: Request) -> str | None:
    try:
        if r.body:
            d = json.loads(r.body)
            if isinstance(d, dict) and d.get("email"):
                return str(d["email"]).lower()
    except json.JSONDecodeError:
        pass
    q = urllib.parse.parse_qs(r.query)
    return (q.get("email") or [None])[0]


def _distinct_window(reqs: list[Request], keyfn):
    """Return (distinct_keys, (onset_ts, trigger_ts)) once >= enum_min distinct
    keys appear within window_s, else None."""
    from collections import deque
    win: deque = deque()
    seen_order: list[Request] = []
    distinct: set = set()
    for r in reqs:
        k = keyfn(r)
        if not k:
            continue
        win.append(r)
        seen_order.append(r)
        while (r.ts - win[0].ts).total_seconds() > T["window_s"]:
            win.popleft()
        keys = {keyfn(x) for x in win if keyfn(x)}
        if len(keys) >= T["enum_min"]:
            onset = next(x for x in seen_order if keyfn(x))
            return keys, (onset.ts, r.ts)
    return None


def _rate_rule(reqs: list[Request], n: int, technique: str, evidence) -> list[Finding]:
    from collections import deque
    win: deque = deque()
    for r in reqs:
        win.append(r)
        while (r.ts - win[0].ts).total_seconds() > T["window_s"]:
            win.popleft()
        if len(win) >= n:
            return [Finding(technique, win[0].ts.isoformat(), r.ts.isoformat(),
                            (r.ts - win[0].ts).total_seconds(), evidence(list(win)))]
    return []


def build_dossier(actor: Actor, findings: list[Finding]) -> Dossier:
    reqs = actor.requests
    status_mix: dict = {}
    for r in reqs:
        status_mix[str(r.status)] = status_mix.get(str(r.status), 0) + 1
    techniques = sorted({f.technique for f in findings})
    # Confidence: more corroborating detectors + more volume => higher.
    conf = min(0.99, 0.5 + 0.15 * len(techniques) + min(0.2, len(reqs) / 200))
    obj = "; ".join(OBJECTIVE.get(t, t) for t in techniques)
    return Dossier(
        actor=actor.key,
        ground_truth_ua=(reqs[0].raw.get("user_agent") or "")[:60],
        start=actor.start.isoformat(), end=actor.end.isoformat(),
        n_requests=len(reqs), techniques=techniques,
        suspected_objective=obj, confidence=round(conf, 2),
        individually_unremarkable=max((r.anomaly_score for r in reqs), default=0) < CRS_THRESHOLD,
        endpoints=sorted({r.endpoint for r in reqs})[:20],
        status_mix=status_mix,
        findings=[asdict(f) for f in findings],
    )


# --- ground truth for evaluation (NOT used by the detector) --------------------
ATTACK_UA = ("sqlmap", "XSStrike", "Nuclei", "commix", "SSRFmap",
             "aegis-enum", "Autorize", "OpenBullet")


def ground_truth(rec: dict) -> str | None:
    """'attack:<campaign>', 'benign' or None, from the gateway's range-only
    gt_label. EVALUATION ONLY -- nothing in detect() reads this. The attack
    user-agent is NOT used any more: an attacker controls it, and CRS itself
    matches on it (rule 913100), which confounded earlier measurements."""
    g = rec.get("gt_label")
    return g or None


def is_attack_actor(actor: Actor) -> bool:
    if not actor.requests:
        return False
    g = ground_truth(actor.requests[0].raw)
    if g is not None:
        return g.startswith("attack:")
    ua = actor.requests[0].raw.get("user_agent", "")  # legacy logs without gt_label
    return any(m.lower() in ua.lower() for m in ATTACK_UA)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--log", type=Path, default=ROOT / "logs" / "gateway" / "requests.jsonl")
    p.add_argument("--out", type=Path, default=ROOT / "logs" / "observer" / "dossiers.jsonl")
    p.add_argument("--min-requests", type=int, default=3,
                   help="ignore actors with fewer requests (noise floor)")
    p.add_argument("--eval", action="store_true", help="score against UA ground truth")
    args = p.parse_args()

    if not args.log.exists():
        print(f"log not found: {args.log}", file=sys.stderr)
        return 1
    actors = reconstruct(args.log)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    dossiers: list[tuple[Actor, Dossier]] = []
    with args.out.open("w", encoding="utf-8") as f:
        for a in actors.values():
            if len(a.requests) < args.min_requests:
                continue
            findings = detect(a)
            if findings:
                d = build_dossier(a, findings)
                dossiers.append((a, d))
                f.write(json.dumps(asdict(d), ensure_ascii=False) + "\n")

    print(f"actors: {len(actors)}  flagged as campaigns: {len(dossiers)}  -> {args.out}")

    if args.eval:
        _evaluate(actors, dossiers, args.min_requests)
    return 0


def _evaluate(actors, dossiers, min_requests) -> None:
    flagged = {d.actor for _, d in dossiers}
    atk = [a for a in actors.values() if is_attack_actor(a) and len(a.requests) >= min_requests]
    ben = [a for a in actors.values() if not is_attack_actor(a) and len(a.requests) >= min_requests]
    tp = [a for a in atk if a.key in flagged]
    fn = [a for a in atk if a.key not in flagged]
    fp = [a for a in ben if a.key in flagged]

    print("\n=== M1 detection eval (ground truth = attack tool UA; detector never sees it) ===")
    print(f"attack actors:  {len(atk):4d}  detected {len(tp)}  missed {len(fn)}"
          f"  -> detection rate {100*len(tp)/max(1,len(atk)):.0f}%")
    print(f"benign actors:  {len(ben):4d}  false-flagged {len(fp)}"
          f"  -> FP rate {100*len(fp)/max(1,len(ben)):.2f}%")

    # time-to-detect across all findings on attack actors
    ttds = [f["ttd_s"] for a in tp for _, d in dossiers if d.actor == a.key for f in d.findings]
    if ttds:
        ttds.sort()
        within30 = 100 * sum(t <= 30 for t in ttds) / len(ttds)
        print(f"time-to-detect: p50 {ttds[len(ttds)//2]:.1f}s  "
              f"p90 {ttds[min(int(len(ttds)*0.9), len(ttds)-1)]:.1f}s  "
              f"within 30s: {within30:.0f}%")
    # per-technique recall on attack actors (by the campaign the UA implies)
    print("missed attack actors:", [(a.requests[0].raw.get("gt_label") or a.requests[0].raw.get("user_agent",""))[:30] for a in fn] or "none")
    if fp:
        print("false-flagged benign (investigate):")
        for a in fp[:8]:
            d = next(d for _, d in dossiers if d.actor == a.key)
            print(f"  {d.techniques}  {d.n_requests} reqs  {d.endpoints[:3]}")


if __name__ == "__main__":
    sys.exit(main())
