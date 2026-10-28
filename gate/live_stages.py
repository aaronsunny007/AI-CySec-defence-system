"""Gate stages 5 (shadow) and 6 (canary + auto-rollback), on the live gateway.

Stages 1, 2, 4 run offline (gate.py); stage 3 is gate/live_validate.py. These
two need live traffic and the hot-reloadable gateway.

STAGE 5 -- shadow. The rule is loaded in mode `shadow`: it matches and counts
but never blocks. Over a window of realistic traffic we check:
  (a) suspected false positives: matches on actors the M1 observer does NOT
      consider attackers. This needs no ground truth -- it is the same signal a
      real deployment would have. Budget: the FP budget applied to that traffic
      (with small windows that rounds to zero allowed).
  (b) live-vs-offline agreement (signature rules): replay the very requests the
      gateway logged through bin/replay.exe and compare the predicted match
      count with the gateway's live count. A mismatch means the live engine is
      not behaving like the one the gate validated against.

STAGE 6 -- canary. Mode `canary(x%)`: the rule BLOCKS only actors whose stable
bucket < x, everyone else stays in shadow. Control = the other actors. While it
runs we monitor, and roll back (mode off, via the admin API) on any of:
  - suspected-FP blocks: requests the rule blocked on actors M1 does not flag
  - app 5xx rate in the canary slice regressing against control
  - p99 latency in the canary slice regressing against control
Rollback is the gateway's mode change, not a restart.

Only a rule that passes both is promoted to `enforce`; promotion is refused in
code for anything else (invariant 5).
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("ir", "gate", "observer", "eval", "range/attacks"):
    sys.path.insert(0, str(ROOT / p))
import compile as irc                              # noqa: E402
import rulestore                                   # noqa: E402
from actors import Actor, actor_key, reconstruct, to_request  # noqa: E402
from detector import detect                       # noqa: E402
from traffic import ReplayDriver, AttackDriver, ATTACK_UA_MARKERS  # noqa: E402

REPLAY = ROOT / "bin" / "replay.exe"
GATEWAY_LOG = ROOT / "logs" / "gateway" / "requests.jsonl"
DECISIONS = ROOT / "logs" / "gate" / "decisions.jsonl"

FP_BUDGET = 0.0001
MIN_SAMPLES = 150          # per slice before a latency/5xx comparison is trusted
SUSPECT_BLOCKS_TO_ROLL = 3
SUSPECT_RATE_TO_ROLL = 0.001
ERR5XX_DELTA = 0.02
ERR5XX_Z = 3.0             # ...AND the difference must be statistically real (one-sided z)
LAT_FACTOR, LAT_ABS_US = 3.0, 20_000


LONG_POLL_MARKERS = ("/socket.io",)


def _slice_latencies(window: list[dict]) -> tuple[list[int], list[int]]:
    """total_us of canary-slice and control-slice requests, excluding held-open long-poll requests."""
    c, k = [], []
    for r in window:
        if any(m in (r.get("uri") or "") for m in LONG_POLL_MARKERS) or r.get("total_us") is None:
            continue
        (c if r.get("canary") else k).append(int(r["total_us"]))
    return c, k


def _p99(vals: list[int]) -> int:
    v = sorted(vals)
    return v[min(len(v) - 1, int(len(v) * 0.99))] if v else 0


@dataclass
class LiveResult:
    stage: str
    passed: bool
    detail: str
    numbers: dict = field(default_factory=dict)


def _is_attack(rec: dict) -> bool:
    """Evaluation-only ground truth (range gt_label; UA fallback for old logs)."""
    g = rec.get("gt_label")
    if g:
        return g.startswith("attack:")
    ua = (rec.get("user_agent") or "").lower()
    return any(m in ua for m in ATTACK_UA_MARKERS)


def _log_size() -> int:
    return GATEWAY_LOG.stat().st_size if GATEWAY_LOG.exists() else 0


def _rec_t(rec: dict) -> float:
    try:
        return datetime.fromisoformat(rec["ts"].replace("Z", "+00:00")).timestamp()
    except (KeyError, ValueError, AttributeError):
        return 0.0


def _read_from(offset: int, since: float = 0.0) -> list[dict]:
    """Records appended after `offset`, optionally only those that ARRIVED at or after `since`.
    The `since` filter matters: the gateway logs in batches and loads a new rule a moment after
    the manifest is written, so requests logged after the offset can predate the rule. Under a
    fast attacker those few requests made the live-vs-replay agreement check fail."""
    if not GATEWAY_LOG.exists():
        return []
    with GATEWAY_LOG.open("rb") as f:
        f.seek(offset)
        data = f.read().decode("utf-8", "replace")
    out = []
    for ln in data.splitlines():
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            pass  # a partially flushed last line
    if since:
        out = [r for r in out if _rec_t(r) >= since]
    return out


def _flagged_actor_keys(records: list[dict]) -> set[str]:
    """Actors the M1 observer judges to be running a campaign (behaviour only)."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "w.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
        actors = reconstruct(path)
    return {k for k, a in actors.items() if len(a.requests) >= 3 and detect(a)}


MIN_ACTOR_REQUESTS = 3     # fewer than this and the observer cannot judge an actor either way
INDETERMINATE_MAX_FRAC = 0.5


def judge_matches(records: list[dict], rule_id: str, flagged: set[str],
                  context: list[dict] | None = None, outcome: str | None = None):
    """Split a rule's matches into (suspected false positives, indeterminate).

    suspect        match on an actor the observer does NOT flag although the observer has
                   seen enough of it (>= MIN_ACTOR_REQUESTS requests) to have flagged it.
    indeterminate  match on a non-flagged actor with too few requests to judge. An attacker
                   that rotates identity produces exactly these (a live run rejected a good
                   SQLi rule because the attacker's 2-request second identity was counted as a
                   'false positive'). They are not counted as FPs, but they are capped: a rule
                   that mostly matches unjudgeable actors is not shown to be safe.
    """
    size: dict[str, int] = {}
    for r in (context or []) + records:
        k = actor_key(r)
        size[k] = size.get(k, 0) + 1
    suspect, indet = [], []
    for r in records:
        k = actor_key(r)
        if k in flagged or not _matched(r, rule_id, outcome):
            continue
        (suspect if size.get(k, 0) >= MIN_ACTOR_REQUESTS else indet).append(r)
    return suspect, indet


def _matched(rec: dict, rule_id: str, outcome: str | None = None) -> bool:
    for m in rec.get("aegis_matches") or []:
        rid, _mode, out = m.split("|")
        if rid == rule_id and (outcome is None or out == outcome):
            return True
    return False


def _predict_with_replay(ir: dict, records: list[dict]) -> int:
    with tempfile.TemporaryDirectory() as td:
        rule = Path(td) / "r.conf"
        rule.write_text(irc.compile_rule(ir, deny=True), encoding="utf-8")
        corpus = Path(td) / "c.jsonl"
        with corpus.open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps({"method": r.get("method"), "uri": r.get("uri"),
                                    "body": r.get("body", ""), "host": r.get("host", ""),
                                    "content_type": r.get("content_type", ""),
                                    "user_agent": r.get("user_agent", "")}) + "\n")
        out = subprocess.run([str(REPLAY), "-rule", str(rule), "-corpus", str(corpus)],
                             capture_output=True, text=True)
        if out.returncode != 0:
            raise RuntimeError(out.stderr.strip())
        return json.loads(out.stdout.strip().splitlines()[-1])["matched"]


# --- stage 5 -----------------------------------------------------------------

def shadow_stage(ir: dict, corpus: Path | None, attack_class: str, duration_s: float = 45.0,
                 rps: float = 60.0, drive: bool = True,
                 context: list[dict] | None = None) -> LiveResult:
    """drive=True (experiments): this stage generates its own benign + attack traffic.
    drive=False (the autonomous controller): observe only the traffic that is really
    flowing. `context` = earlier log records, used ONLY so an actor whose campaign
    began before the window can still be recognised as an attacker by the observer."""
    rid = ir["id"]
    rulestore.upsert(ir, mode="shadow")
    rulestore.wait_version(rulestore.load()["version"])
    t_loaded = time.time()
    off = _log_size()
    rd = ReplayDriver(corpus, rps=rps).start() if drive else None
    ad = AttackDriver(attack_class, interval_s=10.0).start() if drive else None
    time.sleep(duration_s)
    if rd:
        rd.stop()
    if ad:
        ad.stop()
    time.sleep(2.0)  # gateway flushes its log every 500 ms
    window = _read_from(off, t_loaded)
    st = rulestore.stats()["rules"].get(rid, {})
    live = int(st.get("matches", 0))

    flagged = _flagged_actor_keys((context or []) + window)
    nonflag = [r for r in window if actor_key(r) not in flagged]
    suspect, indet = judge_matches(window, rid, flagged, context)
    allowed = int(FP_BUDGET * len(nonflag))
    logged_matches = sum(1 for r in window if _matched(r, rid))
    indet_ok = not (logged_matches >= 4 and len(indet) > INDETERMINATE_MAX_FRAC * logged_matches)
    fp_ok = len(suspect) <= allowed and indet_ok

    numbers = {"window_requests": len(window), "live_matches": live,
               "logged_matches": logged_matches, "nonflagged_requests": len(nonflag),
               "suspected_fp_matches": len(suspect), "fp_allowed": allowed,
               "indeterminate_matches": len(indet),
               "flagged_actors": len(flagged),
               "sample_suspect_uris": [r["uri"][:80] for r in suspect[:3]]}

    agree_ok, agree_detail = True, "n/a (rate rule)"
    if ir["mechanism"] != "rate_limit":
        predicted = _predict_with_replay(ir, window)
        tol = max(2, int(0.02 * max(predicted, logged_matches)))
        agree_ok = abs(predicted - logged_matches) <= tol
        numbers.update(replay_predicted=predicted, tolerance=tol)
        agree_detail = f"live {logged_matches} vs replay-predicted {predicted} (tol {tol})"

    passed = fp_ok and agree_ok
    detail = (f"{len(window)} live requests; suspected FPs {len(suspect)}/{len(nonflag)} "
              f"(+{len(indet)} indeterminate, actors with <{MIN_ACTOR_REQUESTS} requests) "
              f"non-campaign requests (allowed {allowed}); {agree_detail}")
    return LiveResult("shadow", passed, detail, numbers)


# --- stage 6 -----------------------------------------------------------------

def canary_stage(ir: dict, corpus: Path | None, attack_class: str, pct: int = 25,
                 duration_s: float = 60.0, rps: float = 60.0, drive: bool = True,
                 context: list[dict] | None = None, require_samples: bool = False,
                 max_extend: float = 3.0) -> LiveResult:
    """require_samples: a canary that saw too little traffic in either slice cannot
    detect a latency/5xx regression, so it must not pass by default. The window is
    extended (up to max_extend x duration_s); if it is still too thin the stage FAILS
    and the rule is switched off."""
    rid = ir["id"]
    rulestore.upsert(ir, mode="canary", canary_pct=pct)
    rulestore.wait_version(rulestore.load()["version"])
    s0 = rulestore.stats()["slices"]
    t_start = time.time()
    off = _log_size()
    rd = ReplayDriver(corpus, rps=rps, seed=11).start() if drive else None
    ad = AttackDriver(attack_class, interval_s=10.0).start() if drive else None

    trigger, t_trig, rollback_s = None, None, None
    thin = False
    while True:
        elapsed = time.time() - t_start
        if elapsed >= duration_s:
            if not require_samples:
                break
            s_ = rulestore.stats()["slices"]
            if (s_["canary"]["n"] - s0["canary"]["n"] >= MIN_SAMPLES
                    and s_["control"]["n"] - s0["control"]["n"] >= MIN_SAMPLES):
                break
            if elapsed >= duration_s * max_extend:
                thin = True
                break
        time.sleep(2.0)
        s = rulestore.stats()["slices"]
        c, k = s["canary"], s["control"]
        nc, nk = c["n"] - s0["canary"]["n"], k["n"] - s0["control"]["n"]

        # (1) suspected-FP blocks, judged by M1 on what has been logged so far
        window = _read_from(off, t_start)
        blocked = [r for r in window if _matched(r, rid, "blocked")]
        if blocked:
            flagged = _flagged_actor_keys((context or []) + window)
            suspect, _indet = judge_matches(window, rid, flagged, context, "blocked")
            nonflag_canary = sum(1 for r in window if r.get("canary") and actor_key(r) not in flagged)
            rate = len(suspect) / nonflag_canary if nonflag_canary else 0.0
            if len(suspect) >= SUSPECT_BLOCKS_TO_ROLL and rate > SUSPECT_RATE_TO_ROLL:
                trigger = (f"suspected false positives: {len(suspect)} blocks on non-campaign "
                           f"actors ({rate*100:.2f}% of their canary requests); e.g. "
                           f"{suspect[0]['uri'][:70]!r}")
        # (2) app 5xx regression
        if not trigger and nc >= MIN_SAMPLES and nk >= MIN_SAMPLES:
            ec = (c["status_5xx"] - s0["canary"]["status_5xx"]) / nc
            ek = (k["status_5xx"] - s0["control"]["status_5xx"]) / nk
            # The delta alone fired on pure noise at the sample sizes this stage accepts
            # (11.4% vs 9.1% with ~150 requests per slice: standard error ~3.5 points).
            pool = (c["status_5xx"] - s0["canary"]["status_5xx"]
                    + k["status_5xx"] - s0["control"]["status_5xx"]) / (nc + nk)
            se = (pool * (1 - pool) * (1 / nc + 1 / nk)) ** 0.5
            z = (ec - ek) / se if se > 0 else (float("inf") if ec > ek else 0.0)
            if ec - ek > ERR5XX_DELTA and z >= ERR5XX_Z:
                trigger = (f"5xx regression: canary {ec*100:.1f}% vs control {ek*100:.1f}% "
                           f"(z={z:.1f})")
        # (3) latency regression, computed from the log with held-open long-poll requests excluded:
        # the app holds /socket.io polls for ~25 s by design, so whichever slice happens to contain a
        # few of those "regresses" (5 of 5 canaries in the adaptive runs were rolled back this way,
        # blocking nothing).
        if not trigger and nc >= MIN_SAMPLES and nk >= MIN_SAMPLES:
            lc, lk = _slice_latencies(_read_from(off, t_start))
            if len(lc) >= MIN_SAMPLES and len(lk) >= MIN_SAMPLES:
                pc, pk = _p99(lc), _p99(lk)
                if pc > LAT_FACTOR * pk + LAT_ABS_US:
                    trigger = f"p99 latency regression: canary {pc}us vs control {pk}us"
        if trigger:
            t_trig = time.time()
            rulestore.rollback(rid)
            rollback_s = time.time() - t_trig
            break

    if rd:
        rd.stop()
    if ad:
        ad.stop()
    time.sleep(2.0)
    window = _read_from(off, t_start)
    blocked_all = [r for r in window if _matched(r, rid, "blocked")]
    # Ground truth (EVALUATION ONLY -- the stage itself never used it):
    benign_blocked = [r for r in blocked_all if not _is_attack(r)]
    attack_blocked = [r for r in blocked_all if _is_attack(r)]
    numbers = {
        "canary_pct": pct, "window_requests": len(window), "rule_blocks": len(blocked_all),
        "benign_requests_blocked_GT": len(benign_blocked),
        "attack_requests_blocked_GT": len(attack_blocked),
        "rolled_back": trigger is not None,
        "detect_after_s": round(t_trig - t_start, 1) if t_trig else None,
        "rollback_call_s": round(rollback_s, 2) if rollback_s is not None else None,
    }
    if thin:
        rulestore.set_mode(rid, "off")
        numbers["insufficient_traffic"] = True
        return LiveResult("canary", False,
                          f"canary saw < {MIN_SAMPLES} requests in a slice after {max_extend:.0f}x "
                          f"the window: cannot verify absence of regression, rule switched off", numbers)
    if trigger:
        return LiveResult("canary", False, f"ROLLED BACK after {numbers['detect_after_s']}s: {trigger}", numbers)
    return LiveResult("canary", True,
                      f"{duration_s:.0f}s at {pct}%: no regression; rule blocked "
                      f"{len(attack_blocked)} attack / {len(benign_blocked)} benign requests (GT)", numbers)


# --- pipeline + promotion -----------------------------------------------------

def promote(ir: dict, stages: list[LiveResult]) -> bool:
    """Refuse promotion unless BOTH live stages passed (invariant 5)."""
    names = {s.stage for s in stages if s.passed}
    if not {"shadow", "canary"} <= names:
        return False
    rulestore.set_mode(ir["id"], "enforce")
    return True


def log(ir: dict, stages: list[LiveResult], promoted: bool) -> None:
    DECISIONS.parent.mkdir(parents=True, exist_ok=True)
    with DECISIONS.open("a", encoding="utf-8") as f:
        f.write(json.dumps({
            "id": ir["id"], "attack_class": ir["attack_class"], "phase": "live",
            "verdict": "enforced" if promoted else "rejected_live",
            "stages": [{"stage": s.stage, "passed": s.passed, "detail": s.detail,
                        "numbers": s.numbers} for s in stages]}, ensure_ascii=False) + "\n")


def live_pipeline(ir: dict, corpus: Path | None, attack_class: str, shadow_s: float = 45.0,
                  canary_s: float = 60.0, pct: int = 25, skip_shadow: bool = False,
                  drive: bool = True, context: list[dict] | None = None,
                  require_samples: bool = False) -> dict:
    stages: list[LiveResult] = []
    if not skip_shadow:
        sh = shadow_stage(ir, corpus, attack_class, shadow_s, drive=drive, context=context)
        stages.append(sh)
        if not sh.passed:
            rulestore.set_mode(ir["id"], "off")
            log(ir, stages, False)
            return {"id": ir["id"], "promoted": False, "stages": stages}
    cn = canary_stage(ir, corpus, attack_class, pct, canary_s, drive=drive, context=context,
                      require_samples=require_samples)
    stages.append(cn)
    promoted = False
    if cn.passed and not skip_shadow:
        promoted = promote(ir, stages)
    elif not cn.passed:
        pass  # already rolled back to off by the stage
    else:
        rulestore.set_mode(ir["id"], "off")  # canary-only run (fault injection): do not promote
    log(ir, stages, promoted)
    return {"id": ir["id"], "promoted": promoted, "stages": stages}
