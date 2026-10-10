"""Mitigation orchestrator -- M3 closed loop.

Given a campaign dossier, decide HOW to mitigate, cheapest-correct-path first:

  1. REUSED      exact signature already has a proven rule -> use it. No
                 regeneration, no gate. This is the >=10x repeat speedup.
  2. GENERALISED a rule from the same attack class already blocks this new
                 campaign -> reuse it (and remember it for this signature too).
  3. FRESH       nothing in memory fits -> synthesise candidates and run the
                 full gate. The expensive path, taken only for the unrecognised.

Every outcome is recorded with its source and time-to-mitigate, so the repeat
speedup and the fraction taking the expensive path are measurable (the latter
is the cost-control metric from invariant 9: it should fall as memory fills).

This is deterministic-template + memory only; no LLM. When the LLM is added it
slots in as a fourth path BELOW fresh-template, for campaigns templates don't
recognise -- and still emits IR through the same gate.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("ir", "deliberator", "gate", "memory", "observer"):
    sys.path.insert(0, str(ROOT / p))
import compile as irc          # noqa: E402
import generate as deliberator # noqa: E402
import gate as gatemod         # noqa: E402
from store import Memory, signature  # noqa: E402

REPLAY = ROOT / "bin" / "replay.exe"


def _quick_blocks(ir: dict, campaign_requests: list[dict], tmp: Path) -> bool:
    """Does this existing rule still block the new campaign? Attack replay only
    (fast) -- used to decide generalisation. Signature rules only."""
    if ir.get("mechanism") == "rate_limit":
        return False  # rate variants handled by exact-signature reuse for now
    try:
        rule_file = tmp / "variant.conf"
        rule_file.write_text(irc.compile_rule(ir), encoding="utf-8")
    except (irc.IRError, ValueError):
        return False
    mal = [r for r in campaign_requests if r.get("malicious", True)]
    atk = tmp / "camp.jsonl"
    with atk.open("w", encoding="utf-8") as f:
        for r in mal:
            f.write(json.dumps({"method": r.get("method", "GET"), "uri": r.get("uri", ""),
                                "body": r.get("body", ""),
                                "content_type": "application/json"}) + "\n")
    out = subprocess.run([str(REPLAY), "-rule", str(rule_file), "-corpus", str(atk)],
                         capture_output=True, text=True)
    if out.returncode != 0:
        return False
    res = json.loads(out.stdout.strip().splitlines()[-1])
    return res["total"] > 0 and res["matched"] == res["total"]


# Action rate limit on AEGIS itself (invariant 7): at most this many NEW
# enforcing rules promoted per hour. Reuse/generalise do not count -- they
# deploy an already-proven rule, so they are always allowed.
MAX_NEW_RULES_PER_HOUR = 10


def mitigate(dossier: dict, campaign_requests: list[dict], benign_corpus: Path,
             mem: Memory, max_new_per_hour: int = MAX_NEW_RULES_PER_HOUR) -> dict:
    cls = (dossier.get("techniques") or [dossier.get("attack_class", "")])[0]
    campaign_id, sig = mem.record_campaign(dossier)
    t0 = time.perf_counter()

    # 1) exact repeat
    exact = mem.rule_for_signature(sig)
    if exact:
        mem.touch_rule(exact["id"])
        ttm = time.perf_counter() - t0
        mem.record_outcome(campaign_id, "reused", exact["id"], ttm)
        return {"source": "reused", "rule": exact["id"], "ttm_s": ttm, "signature": sig}

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # 2) variant generalisation
        for ir in mem.rules_for_class(cls):
            if _quick_blocks(ir, campaign_requests, tmp):
                mem.promote_rule(ir, sig)  # now also indexed under this signature
                mem.touch_rule(ir["id"])
                ttm = time.perf_counter() - t0
                mem.record_outcome(campaign_id, "generalised", ir["id"], ttm)
                return {"source": "generalised", "rule": ir["id"], "ttm_s": ttm, "signature": sig}

        # 3) fresh synthesis + full gate -- but first the action rate limit:
        # a fresh rule is a NEW enforcing action, so it is capped per hour.
        recent = mem.promotions_since(time.time() - 3600)
        if recent >= max_new_per_hour:
            ttm = time.perf_counter() - t0
            mem.record_outcome(campaign_id, "governor_blocked", None, ttm)
            return {"source": "governor_blocked", "rule": None, "ttm_s": ttm,
                    "signature": sig, "detail": f"{recent} rules promoted in last hour "
                    f">= cap {max_new_per_hour}; new synthesis refused"}

        candidates = deliberator.candidates_for(cls, dossier)
        promoted = None
        for ir in candidates:
            if ir.get("mechanism") == "rate_limit":
                continue  # rate candidates validated by the rate gate, not here
            ok, results = gatemod.run_gate(ir, campaign_requests, benign_corpus, tmp)
            rej = next((r.stage for r in results if not r.passed), None)
            mem.record_candidate(campaign_id, ir, "passed_offline" if ok else "rejected",
                                 rej, [r.detail for r in results])
            if ok and promoted is None:
                promoted = ir
                break
        ttm = time.perf_counter() - t0
        if promoted:
            mem.promote_rule(promoted, sig)
            mem.record_outcome(campaign_id, "fresh", promoted["id"], ttm)
            return {"source": "fresh", "rule": promoted["id"], "ttm_s": ttm, "signature": sig}
        mem.record_outcome(campaign_id, "none", None, ttm)
        return {"source": "none", "rule": None, "ttm_s": ttm, "signature": sig}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--dossier", type=Path, required=True)
    p.add_argument("--campaign", type=Path, required=True)
    p.add_argument("--benign", type=Path,
                   default=next((ROOT / "data" / "benign_corpus").glob("benign_*detect*.jsonl"), None))
    p.add_argument("--db", type=Path, default=ROOT / "memory" / "aegis.db")
    p.add_argument("--repeats", type=int, default=2, help="how many times to see this campaign")
    args = p.parse_args()

    dossier = json.loads(args.dossier.read_text(encoding="utf-8"))
    campaign = [json.loads(l) for l in args.campaign.read_text(encoding="utf-8").splitlines() if l.strip()]
    mem = Memory(args.db)

    results = []
    for i in range(args.repeats):
        r = mitigate(dossier, campaign, args.benign, mem)
        results.append(r)
        print(f"exposure {i+1}: source={r['source']:11s} rule={r['rule']}  "
              f"time-to-mitigate={r['ttm_s']*1000:.1f} ms")

    if len(results) >= 2 and results[0]["ttm_s"] > 0 and results[1]["ttm_s"] > 0:
        speedup = results[0]["ttm_s"] / results[1]["ttm_s"]
        print(f"\nrepeat speedup (exposure1 / exposure2): {speedup:.0f}x "
              f"(target >= 10x)  -> {'PASS' if speedup >= 10 else 'FAIL'}")
    print("memory stats:", json.dumps(mem.stats()))
    mem.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
