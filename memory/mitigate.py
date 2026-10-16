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
import llm as llm_mod          # noqa: E402
import repair as repair_mod    # noqa: E402
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


# LLM calls per hour (invariant 7). The model is the last resort (invariant 9).
MAX_LLM_CALLS_PER_HOUR = 6


def mitigate(dossier: dict, campaign_requests: list[dict], benign_corpus: Path,
             mem: Memory, max_new_per_hour: int = MAX_NEW_RULES_PER_HOUR,
             llm=None, max_llm_per_hour: int = MAX_LLM_CALLS_PER_HOUR,
             llm_rounds: int = 1, exclude: frozenset | set = frozenset(),
             llm_interface: str = "free") -> dict:
    """`exclude`: rule ids that already failed the LIVE stages; never offered again."""
    cls = (dossier.get("techniques") or [dossier.get("attack_class", "")])[0]
    campaign_id, sig = mem.record_campaign(dossier)
    t0 = time.perf_counter()

    # 1) exact repeat
    exact = mem.rule_for_signature(sig)
    if exact and exact["id"] not in exclude:
        mem.touch_rule(exact["id"])
        ttm = time.perf_counter() - t0
        mem.record_outcome(campaign_id, "reused", exact["id"], ttm)
        return {"source": "reused", "rule": exact["id"], "ttm_s": ttm, "signature": sig}

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # 2) variant generalisation
        for ir in mem.rules_for_class(cls):
            if ir["id"] in exclude:
                continue
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
            if ir["id"] in exclude:
                continue
            if ir.get("mechanism") == "rate_limit":
                continue  # rate candidates validated by the rate gate, not here
            ok, results = gatemod.run_gate(ir, campaign_requests, benign_corpus, tmp)
            rej = next((r.stage for r in results if not r.passed), None)
            mem.record_candidate(campaign_id, ir, "passed_offline" if ok else "rejected",
                                 rej, [r.detail for r in results])
            if ok and promoted is None:
                promoted = ir
                break
        if promoted:
            ttm = time.perf_counter() - t0
            mem.promote_rule(promoted, sig)
            mem.record_outcome(campaign_id, "fresh", promoted["id"], ttm)
            return {"source": "fresh", "rule": promoted["id"], "ttm_s": ttm, "signature": sig}

        # 4) LAST RESORT: templates produced nothing promotable -> ask the model.
        # Its candidates are plain IR and go through the SAME gate; it gains no
        # extra authority. Budgeted per hour, and every call's cost is recorded.
        if llm is not None:
            llm_info = {"rounds": [], "tokens_in": 0, "tokens_out": 0, "llm_s": 0.0,
                        "valid": 0, "dropped": [], "gate": []}
            feedback: list[dict] = []
            for rnd in range(max(1, llm_rounds)):
                # Every round is one model call, so each counts against the budget.
                if mem.llm_calls_since(time.time() - 3600) >= max_llm_per_hour:
                    ttm = time.perf_counter() - t0
                    mem.record_outcome(campaign_id, "llm_budget_blocked", None, ttm)
                    return {"source": "llm_budget_blocked", "rule": None, "ttm_s": ttm,
                            "signature": sig, "llm": llm_info,
                            "detail": f"LLM call cap {max_llm_per_hour}/h reached"}
                proposer = llm_mod.propose
                if llm_interface == "patterns":
                    import patterns as patterns_mod
                    proposer = patterns_mod.propose
                prop = proposer(dossier, campaign_requests, llm,
                                feedback=feedback or None)
                r = prop.response
                mem.record_llm_call(campaign_id, r.model if r else "?", r.tokens_in if r else 0,
                                    r.tokens_out if r else 0, r.seconds if r else 0.0,
                                    len(prop.candidates), len(prop.rejected))
                rinfo = {"round": rnd + 1, "tokens_in": r.tokens_in if r else 0,
                         "tokens_out": r.tokens_out if r else 0,
                         "llm_s": round(r.seconds, 1) if r else 0.0,
                         "valid": len(prop.candidates), "dropped": prop.rejected, "gate": []}
                llm_info["rounds"].append(rinfo)
                llm_info["tokens_in"] += rinfo["tokens_in"]
                llm_info["tokens_out"] += rinfo["tokens_out"]
                llm_info["llm_s"] = round(llm_info["llm_s"] + rinfo["llm_s"], 1)
                llm_info["valid"] += rinfo["valid"]
                llm_info["dropped"] += prop.rejected
                for ir in prop.candidates:
                    if ir.get("mechanism") == "rate_limit":
                        continue
                    ok, results = gatemod.run_gate(ir, campaign_requests, benign_corpus, tmp)
                    rej = next((x.stage for x in results if not x.passed), None)
                    mem.record_candidate(campaign_id, ir, "passed_offline" if ok else "rejected",
                                         rej, [x.detail for x in results])
                    g = {"id": ir["id"], "ok": ok, "rejected_at": rej, "round": rnd + 1,
                         "detail": next((x.detail for x in results if not x.passed), "")}
                    rinfo["gate"].append(g)
                    llm_info["gate"].append(g)
                    if ok:
                        ttm = time.perf_counter() - t0
                        mem.promote_rule(ir, sig)
                        mem.record_outcome(campaign_id, "llm", ir["id"], ttm)
                        llm_info["promoted_in_round"] = rnd + 1
                        return {"source": "llm", "rule": ir["id"], "ttm_s": ttm,
                                "signature": sig, "llm": llm_info}
                    # Structured, traffic-text-free feedback for the next round.
                    if rnd + 1 < llm_rounds and rej:
                        try:
                            feedback.append(repair_mod.feedback_for(ir, rej, campaign_requests,
                                                                    benign_corpus))
                        except Exception:  # feedback is best-effort, never fatal
                            pass
            ttm = time.perf_counter() - t0
            mem.record_outcome(campaign_id, "none", None, ttm)
            return {"source": "none", "rule": None, "ttm_s": ttm, "signature": sig, "llm": llm_info}

        ttm = time.perf_counter() - t0
        mem.record_outcome(campaign_id, "none", None, ttm)
        return {"source": "none", "rule": None, "ttm_s": ttm, "signature": sig}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--dossier", type=Path)
    p.add_argument("--campaign", type=Path)
    p.add_argument("--novel", type=Path,
                   help="JSON file holding both {dossier, requests} (e.g. data/attack_corpus/novel_ssti.json)")
    p.add_argument("--benign", type=Path,
                   default=next((ROOT / "data" / "benign_corpus").glob("benign_*detect*.jsonl"), None))
    p.add_argument("--db", type=Path, default=ROOT / "memory" / "aegis.db")
    p.add_argument("--repeats", type=int, default=2, help="how many times to see this campaign")
    p.add_argument("--llm", choices=["none", "ollama"], default="none",
                   help="enable the last-resort LLM path (templates are always tried first)")
    p.add_argument("--model", default="mistral:latest")
    p.add_argument("--llm-rounds", type=int, default=1,
                   help="1 = one shot; N>1 adds N-1 repair rounds fed with structured gate feedback")
    args = p.parse_args()

    if args.novel:
        d = json.loads(args.novel.read_text(encoding="utf-8"))
        dossier, campaign = d["dossier"], d["requests"]
    elif args.dossier and args.campaign:
        dossier = json.loads(args.dossier.read_text(encoding="utf-8"))
        campaign = [json.loads(l) for l in args.campaign.read_text(encoding="utf-8").splitlines() if l.strip()]
    else:
        p.error("give --novel, or both --dossier and --campaign")
    mem = Memory(args.db)
    backend = llm_mod.OllamaBackend(args.model) if args.llm == "ollama" else None

    results = []
    for i in range(args.repeats):
        r = mitigate(dossier, campaign, args.benign, mem, llm=backend, llm_rounds=args.llm_rounds)
        results.append(r)
        print(f"exposure {i+1}: source={r['source']:11s} rule={r['rule']}  "
              f"time-to-mitigate={r['ttm_s']*1000:.1f} ms")
        info = r.get("llm")
        if info:
            print(f"   LLM: {info['tokens_in']} tokens in / {info['tokens_out']} out, {info['llm_s']}s; "
                  f"{info['valid']} valid candidate(s), dropped: {info['dropped']}")
            for g in info["gate"]:
                print(f"   gate {g['id']}: {'PASS' if g['ok'] else 'REJECTED at ' + str(g['rejected_at'])}"
                      + (f" -- {g['detail']}" if g['detail'] else ""))

    if len(results) >= 2 and results[0]["ttm_s"] > 0 and results[1]["ttm_s"] > 0:
        speedup = results[0]["ttm_s"] / results[1]["ttm_s"]
        print(f"\nrepeat speedup (exposure1 / exposure2): {speedup:.0f}x "
              f"(target >= 10x)  -> {'PASS' if speedup >= 10 else 'FAIL'}")
    print("memory stats:", json.dumps(mem.stats()))
    mem.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
