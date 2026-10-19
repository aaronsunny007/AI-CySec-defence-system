"""AEGIS controller: the autonomous loop, in one process, with no human in it.

    tail the gateway log -> reconstruct actors -> detect campaigns (observer)
      -> mitigate: memory reuse / generalise / template synthesis / last-resort LLM
         -> offline gate (benign replay, campaign replay, mutation)   [signature rules]
         -> rate gate against non-campaign actors                     [rate rules]
      -> hot-load in SHADOW -> CANARY -> ENFORCE (live stages; refused unless both pass)

Everything with authority is deterministic code. The controller only ever calls the
existing, tested pieces; it adds no new way to reach `enforce`.

Invariants honoured here:
  fail open        this process is not in the request path. If it dies, the gateway keeps
                   serving with whatever rules are already loaded. A crash mid-stage leaves
                   at worst a rule in shadow/canary; on any error the rule is switched off.
  budgets          new rules/hour and LLM calls/hour (memory.mitigate), campaigns handled/hour
                   (here), bounded stage durations.
  traffic is data  the controller never feeds traffic text to a model; the LLM path is the
                   same unprivileged, schema-constrained one as before.
  no ground truth  nothing here reads the range-only gt_label. "Is this actor an attacker"
                   is the observer's judgement, exactly as in a real deployment.

    python controller/loop.py --stop-file logs/controller/stop
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
for p in ("ir", "deliberator", "gate", "memory", "observer"):
    sys.path.insert(0, str(ROOT / p))
import compile as irc                                   # noqa: E402
import generate as deliberator                          # noqa: E402
import live_stages as LS                                # noqa: E402
import mitigate as mit                                  # noqa: E402
import rulestore                                        # noqa: E402
from actors import Actor, actor_key, reconstruct, to_request  # noqa: E402
from detector import build_dossier, detect, evidence, is_login_attempt  # noqa: E402
from ratelimit import blocked_count                     # noqa: E402
from store import Memory, signature                     # noqa: E402

# Detector technique -> attack class the deliberator has templates for.
TECH_CLASS = {"sqli": "sqli", "xss": "xss", "traversal": "traversal", "cmdi": "cmdi",
              "ssrf": "ssrf", "credential_stuffing": "credential_stuffing",
              "user_enumeration": "user_enumeration", "idor_bola": "idor_bola"}
INJECTION = {"sqli", "xss", "traversal", "cmdi", "ssrf"}
RATE = {"credential_stuffing", "user_enumeration", "idor_bola"}
# 'scan' is detected but has no mitigation template; it is reported, not acted on.

BYPASS_GRACE_S = 2.0        # requests this soon after enforcement may predate the hot reload
BYPASS_MIN = 3              # unblocked evidence requests that make an enforcing rule 'bypassed'
ESCALATE_WINDOW_S = 600.0     # a 2nd identity running the same stuffing campaign within this => rotation
COOLDOWN_S = 600.0          # a campaign signature that yielded no rule is not retried for this long
MIN_BENIGN_ACTORS = 20      # the rate gate refuses to judge on less benign evidence


def account_of(body: str) -> str:
    """Same rule as the gateway's accountOf(): the e-mail/username a request is about."""
    if not body or len(body) > 4096:
        return ""
    try:
        d = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return ""
    if isinstance(d, dict):
        for k in ("email", "username", "user"):
            v = d.get(k)
            if isinstance(v, str) and v:
                return v.strip().lower()[:120]
    return ""


def _enum_req(r) -> bool:
    return (r.path.startswith(("/rest/user/security-question", "/rest/user/reset-password",
                                "/rest/user/whoami"))
            or is_login_attempt(r))


# which of an actor's requests a RATE class is about (used for the dossier endpoints)
RATE_EVIDENCE: dict[str, Callable] = {
    "credential_stuffing": is_login_attempt,
    "user_enumeration": _enum_req,
    "idor_bola": lambda r: any(p.isdigit() for p in r.path.split("/")),
}


@dataclass
class Config:
    log: Path = ROOT / "logs" / "gateway" / "requests.jsonl"
    events: Path = ROOT / "logs" / "controller" / "events.jsonl"
    db: Path = ROOT / "memory" / "controller.db"
    benign_corpus: Path | None = None
    benign_actors: Path | None = None   # optional log of real user sessions for the rate gate
    window_s: float = 600.0
    min_requests: int = 3
    tick_s: float = 1.0
    shadow_s: float = 30.0
    canary_s: float = 45.0
    canary_pct: int = 25
    max_new_rules_per_hour: int = mit.MAX_NEW_RULES_PER_HOUR
    max_campaigns_per_hour: int = 600
    max_per_technique_per_hour: int = 200
    from_start: bool = False            # False: only look at traffic that arrives from now on
    llm: object = None
    llm_rounds: int = 1


def _evidence_fp(ev) -> str:
    """Fingerprint of WHAT the campaign sent (payload skeletons), not just where. The cooldown for a
    failed search is keyed on this, so a benign actor falsely flagged on the same endpoints cannot put a
    real attacker's campaign into cooldown (a replicate lost its SQLi campaign that way)."""
    import hashlib
    import re
    import urllib.parse
    sk = sorted({re.sub(r"\d+", "0", urllib.parse.unquote_plus((r.raw.get("uri") or "") + " " + (r.body or "")))[:120]
                 for r in ev})
    return hashlib.sha1("|".join(sk).encode("utf-8", "replace")).hexdigest()[:10]


class LogTail:
    """Reads newly appended complete JSONL lines; tolerant of a half-written last line."""

    def __init__(self, path: Path, from_start: bool = False):
        self.path = path
        self.offset = 0 if from_start else (path.stat().st_size if path.exists() else 0)
        self.partial = b""

    def read_new(self) -> list[dict]:
        if not self.path.exists():
            return []
        size = self.path.stat().st_size
        if size < self.offset:                    # truncated / rotated
            self.offset, self.partial = 0, b""
        if size == self.offset:
            return []
        with self.path.open("rb") as f:
            f.seek(self.offset)
            data = self.partial + f.read()
            self.offset = f.tell()
        lines = data.split(b"\n")
        self.partial = lines.pop()               # last element is incomplete (or empty)
        out = []
        for ln in lines:
            if not ln.strip():
                continue
            try:
                out.append(json.loads(ln))
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        return out


def _epoch(iso: str) -> float | None:
    try:
        return datetime.fromisoformat(iso).timestamp()
    except (ValueError, OSError):
        return None


class Controller:
    def __init__(self, cfg: Config, mem: Memory | None = None,
                 live: Callable | None = None, mitigate_fn: Callable | None = None):
        self.cfg = cfg
        self.mem = mem or Memory(cfg.db)
        self.tail = LogTail(cfg.log, cfg.from_start)
        self.actors: dict[str, Actor] = {}
        self.recent: collections.deque = collections.deque()    # raw records, for stage context
        self.dirty: set[str] = set()
        self.flagged: set[str] = set()
        self.handled: set[tuple[str, str]] = set()
        self.failed_live: set[str] = set()
        self.retried: set[str] = set()
        self.sig_actors: dict[str, dict[str, float]] = {}   # campaign signature -> {identity: t}
        self.escalated: set[str] = set()
        self.enforced_at: dict[str, float] = {}
        self.handled_times: collections.deque = collections.deque()
        self.newest_ts = 0.0
        LS.GATEWAY_LOG = cfg.log          # the live stages read the same log the controller tails
        self.cooldown: dict[str, float] = {}
        self.live = live or self._live_pipeline
        self.mitigate_fn = mitigate_fn or mit.mitigate
        self.ext_benign: list[Actor] = self._load_ext_benign()
        cfg.events.parent.mkdir(parents=True, exist_ok=True)

    # --- plumbing ----------------------------------------------------------------
    def emit(self, event: str, **kw) -> None:
        rec = {"t": round(time.time(), 3), "event": event, **kw}
        with self.cfg.events.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")

    def _load_ext_benign(self) -> list[Actor]:
        p = self.cfg.benign_actors
        if not p or not Path(p).exists():
            return []
        out = []
        for a in reconstruct(Path(p)).values():
            if len(a.requests) >= self.cfg.min_requests and not detect(a):
                out.append(a)      # sessions the observer itself judges non-campaign
        return out

    # --- observation -------------------------------------------------------------
    def ingest(self) -> int:
        recs = self.tail.read_new()
        for rec in recs:
            req = to_request(rec)
            ts = req.ts.timestamp() if req.ts != datetime.min else 0.0
            self.newest_ts = max(self.newest_ts, ts)
            k = actor_key(rec)
            self.actors.setdefault(k, Actor(key=k)).requests.append(req)
            self.dirty.add(k)
            self.recent.append((ts, rec))
        self._evict()
        return len(recs)

    def _evict(self) -> None:
        cutoff = self.newest_ts - self.cfg.window_s
        while self.recent and self.recent[0][0] < cutoff:
            self.recent.popleft()
        for k in [k for k, a in self.actors.items()
                  if a.requests and a.requests[-1].ts.timestamp() < cutoff]:
            del self.actors[k]
            self.dirty.discard(k)
            self.flagged.discard(k)

    def context_records(self) -> list[dict]:
        return [r for _, r in self.recent]

    def scan(self) -> list[tuple[str, str, list]]:
        """Run the detector on actors that changed; return NEW (actor, technique, findings)."""
        new = []
        for k in sorted(self.dirty):
            a = self.actors.get(k)
            if a is None or len(a.requests) < self.cfg.min_requests:
                continue
            a.requests.sort(key=lambda r: r.ts)
            findings = detect(a)
            if not findings:
                continue
            self.flagged.add(k)
            by_tech: dict[str, list] = {}
            for f in findings:
                by_tech.setdefault(f.technique, []).append(f)

            def weight(tech: str) -> int:
                if tech in INJECTION:
                    return len(evidence(a, tech))
                ev = RATE_EVIDENCE.get(tech)
                return sum(1 for r in a.requests if ev(r)) if ev else 0
            # the technique with the most evidence is the actor's main campaign: handle it first
            for tech, fs in sorted(by_tech.items(), key=lambda kv: -weight(kv[0])):
                if (k, tech) not in self.handled:
                    self.handled.add((k, tech))
                    new.append((weight(tech), k, tech, fs))
        self.dirty.clear()
        # Strongest evidence first: with hundreds of look-alike false triggers queued, the campaign with
        # the most evidence must not wait behind them (stable sort keeps arrival order within a weight).
        new.sort(key=lambda x: -x[0])
        return [(k, tech, fs) for _, k, tech, fs in new]

    # --- the benign evidence the rate gate judges against -----------------------
    def benign_actors(self) -> list[Actor]:
        live = [a for k, a in self.actors.items()
                if k not in self.flagged and len(a.requests) >= self.cfg.min_requests]
        return live + self.ext_benign

    def rate_gate(self, ir: dict, attacker: Actor) -> tuple[bool, list[dict]]:
        stages: list[dict] = []
        try:
            spec = irc.compile_rate(ir)
        except (irc.IRError, ValueError) as e:
            return False, [{"stage": "compile", "passed": False, "detail": f"IR rejected: {e}"}]
        stages.append({"stage": "compile", "passed": True, "detail": "rate spec valid"})
        benign = self.benign_actors()
        if len(benign) < MIN_BENIGN_ACTORS:
            stages.append({"stage": "benign_evidence", "passed": False,
                           "detail": f"only {len(benign)} non-campaign actors observed "
                                     f"(need {MIN_BENIGN_ACTORS}); cannot show the rule is safe"})
            return False, stages
        if spec.get("key") == "account":
            return self._account_gate(spec, benign, attacker, stages)
        hit = [a for a in benign if blocked_count(a.requests, spec) > 0]
        stages.append({"stage": "benign_actors", "passed": not hit,
                       "detail": f"non-campaign actors rate-limited: {len(hit)}/{len(benign)}"})
        if hit:
            return False, stages
        n_atk = blocked_count(attacker.requests, spec)
        stages.append({"stage": "attack_actor", "passed": n_atk > 0,
                       "detail": f"campaign actor would have {n_atk} request(s) limited"})
        return n_atk > 0, stages

    @staticmethod
    def _by_account(actors: list[Actor]) -> dict[str, list]:
        streams: dict[str, list] = {}
        for a in actors:
            for r in a.requests:
                acct = account_of(r.body)
                if acct:
                    streams.setdefault(acct, []).append(r)
        for rs in streams.values():
            rs.sort(key=lambda r: r.ts)
        return streams

    def _account_gate(self, spec: dict, benign: list[Actor], attacker: Actor, stages: list[dict]):
        """Account-keyed rule: counts attempts per TARGET account across all identities.

        An attacker who rotates identity produces many short sessions the observer never
        flags, so "non-campaign" evidence cannot be trusted for the accounts under attack.
        Hence: the accounts the flagged campaign targets are judged on ALL requests naming them
        (every identity), and are expected to be limited -- that is the rule's purpose, and
        also its cost: the victim can be locked out too (docs/M4-RESULTS.md). Safe iff NO
        OTHER account would be limited; effective iff an attacked account would be."""
        pool = [a for k, a in self.actors.items() if k in self.flagged]
        if attacker not in pool:
            pool.append(attacker)
        attacked = set(self._by_account(pool))
        every = self._by_account(list(self.actors.values()))
        ben = {a: rs for a, rs in self._by_account(benign).items() if a not in attacked}
        hit = [a for a, rs in ben.items() if blocked_count(rs, spec) > 0]
        stages.append({"stage": "benign_accounts", "passed": not hit,
                       "detail": f"accounts outside the campaign that would be rate-limited: "
                                 f"{len(hit)}/{len(ben)}"})
        if hit:
            return False, stages
        limited = [a for a in attacked if blocked_count(every.get(a, []), spec) > 0]
        stages.append({"stage": "attack_accounts", "passed": bool(limited),
                       "detail": f"attacked accounts that would be limited: {len(limited)}/{len(attacked)} "
                                 f"(victim lock-out is the accepted cost)"})
        return bool(limited), stages

    # --- mitigation ----------------------------------------------------------------
    def _dossier(self, actor: Actor, tech: str, findings) -> tuple[dict, list[dict], list]:
        d = build_dossier(actor, findings)
        if tech in INJECTION:
            ev = evidence(actor, tech)
        else:
            ev = [r for r in actor.requests if RATE_EVIDENCE[tech](r)]
        dossier = {"actor": actor.key, "techniques": [tech], "attack_class": TECH_CLASS[tech],
                   "suspected_objective": d.suspected_objective, "confidence": d.confidence,
                   "individually_unremarkable": d.individually_unremarkable,
                   "endpoints": sorted({r.endpoint for r in ev}), "n_requests": d.n_requests,
                   "status_mix": d.status_mix}
        reqs = [{"method": r.method, "uri": r.raw.get("uri", ""), "body": r.body,
                 "content_type": r.raw.get("content_type") or "application/json",
                 "malicious": True} for r in ev]
        return dossier, reqs, ev

    def _mitigate_rate(self, dossier: dict, cls: str, attacker: Actor) -> dict:
        t0 = time.perf_counter()
        cid, sig = self.mem.record_campaign(dossier)
        exact = self.mem.rule_for_signature(sig)
        esc = sig in self.escalated
        if exact and exact["id"] not in self.failed_live and not (esc and exact.get("key", "actor") != "account"):
            self.mem.touch_rule(exact["id"])
            ttm = time.perf_counter() - t0
            self.mem.record_outcome(cid, "reused", exact["id"], ttm)
            return {"source": "reused", "rule": exact["id"], "ttm_s": ttm, "signature": sig}
        if self.mem.promotions_since(time.time() - 3600) >= self.cfg.max_new_rules_per_hour:
            ttm = time.perf_counter() - t0
            self.mem.record_outcome(cid, "governor_blocked", None, ttm)
            return {"source": "governor_blocked", "rule": None, "ttm_s": ttm, "signature": sig}
        cands = [ir for ir in deliberator.candidates_for(cls, dossier)
                 if ir.get("mechanism") == "rate_limit" and ir["id"] not in self.failed_live]
        if esc:
            # Identity rotation seen: try the account-keyed limits first. If none is safe,
            # FALL BACK to the identity-keyed ones rather than leave the campaign unprotected
            # (a live run left stuffing unmitigated for a whole phase before this fallback).
            cands = ([c for c in cands if c.get("key", "actor") == "account"]
                     + [c for c in cands if c.get("key", "actor") != "account"])
        for ir in cands:
            ok, stages = self.rate_gate(ir, attacker)
            rej = next((s["stage"] for s in stages if not s["passed"]), None)
            self.mem.record_candidate(cid, ir, "passed_offline" if ok else "rejected", rej,
                                      [s["detail"] for s in stages])
            self.emit("candidate", id=ir["id"], ok=ok, rejected_at=rej,
                      stages=[s["detail"] for s in stages])
            if ok:
                ttm = time.perf_counter() - t0
                self.mem.promote_rule(ir, sig)
                self.mem.record_outcome(cid, "fresh", ir["id"], ttm)
                return {"source": "fresh", "rule": ir["id"], "ttm_s": ttm, "signature": sig}
        ttm = time.perf_counter() - t0
        self.mem.record_outcome(cid, "none", None, ttm)
        return {"source": "none", "rule": None, "ttm_s": ttm, "signature": sig}

    def _live_pipeline(self, ir: dict) -> dict:
        return LS.live_pipeline(ir, None, ir["attack_class"], self.cfg.shadow_s,
                                self.cfg.canary_s, self.cfg.canary_pct, drive=False,
                                context=self.context_records(), require_samples=True)

    @staticmethod
    def _mode_of(rule_id: str) -> str | None:
        e = next((r for r in rulestore.load()["rules"] if r["id"] == rule_id), None)
        return e.get("mode") if e else None

    def deploy(self, ir: dict) -> bool:
        """Get a gate-passed rule into enforcement via the live stages (or note that it
        is already enforcing). Any failure leaves the rule OFF."""
        if self._mode_of(ir["id"]) == "enforce":
            self.emit("already_enforcing", rule=ir["id"])
            return True
        self.emit("live_start", rule=ir["id"], shadow_s=self.cfg.shadow_s,
                  canary_s=self.cfg.canary_s, canary_pct=self.cfg.canary_pct)
        try:
            res = self.live(ir)
        except BaseException as e:                 # fail safe: never leave a half-tested rule on
            try:
                rulestore.set_mode(ir["id"], "off")
            except Exception:
                pass
            # A crash or a vanished rule (e.g. HTTP 404 from the admin API) is an operational
            # error, NOT a gate verdict: switch the rule off but do not blacklist it.
            self.emit("live_error", rule=ir["id"], error=repr(e))
            if isinstance(e, (KeyboardInterrupt, SystemExit)):
                raise
            return False
        for s in res["stages"]:
            self.emit("live_stage", rule=ir["id"], stage=s.stage, passed=s.passed,
                      detail=s.detail, numbers=s.numbers)
        if res["promoted"]:
            self.enforced_at[ir["id"]] = time.time()
            self.emit("enforced", rule=ir["id"])
            return True
        # A canary that rolled back on a latency/5xx comparison (not on suspected false
        # positives) is retried ONCE: the comparison is between two different groups of
        # actors and was seen to false-alarm on clustered traffic (docs/E2E-RESULTS.md).
        # The retry must pass a clean canary on its own; suspected-FP rollbacks are final.
        last = res["stages"][-1] if res["stages"] else None
        noisy = (last is not None and last.stage == "canary" and "ROLLED BACK" in last.detail
                 and ("5xx" in last.detail or "latency" in last.detail))
        if noisy and ir["id"] not in self.retried:
            self.retried.add(ir["id"])
            self.emit("retry_after_noisy_rollback", rule=ir["id"], detail=last.detail)
            return self.deploy(ir)
        self.failed_live.add(ir["id"])
        self.mem.set_rule_status(ir["id"], "rejected_live")
        self.emit("rejected_live", rule=ir["id"])
        return False

    def handle(self, key: str, tech: str, findings: list) -> None:
        actor = self.actors.get(key)
        onset = min((_epoch(f.onset) or 0.0) for f in findings) or None
        self.emit("campaign_detected", actor=key, technique=tech, onset=onset,
                  ttd_s=min(f.ttd_s for f in findings),
                  n_requests=len(actor.requests) if actor else 0)
        cls = TECH_CLASS.get(tech)
        if cls is None or actor is None:
            self.emit("no_template", technique=tech)
            return
        dossier, reqs, ev = self._dossier(actor, tech, findings)
        if not ev:
            self.emit("no_evidence", technique=tech)
            return
        sig = signature(cls, dossier["endpoints"])
        # Budget (invariant 7): only campaigns that need NEW work (synthesis + gate) count.
        # A repeat of a campaign whose rule is already known costs a lookup, and an
        # attacker rotating identities must not be able to exhaust the budget for real work.
        known = self.mem.rule_for_signature(sig)
        exclude = set(self.failed_live)
        bypass = False
        if tech == "credential_stuffing":
            # A second identity running the same campaign inside 10 minutes means the attacker
            # rotates identity: an identity-keyed limit is beaten by construction, so escalate
            # to an account-keyed one (counts guesses per TARGET account).
            seen = self.sig_actors.setdefault(sig, {})
            seen[key] = time.time()
            recent = [k for k, t in seen.items() if time.time() - t < ESCALATE_WINDOW_S]
            if len(recent) >= 2 and sig not in self.escalated:
                self.escalated.add(sig)
                self.emit("identity_rotation_detected", technique=tech, identities=len(recent))
            if sig in self.escalated and known and known.get("key", "actor") != "account":
                known = None
        if (known and known["id"] not in exclude and tech in INJECTION
                and self._mode_of(known["id"]) == "enforce"):
            # The rule that should stop this campaign is enforcing, yet the campaign's
            # evidence still reached the app: the rule does not cover this variant.
            # Only requests that arrived AFTER the rule was enforcing count: an attacker whose
            # campaign began before enforcement has legitimately unblocked history (a live run
            # mistook that for a bypass, searched in vain, and the cooldown then delayed a real
            # redeploy by ten minutes).
            since = self.enforced_at.get(known["id"], 0.0) + BYPASS_GRACE_S
            leaked = [r for r in ev if not r.raw.get("blocked") and r.ts.timestamp() >= since]
            if len(leaked) >= BYPASS_MIN:
                self.emit("rule_bypassed", rule=known["id"], technique=tech,
                          leaked=len(leaked), of=len(ev))
                exclude.add(known["id"])
                known = None
                bypass = True
        ckey = sig + "#" + _evidence_fp(ev) + ("#bypass" if bypass else "")
        if time.time() - self.cooldown.get(ckey, 0.0) < COOLDOWN_S:
            self.emit("cooldown_skip", technique=tech, signature=sig, bypass=bypass)
            return
        if not (known and known["id"] not in exclude):
            now = time.time()
            while self.handled_times and now - self.handled_times[0][0] > 3600:
                self.handled_times.popleft()
            per_tech = sum(1 for _, t in self.handled_times if t == tech)
            # A total cap alone let noise starve real work: ~190 false idor_bola triggers on
            # synthetic users used up the 30/hour budget before a SQLi campaign was handled
            # (a live replicate never mitigated SQLi). Each technique now has its own share.
            if len(self.handled_times) >= self.cfg.max_campaigns_per_hour or per_tech >= self.cfg.max_per_technique_per_hour:
                self.emit("budget_skip", technique=tech, reason="campaigns/hour cap",
                          cap=self.cfg.max_campaigns_per_hour, per_technique=per_tech)
                return
            self.handled_times.append((now, tech))
        if tech in RATE:
            res = self._mitigate_rate(dossier, cls, actor)
        else:
            res = self.mitigate_fn(dossier, reqs, self.cfg.benign_corpus, self.mem,
                                   max_new_per_hour=self.cfg.max_new_rules_per_hour,
                                   llm=self.cfg.llm, llm_rounds=self.cfg.llm_rounds,
                                   exclude=frozenset(exclude))
        self.emit("mitigation", technique=tech, source=res["source"], rule=res.get("rule"),
                  ttm_s=round(res["ttm_s"], 4), signature=res.get("signature"))
        if not res.get("rule"):
            self.cooldown[ckey] = time.time()   # don't re-run an expensive failed search
            return
        ir = self.mem.rule_ir(res["rule"])
        if ir is None:
            self.emit("error", where="rule_ir", rule=res["rule"])
            return
        self.deploy(ir)

    # --- main loop ---------------------------------------------------------------------
    def step(self) -> int:
        n = self.ingest()
        for key, tech, findings in self.scan():
            try:
                self.handle(key, tech, findings)
            except Exception as e:     # one bad campaign must not stop the loop
                self.emit("error", where="handle", technique=tech, error=repr(e),
                          trace=traceback.format_exc()[-600:])
        return n

    def _switch_off_unfinished(self) -> None:
        """A rule left in shadow/canary (controller stopped or crashed mid-stage) has not
        finished the gate: switch it off rather than leave it half-tested."""
        try:
            for r in rulestore.load()["rules"]:
                if r.get("mode") in ("shadow", "canary"):
                    rulestore.set_mode(r["id"], "off")
                    self.emit("switched_off_unfinished", rule=r["id"], was=r.get("mode"))
        except Exception as e:
            self.emit("error", where="switch_off_unfinished", error=repr(e))

    def run(self, stop_file: Path | None = None, max_seconds: float | None = None) -> None:
        t0 = time.time()
        self.emit("controller_start", log=str(self.cfg.log), shadow_s=self.cfg.shadow_s,
                  canary_s=self.cfg.canary_s, window_s=self.cfg.window_s,
                  ext_benign_actors=len(self.ext_benign))
        self._switch_off_unfinished()
        try:
            while True:
                if stop_file and stop_file.exists():
                    break
                if max_seconds and time.time() - t0 > max_seconds:
                    break
                try:
                    self.step()
                except Exception as e:
                    self.emit("error", where="step", error=repr(e),
                              trace=traceback.format_exc()[-600:])
                time.sleep(self.cfg.tick_s)
        finally:
            self._switch_off_unfinished()
            self.emit("controller_stop", memory=self.mem.stats())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", type=Path, default=Config.log)
    ap.add_argument("--events", type=Path, default=Config.events)
    ap.add_argument("--db", type=Path, default=Config.db)
    ap.add_argument("--benign-corpus", type=Path,
                    default=(sorted((ROOT / "data" / "benign_corpus").glob("benign_*detect*.jsonl")) or [None])[0])
    ap.add_argument("--benign-actors", type=Path, default=None,
                    help="gateway-format log of real user sessions (for the rate gate)")
    ap.add_argument("--shadow-s", type=float, default=Config.shadow_s)
    ap.add_argument("--canary-s", type=float, default=Config.canary_s)
    ap.add_argument("--canary-pct", type=int, default=Config.canary_pct)
    ap.add_argument("--stop-file", type=Path, default=ROOT / "logs" / "controller" / "stop")
    ap.add_argument("--max-seconds", type=float, default=None)
    ap.add_argument("--from-start", action="store_true")
    ap.add_argument("--llm", choices=["none", "ollama"], default="none")
    ap.add_argument("--model", default="mistral:latest")
    a = ap.parse_args()
    llm_backend = None
    if a.llm == "ollama":
        import llm as llm_mod
        llm_backend = llm_mod.OllamaBackend(a.model)
    cfg = Config(log=a.log, events=a.events, db=a.db, benign_corpus=a.benign_corpus,
                 benign_actors=a.benign_actors, shadow_s=a.shadow_s, canary_s=a.canary_s,
                 canary_pct=a.canary_pct, from_start=a.from_start, llm=llm_backend)
    Controller(cfg).run(stop_file=a.stop_file, max_seconds=a.max_seconds)
    return 0


if __name__ == "__main__":
    sys.exit(main())
