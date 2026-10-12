"""Tests for the autonomous controller's safety properties (no gateway needed).

The live stages are replaced by a fake; what is tested is the controller's own
logic: detection from a tailed log, budgets, the rate gate's refusal to act on thin
or harmful evidence, memory reuse, and that a failing/crashing deployment leaves
the rule OFF and never offered again.
"""

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controller"))
import loop                               # noqa: E402
from store import Memory                  # noqa: E402

T0 = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)


def rec(sec, session, method="GET", uri="/", body="", status=200):
    return {"ts": (T0 + timedelta(seconds=sec)).isoformat().replace("+00:00", "Z"),
            "method": method, "uri": uri, "body": body, "status": status,
            "session": session, "user_agent": "Mozilla/5.0", "content_type": "application/json",
            "anomaly_score": 0}


def stuffing(session, start=0.0, n=8):
    return [rec(start + i * 2, session, "POST", "/rest/user/login",
                json.dumps({"email": f"u{i}@x.test", "password": "pw"}), 401) for i in range(n)]


def benign_users(n=25, start=0.0):
    out = []
    for u in range(n):
        for i in range(4):
            out.append(rec(start + u + i * 10, f"benign-{u}", "GET", f"/rest/products/search?q=apple{i}"))
    return out


class Fake:
    """Stands in for live_stages.live_pipeline."""
    def __init__(self, promoted=True, boom=False):
        self.promoted, self.boom, self.calls = promoted, boom, []

    def __call__(self, ir):
        self.calls.append(ir["id"])
        if self.boom:
            raise RuntimeError("gateway vanished")
        st = [loop.LS.LiveResult("shadow", self.promoted, "fake"),
              loop.LS.LiveResult("canary", self.promoted, "fake")]
        return {"id": ir["id"], "promoted": self.promoted, "stages": st}


class Base(unittest.TestCase):
    window = 0.0       # identity-rotation escalation off by default; its own tests turn it on

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = Path(self.td.name)
        self.log = d / "req.jsonl"
        self.log.write_text("")
        self.cfg = loop.Config(log=self.log, events=d / "events.jsonl", db=d / "m.db",
                               benign_corpus=d / "none.jsonl", from_start=True)
        self.mem = Memory(self.cfg.db)
        # never touch the real manifest / a real gateway
        self.p = [mock.patch.object(loop, "ESCALATE_WINDOW_S", self.window),
                  mock.patch.object(loop.rulestore, "load", return_value={"version": 1, "rules": []}),
                  mock.patch.object(loop.rulestore, "set_mode", return_value="ok")]
        for p in self.p:
            p.start()

    def tearDown(self):
        for p in self.p:
            p.stop()
        self.mem.close()
        self.td.cleanup()

    def feed(self, records):
        with self.log.open("a", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

    def events(self):
        p = self.cfg.events
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    def names(self):
        return [e["event"] for e in self.events()]


class LogTailTests(unittest.TestCase):
    def test_partial_line_waits_for_completion(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "l.jsonl"
            tail = loop.LogTail(p, from_start=True)
            p.write_bytes(b'{"a":1}\n{"b":')
            self.assertEqual(tail.read_new(), [{"a": 1}])
            with p.open("ab") as f:
                f.write(b'2}\n')
            self.assertEqual(tail.read_new(), [{"b": 2}])

    def test_default_ignores_history(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "l.jsonl"
            p.write_text('{"old":1}\n')
            tail = loop.LogTail(p)
            self.assertEqual(tail.read_new(), [])
            with p.open("a") as f:
                f.write('{"new":1}\n')
            self.assertEqual(tail.read_new(), [{"new": 1}])

    def test_garbage_lines_are_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "l.jsonl"
            p.write_bytes(b'not json\n\xff\xfe\n{"ok":1}\n')
            self.assertEqual(loop.LogTail(p, True).read_new(), [{"ok": 1}])


class RateCampaignFlow(Base):
    def test_detect_gate_deploy_and_memory_reuse(self):
        fake = Fake()
        c = loop.Controller(self.cfg, self.mem, live=fake)
        self.feed(benign_users() + stuffing("atk-1"))
        c.step()
        n = self.names()
        self.assertIn("campaign_detected", n)
        self.assertIn("mitigation", n)
        self.assertIn("enforced", n)
        mitig = next(e for e in self.events() if e["event"] == "mitigation"
                     and e["technique"] == "credential_stuffing")
        self.assertEqual(mitig["source"], "fresh")
        self.assertEqual(fake.calls, [mitig["rule"]])
        # the same campaign again, from a new actor: recognised, no fresh synthesis
        self.feed(stuffing("atk-2", start=100))
        c.step()
        again = [e for e in self.events() if e["event"] == "mitigation"
                 and e["technique"] == "credential_stuffing"][-1]
        self.assertEqual(again["source"], "reused")

    def test_no_benign_evidence_means_no_rule(self):
        c = loop.Controller(self.cfg, self.mem, live=Fake())
        self.feed(benign_users(n=5) + stuffing("atk-1"))
        c.step()
        self.assertNotIn("enforced", self.names())
        cands = [e for e in self.events() if e["event"] == "candidate"]
        self.assertTrue(cands and all(not e["ok"] and e["rejected_at"] == "benign_evidence" for e in cands))

    def test_rule_that_would_limit_a_real_user_is_rejected(self):
        # The rate gate must refuse a rule that would throttle any non-campaign actor, even
        # though the same rule stops the attacker. Here a 'known good' session (as the
        # observer would have judged it) logs in 7 times in a minute.
        c = loop.Controller(self.cfg, self.mem, live=Fake())
        for r in benign_users():
            self.feed([r])
        c.step()
        user = loop.Actor(key="benign-x")
        user.requests = [loop.to_request(r) for r in stuffing("benign-x", 0.0, 7)]
        c.ext_benign = [user]
        attacker = loop.Actor(key="atk")
        attacker.requests = [loop.to_request(r) for r in stuffing("atk", 0.0, 8)]
        ir = loop.deliberator.candidates_for("credential_stuffing", {})[0]
        ok, stages = c.rate_gate(ir, attacker)
        self.assertFalse(ok)
        self.assertEqual([s["stage"] for s in stages if not s["passed"]], ["benign_actors"])
        # ...and with that user removed, the same rule is accepted
        c.ext_benign = []
        ok, _ = c.rate_gate(ir, attacker)
        self.assertTrue(ok)


class Cooldown(Base):
    def test_failed_search_is_not_repeated_immediately(self):
        c = loop.Controller(self.cfg, self.mem, live=Fake())
        self.feed(benign_users(n=5) + stuffing("atk-1"))      # too little benign evidence -> no rule
        c.step()
        self.feed(stuffing("atk-2", start=100))
        c.step()
        self.assertIn("cooldown_skip", self.names())


class FailSafe(Base):
    def test_failed_live_stage_leaves_rule_off_and_is_not_reused(self):
        fake = Fake(promoted=False)
        c = loop.Controller(self.cfg, self.mem, live=fake)
        self.feed(benign_users() + stuffing("atk-1"))
        c.step()
        self.assertIn("rejected_live", self.names())
        self.assertNotIn("enforced", self.names())
        rid = fake.calls[0]
        self.assertIn(rid, c.failed_live)
        self.assertEqual(self.mem.rule_for_signature(
            next(e for e in self.events() if e["event"] == "mitigation")["signature"]), None)

    def test_crash_during_deployment_switches_rule_off(self):
        c = loop.Controller(self.cfg, self.mem, live=Fake(boom=True))
        self.feed(benign_users() + stuffing("atk-1"))
        c.step()                      # must not raise
        self.assertIn("live_error", self.names())
        loop.rulestore.set_mode.assert_called_with(mock.ANY, "off")
        self.assertNotIn("enforced", self.names())

    def test_already_enforcing_rule_is_not_redeployed(self):
        fake = Fake()
        c = loop.Controller(self.cfg, self.mem, live=fake)
        self.feed(benign_users() + stuffing("atk-1"))
        c.step()
        rid = fake.calls[0]
        loop.rulestore.load.return_value = {"version": 3, "rules": [{"id": rid, "mode": "enforce"}]}
        self.feed(stuffing("atk-2", start=100))
        c.step()
        self.assertEqual(fake.calls, [rid])                 # not deployed a second time
        self.assertIn("already_enforcing", self.names())

    def test_campaign_budget_per_hour(self):
        self.cfg.max_campaigns_per_hour = 1
        c = loop.Controller(self.cfg, self.mem, live=Fake())
        self.feed(benign_users() + stuffing("atk-1") + stuffing("atk-2", start=0))
        c.step()
        self.assertIn("budget_skip", self.names())


class OperationalErrorsAreNotVerdicts(Base):
    def test_live_error_does_not_blacklist_the_rule(self):
        c = loop.Controller(self.cfg, self.mem, live=Fake(boom=True))
        self.feed(benign_users() + stuffing("atk-1"))
        c.step()
        self.assertEqual(c.failed_live, set())
        sig = next(e for e in self.events() if e["event"] == "mitigation")["signature"]
        self.assertIsNotNone(self.mem.rule_for_signature(sig))     # still reusable later

    def test_noisy_canary_rollback_is_retried_once_then_final(self):
        calls = []

        def live(ir):
            calls.append(ir["id"])
            st = [loop.LS.LiveResult("shadow", True, "ok"),
                  loop.LS.LiveResult("canary", False, "ROLLED BACK after 20s: 5xx regression: canary 9% vs control 4% (z=3.0)")]
            return {"id": ir["id"], "promoted": False, "stages": st}
        c = loop.Controller(self.cfg, self.mem, live=live)
        self.feed(benign_users() + stuffing("atk-1"))
        c.step()
        rid = calls[0]
        self.assertEqual(calls, [rid, rid])                      # exactly one retry
        self.assertIn("retry_after_noisy_rollback", self.names())
        self.assertIn(rid, c.failed_live)

    def test_suspected_false_positive_rollback_is_final(self):
        calls = []

        def live(ir):
            calls.append(ir["id"])
            st = [loop.LS.LiveResult("canary", False, "ROLLED BACK after 9s: suspected false positives: 4 blocks")]
            return {"id": ir["id"], "promoted": False, "stages": st}
        c = loop.Controller(self.cfg, self.mem, live=live)
        self.feed(benign_users() + stuffing("atk-1"))
        c.step()
        self.assertEqual(len(calls), 1)


class BypassDetection(Base):
    def test_enforcing_rule_that_does_not_stop_the_evidence_triggers_resynthesis(self):
        seen = {}

        def fake_mitigate(dossier, reqs, corpus, mem, **kw):
            seen["exclude"] = kw["exclude"]
            return {"source": "none", "rule": None, "ttm_s": 0.0, "signature": "x"}
        c = loop.Controller(self.cfg, self.mem, live=Fake(), mitigate_fn=fake_mitigate)
        # a known, enforcing cmdi rule for this campaign signature
        ir = loop.deliberator.candidates_for("cmdi", {"endpoints": ["/rest/products/search"]})[0]
        sig = loop.signature("cmdi", ["/rest/products/search"])
        self.mem.promote_rule(ir, sig)
        loop.rulestore.load.return_value = {"version": 2, "rules": [{"id": ir["id"], "mode": "enforce"}]}
        atk = [dict(rec(i, "atk-9", "GET", "/rest/products/search?q=apple%3B+cat+%2Fetc%2Fpasswd"), blocked=False)
               for i in range(4)]
        self.feed(benign_users() + atk)
        c.step()
        self.assertIn("rule_bypassed", self.names())
        self.assertIn(ir["id"], seen["exclude"])

    def test_blocked_evidence_is_not_a_bypass(self):
        c = loop.Controller(self.cfg, self.mem, live=Fake())
        ir = loop.deliberator.candidates_for("cmdi", {"endpoints": ["/rest/products/search"]})[0]
        self.mem.promote_rule(ir, loop.signature("cmdi", ["/rest/products/search"]))
        loop.rulestore.load.return_value = {"version": 2, "rules": [{"id": ir["id"], "mode": "enforce"}]}
        atk = [dict(rec(i, "atk-9", "GET", "/rest/products/search?q=apple%3B+cat+%2Fetc%2Fpasswd", status=403),
                    blocked=True) for i in range(4)]
        self.feed(benign_users() + atk)
        c.step()
        self.assertNotIn("rule_bypassed", self.names())


def stuffing_accounts(session, start, accounts, per_account):
    """An identity-rotating attacker: each request names one of a few accounts."""
    out, t = [], start
    for i in range(per_account):
        for a in accounts:
            out.append(rec(t, session, "POST", "/rest/user/login",
                           json.dumps({"email": a, "password": f"p{i}"}), 401))
            t += 1.0
    return out


class AccountKeyedEscalation(Base):
    window = 600.0

    def test_rotating_identities_escalate_to_an_account_keyed_rule(self):
        c = loop.Controller(self.cfg, self.mem, live=Fake())
        self.feed(benign_users())
        # first identity: a normal stuffing run -> identity-keyed rule
        self.feed(stuffing("atk-1"))
        c.step()
        # a second identity hammers two accounts: the attacker rotates
        self.feed(stuffing_accounts("atk-2", 100, ["admin@x.test", "jim@x.test"], 4)
                  + stuffing_accounts("atk-3", 140, ["admin@x.test", "jim@x.test"], 4))
        c.step()
        self.assertIn("identity_rotation_detected", self.names())
        cands = [e["id"] for e in self.events() if e["event"] == "candidate" and e["ok"]]
        self.assertTrue(any(i in ("aegis-credential_stuffing-3", "aegis-credential_stuffing-4") for i in cands), cands)

    def test_falls_back_to_identity_keyed_rule_when_no_account_rule_is_safe(self):
        c = loop.Controller(self.cfg, self.mem, live=Fake())
        self.feed(benign_users())
        self.feed(stuffing("atk-1"))
        c.step()
        # 2nd identity -> escalation; make every account-keyed candidate fail the gate
        real = c.rate_gate

        def gate(ir, attacker):
            if ir.get("key") == "account":
                return False, [{"stage": "benign_accounts", "passed": False, "detail": "x"}]
            return real(ir, attacker)
        c.rate_gate = gate
        self.mem.set_rule_status("aegis-credential_stuffing-1", "retired")   # force a fresh search
        c.failed_live.clear()
        self.feed(stuffing("atk-2", start=100))
        c.step()
        self.assertIn("identity_rotation_detected", self.names())
        enforced = [e["rule"] for e in self.events() if e["event"] == "enforced"]
        self.assertGreaterEqual(len(enforced), 2, self.names())     # the fallback got deployed

    def test_account_gate_counts_across_identities_and_protects_benign_accounts(self):
        c = loop.Controller(self.cfg, self.mem, live=Fake())
        # 25 ordinary users, each logging in once or twice to their OWN account
        ben = []
        for u in range(25):
            ben += [rec(u * 5 + i, f"benign-{u}", "POST", "/rest/user/login",
                        json.dumps({"email": f"user{u}@x.test", "password": "pw"}), 200) for i in range(2)]
            ben += [rec(u * 5 + 3, f"benign-{u}", "GET", "/rest/products/search?q=a")]
        self.feed(ben)
        c.step()
        # 4 attacker identities, 3 guesses each, all against the SAME two accounts
        atk_reqs = []
        for n in range(4):
            atk_reqs += stuffing_accounts(f"atk-{n}", 130 + n * 20, ["admin@x.test", "jim@x.test"], 2)
        self.feed(atk_reqs)
        c.step()
        ir = next(x for x in loop.deliberator.candidates_for("credential_stuffing", {})
                  if x["id"] == "aegis-credential_stuffing-3")
        attacker = loop.Actor(key="atk-0", requests=[loop.to_request(r) for r in atk_reqs[:4]])
        ok, stages = c.rate_gate(ir, attacker)
        self.assertTrue(ok, stages)
        names = [s["stage"] for s in stages]
        self.assertIn("benign_accounts", names)
        self.assertIn("attack_accounts", names)
        # an identity-keyed 5/60 rule would NOT have stopped 3-guess identities
        ir1 = next(x for x in loop.deliberator.candidates_for("credential_stuffing", {})
                   if x["id"] == "aegis-credential_stuffing-1")
        self.assertEqual(loop.blocked_count(attacker.requests, loop.irc.compile_rate(ir1)), 0)

    def test_account_extraction_matches_gateway_rule(self):
        self.assertEqual(loop.account_of('{"email":"  Jim@X.Test "}'), "jim@x.test")
        self.assertEqual(loop.account_of('{"email":5}'), "")
        self.assertEqual(loop.account_of("not json"), "")


class Boundaries(unittest.TestCase):
    def test_controller_never_reads_ground_truth(self):
        src = (ROOT / "controller" / "loop.py").read_text(encoding="utf-8")
        code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
        self.assertNotIn("gt_label", code.replace("range-only gt_label", ""))
        self.assertNotIn("ground_truth", code)
        self.assertNotIn("is_attack_actor", code)


if __name__ == "__main__":
    unittest.main()
