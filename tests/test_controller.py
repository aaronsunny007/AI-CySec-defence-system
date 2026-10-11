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
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = Path(self.td.name)
        self.log = d / "req.jsonl"
        self.log.write_text("")
        self.cfg = loop.Config(log=self.log, events=d / "events.jsonl", db=d / "m.db",
                               benign_corpus=d / "none.jsonl", from_start=True)
        self.mem = Memory(self.cfg.db)
        # never touch the real manifest / a real gateway
        self.p = [mock.patch.object(loop.rulestore, "load", return_value={"version": 1, "rules": []}),
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


class Boundaries(unittest.TestCase):
    def test_controller_never_reads_ground_truth(self):
        src = (ROOT / "controller" / "loop.py").read_text(encoding="utf-8")
        code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
        self.assertNotIn("gt_label", code.replace("range-only gt_label", ""))
        self.assertNotIn("ground_truth", code)
        self.assertNotIn("is_attack_actor", code)


if __name__ == "__main__":
    unittest.main()
