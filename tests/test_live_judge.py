"""The live stages' false-positive judge (no gateway needed)."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("gate", "ir", "observer", "eval", "range/attacks"):
    sys.path.insert(0, str(ROOT / p))
import live_stages as LS   # noqa: E402

RID = "aegis-x-1"


def rec(session, matched=False, outcome="shadow"):
    r = {"session": session, "uri": "/x", "method": "GET", "ts": "2026-10-11T12:00:00Z"}
    if matched:
        r["aegis_matches"] = [f"{RID}|shadow|{outcome}"]
    return r


class Judge(unittest.TestCase):
    def test_short_lived_identity_is_indeterminate_not_a_false_positive(self):
        # the attacker's 2-request second identity (the live-run bug)
        w = [rec("h:atk2", True), rec("h:atk2", True)]
        suspect, indet = LS.judge_matches(w, RID, flagged=set())
        self.assertEqual((len(suspect), len(indet)), (0, 2))

    def test_established_unflagged_actor_that_matches_is_a_suspected_fp(self):
        w = [rec("h:user", True)] + [rec("h:user") for _ in range(5)]
        suspect, indet = LS.judge_matches(w, RID, flagged=set())
        self.assertEqual((len(suspect), len(indet)), (1, 0))

    def test_context_counts_towards_actor_size(self):
        ctx = [rec("h:user") for _ in range(4)]
        suspect, _ = LS.judge_matches([rec("h:user", True)], RID, set(), ctx)
        self.assertEqual(len(suspect), 1)

    def test_flagged_actors_are_never_suspects(self):
        w = [rec("h:atk", True) for _ in range(5)]
        self.assertEqual(LS.judge_matches(w, RID, {"h:atk"}), ([], []))

    def test_outcome_filter(self):
        w = [rec("h:user", True, "shadow") for _ in range(4)]
        self.assertEqual(len(LS.judge_matches(w, RID, set(), outcome="blocked")[0]), 0)
        self.assertEqual(len(LS.judge_matches(w, RID, set(), outcome="shadow")[0]), 4)


class WindowStart(unittest.TestCase):
    def test_records_that_arrived_before_the_rule_loaded_are_excluded(self):
        import json
        import tempfile
        from datetime import datetime, timezone
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "g.jsonl"

            def line(ts):
                return json.dumps({"ts": datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z"),
                                   "uri": "/x"}) + chr(10)

            log.write_text(line(100.0) + line(101.0) + line(102.0), encoding="utf-8")
            old = LS.GATEWAY_LOG
            LS.GATEWAY_LOG = log
            try:
                self.assertEqual(len(LS._read_from(0)), 3)
                self.assertEqual(len(LS._read_from(0, since=101.0)), 2)     # the 100.0 request predates the rule
            finally:
                LS.GATEWAY_LOG = old


if __name__ == "__main__":
    unittest.main()


class CanaryLatencyIgnoresLongPolls(unittest.TestCase):
    def test_held_open_socketio_polls_do_not_count_as_a_regression(self):
        ls = LS
        win = [{"uri": "/rest/products/search?q=a", "canary": i % 4 == 0, "total_us": 40_000} for i in range(400)]
        # a few 25 s long-polls land in the canary slice
        win += [{"uri": "/socket.io/?EIO=4&transport=polling", "canary": True, "total_us": 25_000_000} for _ in range(20)]
        c, k = ls._slice_latencies(win)
        self.assertEqual(len(c) + len(k), 400)
        self.assertLessEqual(ls._p99(c), 3 * ls._p99(k) + ls.LAT_ABS_US)
