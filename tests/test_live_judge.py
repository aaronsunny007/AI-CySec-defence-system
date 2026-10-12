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


if __name__ == "__main__":
    unittest.main()
