"""The red agent's rules of engagement and adaptation logic (no network)."""

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "range" / "attacks"))
import adaptive                      # noqa: E402
from client import Result            # noqa: E402


def res(status, body=""):
    return Result(status, status in (403, 429), body, 1.0)


class Agent(unittest.TestCase):
    def run_agent(self, goal, statuses, budget=30, **kw):
        it = iter(statuses)

        def fake_fire(self_, *a, **k):
            try:
                s = next(it)
            except StopIteration:
                s = 403
            return res(s, "authentication" if s == 200 else "")
        with mock.patch.object(adaptive.Actor, "fire", fake_fire), \
                mock.patch.object(adaptive.time, "sleep", lambda s: None):
            return adaptive.RedAgent(goal, budget=budget, pace=0.0, **kw).run()

    def test_budget_is_a_hard_bound(self):
        rep = self.run_agent("command_injection", [403] * 1000, budget=25)
        self.assertEqual(rep.requests, 25)

    def test_only_the_local_range_by_default(self):
        self.assertTrue(adaptive.RedAgent("sqli", budget=1, pace=0).base.startswith("http://localhost"))

    def test_blocks_trigger_the_ladder_in_order(self):
        rep = self.run_agent("sqli", [403] * 12, budget=12)
        order = [e.split("->")[0].split(" ")[0] for _, e in rep.timeline]
        self.assertEqual(order[:3], ["mutate", "rotate", "slow"])
        self.assertEqual(rep.first_block_at, 1)

    def test_it_learns_a_quota_and_rotates_before_hitting_it(self):
        # 5 allowed, then 429s -> quota 5; afterwards it rotates proactively
        rep = self.run_agent("credential_stuffing", [401] * 5 + [429, 429] + [401] * 10, budget=17)
        self.assertEqual(rep.learned_quota, 5)
        self.assertGreaterEqual(rep.adaptations["rotate"], 2)
        self.assertGreater(rep.identities, 1)

    def test_stops_when_objective_met(self):
        rep = self.run_agent("credential_stuffing", [401, 401, 200], budget=50)
        self.assertTrue(rep.objective_met)
        self.assertEqual(rep.requests_to_objective, 3)
        self.assertEqual(rep.requests, 3)


if __name__ == "__main__":
    unittest.main()
