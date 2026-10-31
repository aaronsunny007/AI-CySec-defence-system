"""The controller detects an identity-rotating campaign by pooling one-request actors by client IP. The live
shadow/canary stages judge a new rule by who it matched, so they must count those same actors as attackers.
Seen live: the rule passed every offline stage, then the shadow stage rejected it because all 59 of its matches
were on 'indeterminate' one-request actors (over the 50% cap), so the rotating attacker was never mitigated."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("gate", "ir", "observer", "eval", "range/attacks"):
    sys.path.insert(0, str(ROOT / p))
import live_stages as LS   # noqa: E402
import detector            # noqa: E402
from actors import reconstruct  # noqa: E402

RID = "aegis-sqli-3"
PAYLOADS = ["' OR 1=1--", "' UNION SELECT username,password FROM users--", "' AND SLEEP(5)--", "admin'--", "' OR '1'='1"]


def rec(i, session, uri, ident="auth", ip="203.0.113.7", matched=False):
    r = {"ts": f"2026-10-30T10:00:{i % 60:02d}Z", "method": "GET", "uri": uri, "body": "", "status": 403,
         "session": session, "user_agent": "x", "client_ip": ip, "ident": ident}
    if matched:
        r["aegis_matches"] = [f"{RID}|shadow|shadow"]
    return r


def rotating(n, ident="auth", ip="203.0.113.7"):
    return [rec(i, f"h:rot{i:03d}", "/search?q=" + PAYLOADS[i % 5].replace(" ", "%20"), ident, ip, matched=True)
            for i in range(n)]


class Live(unittest.TestCase):
    def test_rotating_attacker_is_flagged_so_its_matches_are_not_indeterminate(self):
        w = rotating(40)
        flagged = LS._flagged_actor_keys(w)
        self.assertEqual(len(flagged), 40)
        self.assertEqual(LS.judge_matches(w, RID, flagged), ([], []))

    def test_without_the_fix_the_matches_were_all_indeterminate(self):
        w = rotating(40)
        suspect, indet = LS.judge_matches(w, RID, flagged=set())       # what the old code concluded
        self.assertEqual((len(suspect), len(indet)), (0, 40))

    def test_benign_one_request_visitors_are_not_flagged(self):
        w = [rec(i, f"h:u{i}", f"/page{i}") for i in range(30)]
        self.assertEqual(LS._flagged_actor_keys(w), set())

    def test_a_benign_visitor_matching_the_rule_is_still_a_suspect(self):
        w = rotating(40) + [rec(1, "h:real", "/search?q=shoes", matched=True)] + \
            [rec(i, "h:real", f"/page{i}") for i in range(2, 8)]
        flagged = LS._flagged_actor_keys(w)
        self.assertNotIn("h:real", flagged)
        suspect, _ = LS.judge_matches(w, RID, flagged)
        self.assertEqual([r["session"] for r in suspect], ["h:real"])

    def test_lab_identities_are_not_pooled(self):
        self.assertEqual(LS._flagged_actor_keys(rotating(40, ident="vid")), set())

    def test_pools_are_per_ip(self):
        w = rotating(2, ip="198.51.100.1") + [dict(r, client_ip="198.51.100.2", session="h:z" + r["session"]) for r in rotating(2)]
        self.assertEqual(LS._flagged_actor_keys(w), set())

    def test_ordinary_visitors_sharing_an_address_with_a_few_odd_searches_are_not_flagged(self):
        w = rotating(6) + [rec(i, f"h:ok{i:03d}", f"/page{i % 9}") for i in range(200)]      # 3% payloads
        self.assertEqual(LS._flagged_actor_keys(w), set())

    def test_a_rotating_attacker_among_ordinary_traffic_is_still_flagged(self):
        w = rotating(40) + [rec(i, f"h:ok{i:03d}", f"/page{i % 9}") for i in range(60)]     # 40% payloads
        self.assertEqual(len(LS._flagged_actor_keys(w)), 40)

    def test_helper_returns_the_pooled_actor(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "w.jsonl"
            import json
            path.write_text("\n".join(json.dumps(r) for r in rotating(12)))
            pooled = detector.pooled_orphans(reconstruct(path))
        (keys, actor), = pooled.values()
        self.assertEqual(len(keys), 12)
        self.assertTrue(actor.key.startswith("orphans:"))


if __name__ == "__main__":
    unittest.main()
