"""An attacker who sets a fresh Authorization header (or app cookie) on every request used to turn one SQLi
campaign into N one-request actors, none of which the detector ever judged: 0 campaigns detected out of 40
payload requests (measured live). The controller now pools payload-bearing requests of too-small actors by
client IP. Also: its memory is budgeted, and the lab's cookie identity is never pooled."""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_controller as tc            # noqa: E402

loop = tc.loop

PAYLOADS = ["' OR 1=1--", "' UNION SELECT username,password FROM users--", "1; DROP TABLE users--",
            "' AND SLEEP(5)--", "admin'--", "' OR '1'='1", "1' ORDER BY 3--", "' UNION SELECT NULL,NULL,NULL--"]


def rotating(n, ident="auth", ip="203.0.113.7", start=0.0, payload=True):
    out = []
    for i in range(n):
        q = PAYLOADS[i % len(PAYLOADS)] if payload else f"shoes{i}"
        r = tc.rec(start + i * 0.5, f"h:rot{i:04d}", "GET", "/search?q=" + q.replace(" ", "%20"))
        r.update(ident=ident, client_ip=ip)
        out.append(r)
    return out


class Rotation(tc.Base):
    def detections(self):
        c = loop.Controller(self.cfg, self.mem, live=tc.Fake(), mitigate_fn=mock.Mock(
            return_value={"source": "none", "rule": None, "ttm_s": 0.0, "signature": "s"}))
        c.step()
        return c, [e for e in self.events() if e["event"] == "campaign_detected"]

    def test_rotating_authorization_header_is_still_detected(self):
        self.feed(rotating(40))
        c, det = self.detections()
        self.assertEqual([d["technique"] for d in det], ["sqli"], self.names())
        self.assertTrue(det[0]["actor"].startswith("orphans:203.0.113.7"))

    def test_rotating_app_cookie_is_detected(self):
        self.feed(rotating(40, ident="cookie"))
        _, det = self.detections()
        self.assertEqual(len(det), 1)

    def test_lab_cookie_identity_is_never_pooled(self):
        # in the lab each aegis_vid is a distinct simulated client behind one IP: pooling would merge them
        self.feed(rotating(40, ident="vid"))
        _, det = self.detections()
        self.assertEqual(det, [])

    def test_records_without_an_ident_are_never_pooled(self):    # logs written before the field existed
        recs = rotating(40)
        for r in recs:
            r.pop("ident")
        self.feed(recs)
        _, det = self.detections()
        self.assertEqual(det, [])

    def test_benign_rotating_traffic_is_not_flagged(self):
        self.feed(rotating(60, payload=False))
        _, det = self.detections()
        self.assertEqual(det, [])

    def test_a_few_payloads_below_the_minimum_are_not_a_campaign(self):
        self.feed(rotating(2))
        _, det = self.detections()
        self.assertEqual(det, [])

    def test_pooling_is_per_ip(self):
        self.feed(rotating(2, ip="198.51.100.1") + rotating(2, ip="198.51.100.2", start=5))
        _, det = self.detections()
        self.assertEqual(det, [], "two payloads from each of two IPs must not combine")

    def test_a_single_identity_campaign_is_not_double_counted(self):
        recs = []
        for i in range(10):
            r = tc.rec(i * 0.5, "h:one", "GET", "/search?q=" + PAYLOADS[i % 8].replace(" ", "%20"))
            r.update(ident="auth", client_ip="203.0.113.9")
            recs.append(r)
        self.feed(recs)
        _, det = self.detections()
        self.assertEqual(len(det), 1, [d["actor"] for d in det])
        self.assertEqual(det[0]["actor"], "h:one")


class Budgets(tc.Base):
    def test_actor_table_is_capped(self):
        with mock.patch.object(loop, "MAX_ACTORS", 100):
            c = loop.Controller(self.cfg, self.mem, live=tc.Fake())
            self.feed(rotating(1000, payload=False))
            c.step()
            self.assertLessEqual(len(c.actors), 100)

    def test_per_actor_history_is_capped(self):
        with mock.patch.object(loop, "MAX_ACTOR_REQUESTS", 50):
            c = loop.Controller(self.cfg, self.mem, live=tc.Fake())
            self.feed([tc.rec(i, "h:busy", "GET", f"/p/{i}") for i in range(400)])
            c.step()
            self.assertEqual(len(c.actors["h:busy"].requests), 50)

    def test_recent_context_is_capped(self):
        with mock.patch.object(loop, "MAX_RECENT", 100):
            c = loop.Controller(self.cfg, self.mem, live=tc.Fake())
            self.feed([tc.rec(i * 0.01, f"h:{i}", "GET", "/x") for i in range(1000)])
            c.step()
            self.assertLessEqual(len(c.recent), 100)


if __name__ == "__main__":
    unittest.main()
