"""The observer and the LLM vocabulary run regular expressions over text an attacker controls. Before the fix,
one request of a quote followed by 60,000 spaces cost the SQLi pattern 43 s, 'select ' x 9000 cost 4 s and a few
KB of '{{' cost seconds: a handful of requests froze the out-of-band controller (no new rules). Each hostile input
below must now be scanned quickly. The 1 s ceiling is ~20x the measured worst case, so it only trips on a real
regression (a quantifier that became super-linear), not on a slow machine."""

import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "observer"))
sys.path.insert(0, str(ROOT / "deliberator"))
import detector  # noqa: E402
import llm       # noqa: E402

N = 200_000
HOSTILE = {
    "quote + spaces": "'" + " " * N + "x", "quote-paren pairs": "')" * N, "select repeated": "select " * 30000,
    "select no from": "select " + "fro " * N, "union + spaces": "union" + " " * N + "x", "or repeated": "' or " * N,
    "open braces": "{{" * N, "dollar braces": "${" * N, "angle-percent": "<%" * N, "hash braces": "#{" * N,
    "comment openers": "union" + "/*" * N, "backticks": "`" * N, "angle brackets": "<" * N, "dots": "../" * N,
    "pipes + spaces": "|" + " " * N + "x", "ampersands": "&&" + " " * N, "urls": "http://" * 30000,
    "percent": "%27 " * N, "digits and operators": "1+" * N, "one long token": "a" * N,
}
CEILING_S = 1.0


def req(text):
    return detector.Request(ts=None, method="GET", path="/x", query="", body=text, status=200,
                            anomaly_score=0, attack_tags=[], raw={})


class Linear(unittest.TestCase):
    def test_detector_signatures_are_fast_on_hostile_input(self):
        for name, text in HOSTILE.items():
            r = req(text)
            t0 = time.perf_counter()
            detector.has_payload(r)
            for fam in detector.SIGS:
                detector.evidence(detector.Actor(key="k", requests=[r]), fam)
            self.assertLess(time.perf_counter() - t0, CEILING_S, f"observer pattern is super-linear on: {name}")

    def test_llm_vocabulary_is_fast_on_hostile_input(self):
        for name, text in HOSTILE.items():
            t = llm._decoded({"uri": "/x", "body": text})
            t0 = time.perf_counter()
            for rx in llm.VOCAB.values():
                rx.search(t)
            self.assertLess(time.perf_counter() - t0, CEILING_S, f"vocabulary pattern is super-linear on: {name}")

    def test_scan_text_is_capped(self):
        self.assertLessEqual(len(detector._decoded(req("A" * 5_000_000))), detector.MAX_SCAN + 2)
        self.assertLessEqual(len(llm._decoded({"uri": "/x", "body": "A" * 5_000_000})), llm._MAX_SCAN + 2)

    def test_a_payload_at_the_start_or_end_of_a_huge_body_is_still_seen(self):
        pad = "A" * 3_000_000
        for body in (" ' OR 1=1-- " + pad, pad + " ' OR 1=1-- "):
            self.assertTrue(detector.has_payload(req(body)))

    def test_tautology_and_select_from_still_detected(self):
        for body in ("q=' OR 1=1--", "a' or 'x'='x", "x') AND (1=1", "select username, password from users",
                     "1 UNION SELECT NULL"):
            self.assertTrue(detector.SIGS["sqli"].search(body), body)


if __name__ == "__main__":
    unittest.main()
