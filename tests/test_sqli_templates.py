"""The gate needs ONE candidate that blocks all of a campaign's evidence. libinjection (candidates 1 and 2) misses
`admin'--`, and template 3 had no rule for a function call after quote+and/or, so it missed the time-based
`' AND SLEEP(5)--`. An ordinary mixed campaign of five requests therefore defeated every candidate and no rule
was made (found live: a campaign whose evidence had grown to five requests before it was handled). Template 3
now covers the function-call shape; it must still not match ordinary text."""

import json
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ir"))
sys.path.insert(0, str(ROOT / "deliberator"))
import compile as irc     # noqa: E402
import generate           # noqa: E402

REPLAY = ROOT / "bin" / ("replay.exe" if sys.platform == "win32" else "replay")
EVIDENCE = ["' OR 1=1--", "' UNION SELECT username,password FROM users--", "' AND SLEEP(5)--", "admin'--", "' OR '1'='1"]
TIME_BASED = ["' AND SLEEP(5)--", "' or sleep(5)#", "1' AND BENCHMARK(5000000,MD5(1))--", "' OR pg_sleep(5)--",
              "x'  and  sleep (3) --", "' AND/**/SLEEP(5)--"]
BENIGN = ["Bobby Tables' review of the O'Brien hummus", "rock 'n' roll", "it's a sleep(y) town", "O'Brien and sons",
          "the baker's and the grocer's shops", "don't or won't, that is the question", "sleep(", "and sleep(5) hours",
          "shoes and socks", "7ggq|;]3,p'#"]


def template(n, endpoints=("/search",)):
    cs = generate.candidates_for("sqli", {"attack_class": "sqli", "endpoints": list(endpoints), "techniques": ["sqli"],
                                          "actor": "x", "n_requests": 5})
    return next(c for c in cs if c["id"] == f"aegis-sqli-{n}")


def blocked(cand, payload):
    with tempfile.TemporaryDirectory() as td:
        rf, cf = Path(td) / "r.conf", Path(td) / "c.jsonl"
        rf.write_text(irc.compile_rule(cand, deny=True))
        cf.write_text(json.dumps({"method": "GET", "uri": "/search?q=" + urllib.parse.quote(payload),
                                  "body": "", "content_type": ""}))
        out = subprocess.run([str(REPLAY), "-rule", str(rf), "-corpus", str(cf)], capture_output=True, text=True)
        return json.loads(out.stdout.strip().splitlines()[-1])["matched"] == 1


@unittest.skipUnless(REPLAY.exists(), "bin/replay not built")
class Template3(unittest.TestCase):
    def test_premise_libinjection_misses_admin_comment(self):
        self.assertFalse(blocked(template(1), "admin'--"))

    def test_blocks_every_request_of_the_mixed_campaign(self):
        c3 = template(3)
        irc.validate(c3)
        for p in EVIDENCE:
            self.assertTrue(blocked(c3, p), p)

    def test_blocks_time_based_blind_injection_shapes(self):
        c3 = template(3)
        for p in TIME_BASED:
            self.assertTrue(blocked(c3, p), p)

    def test_does_not_match_ordinary_text(self):
        c3 = template(3)
        for p in BENIGN:
            self.assertFalse(blocked(c3, p), f"template 3 matched benign text: {p!r}")

    def test_matches_none_of_the_known_harmful_to_block_requests(self):
        with tempfile.TemporaryDirectory() as td:
            rf = Path(td) / "r.conf"
            rf.write_text(irc.compile_rule(template(3), deny=True))
            out = subprocess.run([str(REPLAY), "-rule", str(rf), "-corpus", str(ROOT / "data" / "hard_negatives.jsonl")],
                                 capture_output=True, text=True)
        self.assertEqual(json.loads(out.stdout.strip().splitlines()[-1])["matched"], 0)


class Shape(unittest.TestCase):
    def test_every_candidate_validates(self):
        for ep in ((), ("/search",), ("/rest/products/search",)):
            for c in generate.candidates_for("sqli", {"attack_class": "sqli", "endpoints": list(ep), "techniques": ["sqli"],
                                                      "actor": "x", "n_requests": 5}):
                irc.validate(c)


if __name__ == "__main__":
    unittest.main()
