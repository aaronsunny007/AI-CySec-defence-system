"""The injection signatures must not fire on ordinary text and random passwords, and must still fire on the
attack payloads. Both lists come from the false-trigger investigation (docs/FALSE-TRIGGERS-2026-11-09.md):
random passwords like "B'#67..." and prose like "$(10) off" or `code` flagged ~1 in 80 benign visitors."""

import json
import sys
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "observer"))
import detector  # noqa: E402

BENIGN = {
    "cmdi": ["$(10) off", "I use `code` blocks", "PQ`Vw16Owf6gRt3njS`=+", "price $(approx) later", "a && b", "a || b",
             "T}4-`L=,\"*4[`!t7)"],
    "sqli": ["B'#67\\&M6%jS", "C0N@+=^|MbLW8ARc)#R", "l#*7ed:Gm1H)#e6t&n", "foo--bar", "late -- but worth it",
             "'quoted' and \"double\"", "the 'best' and the worst", "dogs' or cats' bowls"],
}
ATTACK = {
    "cmdi": ["| whoami", "$(sleep 3)", "`id`", "&& ping -c 1 127.0.0.1", "$( whoami)", "$(/bin/id)", "`uname -a`"],
    "sqli": ["admin'--", "' OR 1=1--", "') OR ('1'='1'--", "x'#", "%27--", "' or 1=1 -- ", "') OR ('1'='1",
             "' or sleep(5)#", "' and 1=2 union select 1", "%27%20or%201=1", "' or true--", "' or \"1\"=\"1"],
}


def hits(fam: str, s: str) -> bool:
    return bool(detector.SIGS[fam].search(urllib.parse.unquote_plus(s)))


class Precision(unittest.TestCase):
    def test_benign_text_and_passwords_do_not_match(self):
        for fam, items in BENIGN.items():
            for s in items:
                self.assertFalse(hits(fam, s), f"{fam} matched benign {s!r}")

    def test_attack_shapes_still_match(self):
        for fam, items in ATTACK.items():
            for s in items:
                self.assertTrue(hits(fam, s), f"{fam} missed {s!r}")

    def test_corpus_payloads_in_touched_families_still_match(self):
        p = json.loads((ROOT / "data" / "attack_corpus" / "payloads.json").read_text(encoding="utf-8"))
        for key, fam in (("sqli_login", "sqli"), ("sqli_union", "sqli")):
            for s in p[key]:      # every one, including the parenthesised `') OR ('1'='1`
                self.assertTrue(hits(fam, s), f"{key}: {s!r}")
        for s in p["cmdi"][:5]:      # the sixth is an SQL DROP payload, not a shell one
            self.assertTrue(hits("cmdi", s), f"cmdi: {s!r}")


if __name__ == "__main__":
    unittest.main()
