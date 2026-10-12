"""Regression: the SQLi template must not block the real user's password, and must still
block the attack payloads. Needs bin/replay.exe (the real Coraza engine); skipped without it."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("ir", "deliberator", "gate"):
    sys.path.insert(0, str(ROOT / p))
import compile as irc        # noqa: E402
import generate as g         # noqa: E402
import gate as gate_mod      # noqa: E402

REPLAY = ROOT / "bin" / "replay.exe"
PAYLOADS = json.loads((ROOT / "data" / "attack_corpus" / "payloads.json").read_text(encoding="utf-8"))


def matched(rule_ir, records):
    with tempfile.TemporaryDirectory() as td:
        rf, cf = Path(td) / "r.conf", Path(td) / "c.jsonl"
        rf.write_text(irc.compile_rule(rule_ir), encoding="utf-8")
        cf.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
        out = subprocess.run([str(REPLAY), "-rule", str(rf), "-corpus", str(cf)],
                             capture_output=True, text=True, check=True)
    return json.loads(out.stdout.strip().splitlines()[-1])["matched"]


@unittest.skipUnless(REPLAY.exists(), "bin/replay.exe not built")
class SqliTemplate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rule = next(c for c in g.candidates_for("sqli", {"endpoints": ["/rest/user/login"]})
                        if c["id"] == "aegis-sqli-3")

    def test_hard_negatives_file_is_not_blocked(self):
        recs = [json.loads(l) for l in (ROOT / "data" / "hard_negatives.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        self.assertGreaterEqual(len(recs), 2)
        self.assertEqual(matched(self.rule, recs), 0)

    def test_attack_payloads_still_blocked(self):
        recs = [{"method": "POST", "uri": "/rest/user/login", "content_type": "application/json",
                 "body": json.dumps({"email": p, "password": "x"})} for p in PAYLOADS["sqli_login"]]
        recs += [{"method": "GET", "uri": "/rest/products/search?q=" + p} for p in PAYLOADS["sqli_union"]]
        self.assertEqual(matched(self.rule, recs), len(recs))

    def test_gate_has_a_hard_negative_stage(self):
        self.assertTrue(gate_mod.HARD_NEGATIVES.exists())


if __name__ == "__main__":
    unittest.main()
