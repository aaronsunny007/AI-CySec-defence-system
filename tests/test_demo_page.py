"""The demo page reads every number out of the recording, so the text cannot disagree with the video."""

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demo"))
import build_page  # noqa: E402

CAST = ROOT / "demo" / "aegis-demo.cast"


@unittest.skipUnless(CAST.exists(), "no recording committed")
class Page(unittest.TestCase):
    def test_facts_come_from_the_recording(self):
        f = build_page.facts(CAST.read_text(encoding="utf-8").splitlines())
        self.assertEqual(f["guesses"], f["reached"] + f["stopped"])
        self.assertGreater(f["enforce_s"], 0)
        self.assertEqual(f["user_login"], 200)
        self.assertEqual(f["benign_blocked"], 0)
        self.assertLess(f["t_attack"], f["t_detect"] + 1)
        self.assertLess(f["t_detect"], f["t_enforced"])
        self.assertLess(f["t_enforced"], f["t_result"])

    def test_page_states_those_numbers_and_keeps_the_caveats(self):
        f = build_page.facts(CAST.read_text(encoding="utf-8").splitlines())
        page = build_page.build(CAST, standalone=True)
        text = re.sub(r"<script.*?</script>|<style.*?</style>", "", page, flags=re.S)
        for needle in (str(f["guesses"]), str(f["reached"]), str(f["stopped"]), f"{f['benign_sent']:,}", f"{f['enforce_s']} s"):
            self.assertIn(needle, text)
        self.assertIn("shortened", text)                         # the gate windows caveat must stay on the page
        self.assertIn("Read this before you believe it", text)

    def test_recording_is_embedded_and_valid_ndjson(self):
        page = build_page.build(CAST, standalone=False)
        body = re.search(r'<script type="application/json" id="cast">\n(.*?)\n</script>', page, re.S).group(1)
        rows = [json.loads(l) for l in body.splitlines()]
        self.assertEqual(rows[0]["version"], 2)
        self.assertTrue(all(r[1] == "o" for r in rows[1:]))
        self.assertNotIn("</script", body.lower())               # would end the embedding early

    def test_a_recording_missing_a_marker_fails_loudly(self):
        lines = CAST.read_text(encoding="utf-8").splitlines()
        broken = [l for l in lines if "ENFORCED" not in l]
        with self.assertRaises(SystemExit):
            build_page.facts(broken)

    def test_no_machine_paths_or_secrets_in_the_recording(self):
        raw = CAST.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"/(home|root|tmp|Users)/\S+", raw))
        self.assertIsNone(re.search(r"[0-9a-f]{40,}", raw))


if __name__ == "__main__":
    unittest.main()
