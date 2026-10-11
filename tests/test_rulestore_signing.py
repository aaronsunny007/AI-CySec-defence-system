"""Rule-store hardening, Python side: signed manifest + admin token (see gateway/sign.go)."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gate"))
import rulestore  # noqa: E402

KEY = "test-key-not-a-secret"
M = {"version": 5, "rules": [{"id": "r1", "type": "rate", "mode": "enforce"}]}


class Signing(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.p = Path(self.d.name) / "m.json"

    def tearDown(self):
        self.d.cleanup()

    def test_vector_matches_go(self):
        self.assertEqual(rulestore.sign(KEY.encode(), "abc"),
                         "51803ef0fd04de1cc4ee6975038f77e24a053eac7c93830ad6730f5930a98628")

    def test_round_trip_and_envelope_shape(self):
        with mock.patch.dict(os.environ, {"AEGIS_MANIFEST_KEY": KEY}):
            rulestore.save(M, self.p)
            raw = json.loads(self.p.read_text())
            self.assertEqual(set(raw), {"payload", "sig"})
            self.assertEqual(rulestore.load(self.p), M)

    def test_tampered_payload_or_unsigned_file_is_refused(self):
        with mock.patch.dict(os.environ, {"AEGIS_MANIFEST_KEY": KEY}):
            rulestore.save(M, self.p)
            env = json.loads(self.p.read_text())
            env["payload"] = env["payload"].replace("enforce", "off")
            self.p.write_text(json.dumps(env))
            with self.assertRaises(ValueError):
                rulestore.load(self.p)
            self.p.write_text(json.dumps(M))             # plain, unsigned
            with self.assertRaises(ValueError):
                rulestore.load(self.p)

    def test_unsigned_mode_is_unchanged(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AEGIS_MANIFEST_KEY", None)
            os.environ.pop("AEGIS_MANIFEST_KEY_FILE", None)
            rulestore.save(M, self.p)
            self.assertEqual(json.loads(self.p.read_text()), M)
            self.assertEqual(rulestore.load(self.p), M)

    def test_key_can_come_from_a_file(self):
        kf = Path(self.d.name) / "k"
        kf.write_text(KEY + "\n")
        env = {"AEGIS_MANIFEST_KEY_FILE": str(kf)}
        with mock.patch.dict(os.environ, env):
            os.environ.pop("AEGIS_MANIFEST_KEY", None)
            rulestore.save(M, self.p)
            self.assertIn("sig", json.loads(self.p.read_text()))

    def test_admin_token_is_sent_on_mutations_only(self):
        seen = {}

        class R:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def read(self): return b"{}"

        def fake_open(req, timeout=0):
            seen[req.method] = req.get_header("Authorization")
            return R()
        with mock.patch.dict(os.environ, {"AEGIS_ADMIN_TOKEN": "tok"}), \
                mock.patch.object(rulestore.urllib.request, "urlopen", fake_open):
            rulestore.stats()
            rulestore.set_mode("r1", "off")
        self.assertIsNone(seen["GET"])
        self.assertEqual(seen["POST"], "Bearer tok")

    def test_no_secret_is_ever_in_source_or_repo_defaults(self):
        src = (ROOT / "gate" / "rulestore.py").read_text(encoding="utf-8")
        self.assertNotIn(KEY, src)


if __name__ == "__main__":
    unittest.main()
