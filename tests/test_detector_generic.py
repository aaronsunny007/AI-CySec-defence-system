"""The detector must not be tied to Juice Shop's URLs (found by pointing it at a second app)."""

import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "observer"))
sys.path.insert(0, str(ROOT / "deliberator"))
from actors import Actor, to_request     # noqa: E402
from detector import detect, is_login_attempt   # noqa: E402
import generate                           # noqa: E402

T0 = datetime(2026, 10, 12, 9, 0, 0, tzinfo=timezone.utc)


def login(i, path, body):
    return to_request({"ts": (T0 + timedelta(seconds=i)).isoformat().replace("+00:00", "Z"),
                       "method": "POST", "uri": path, "body": json.dumps(body), "status": 401,
                       "session": "s"})


class Generic(unittest.TestCase):
    def test_stuffing_is_detected_on_any_login_path(self):
        for path in ("/rest/user/login", "/api/login", "/auth/signin", "/v2/sessions"):
            a = Actor(key="s", requests=[login(i, path, {"email": f"u{i}@x.test", "password": "pw"})
                                          for i in range(8)])
            self.assertIn("credential_stuffing", {f.technique for f in detect(a)}, path)

    def test_login_attempt_needs_a_password_and_an_identifier(self):
        self.assertTrue(is_login_attempt(login(0, "/x", {"username": "a", "password": "b"})))
        self.assertFalse(is_login_attempt(login(0, "/x", {"comment": "my password is hidden"})))
        self.assertFalse(is_login_attempt(login(0, "/x", {"password": "b"})))
        self.assertFalse(is_login_attempt(login(0, "/x", {"email": "a", "password": 5})))

    def test_rate_candidates_are_scoped_to_the_endpoint_the_campaign_hit(self):
        c = generate.candidates_for("credential_stuffing", {"endpoints": ["/", "/api/login"]})
        self.assertTrue(c and all(x["scope"]["endpoint_prefix"] == "/api/login" for x in c))
        self.assertTrue(any(x.get("key") == "account" for x in c))


if __name__ == "__main__":
    unittest.main()
