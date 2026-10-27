"""Credential attempts are recognised in JSON and in HTML-form bodies (DVWA logs in with a form)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("observer", "controller"):
    sys.path.insert(0, str(ROOT / p))
import detector as D   # noqa: E402


class R:
    def __init__(self, method, body, query=""):
        self.method, self.body, self.query = method, body, query


class FormBodies(unittest.TestCase):
    def test_json_and_form_logins(self):
        self.assertTrue(D.is_login_attempt(R("POST", '{"email":"a@b.c","password":"x"}')))
        self.assertTrue(D.is_login_attempt(R("POST", "username=admin&password=password&Login=Login&user_token=ab")))

    def test_non_logins(self):
        self.assertFalse(D.is_login_attempt(R("GET", "username=admin&password=x")))
        self.assertFalse(D.is_login_attempt(R("POST", "password=only")))
        self.assertFalse(D.is_login_attempt(R("POST", "free text with password in it")))
        self.assertFalse(D.is_login_attempt(R("POST", "q=" + "a" * 5000 + "&password=x&user=u")))

    def test_account_extraction_matches_gateway(self):
        import loop
        self.assertEqual(loop.account_of("username=Admin&password=x"), "admin")
        self.assertEqual(loop.account_of('{"email":" Jim@X.op "}'), "jim@x.op")
        self.assertEqual(loop.account_of("nonsense"), "")


if __name__ == "__main__":
    unittest.main()


class FormMutants(unittest.TestCase):
    def test_form_body_mutants_keep_the_form_structure(self):
        sys.path.insert(0, str(ROOT / "range" / "mutate"))
        import mutate as mut
        rec = {"method": "POST", "uri": "/vulnerabilities/exec/", "body": "ip=1.1.1.1+%26+whoami&Submit=Submit"}
        ms = mut.mutate_request(rec)
        self.assertTrue(ms)
        for m in ms:
            # the parameter names and the separator survive; only values are rewritten
            self.assertIn("ip=", m["body"])
            self.assertIn("&Submit=", m["body"])
            self.assertNotIn("%253D", m["body"])
