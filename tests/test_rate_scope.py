"""Rate-limit candidates must be scoped to the endpoint the campaign hit, for every rate class. IDOR and
enumeration used to be hard-coded to Juice Shop's paths, so on another app no rule could ever block the attacker."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ir"))
sys.path.insert(0, str(ROOT / "deliberator"))
import compile as irc   # noqa: E402
import generate         # noqa: E402


def scopes(cls, endpoints):
    cs = [c for c in generate.candidates_for(cls, {"attack_class": cls, "endpoints": endpoints, "techniques": [cls],
                                                   "actor": "x", "n_requests": 9}) if c["mechanism"] == "rate_limit"]
    for c in cs:
        irc.validate(c)
    return {c["scope"]["endpoint_prefix"] for c in cs}, cs


class Scope(unittest.TestCase):
    def test_idor_follows_the_observed_endpoint_on_another_app(self):
        self.assertEqual(scopes("idor_bola", ["/api/orders/{id}"])[0], {"/api/orders"})

    def test_enumeration_follows_the_observed_endpoint_on_another_app(self):
        self.assertEqual(scopes("user_enumeration", ["/api/users/lookup"])[0], {"/api/users/lookup"})

    def test_credential_stuffing_unchanged(self):
        self.assertEqual(scopes("credential_stuffing", ["/api/login"])[0], {"/api/login"})

    def test_juice_shop_scopes_are_what_the_lab_measured(self):
        # the research results were produced with these; the generalisation must not move them
        self.assertEqual(scopes("idor_bola", ["/rest/basket/{id}"])[0], {"/rest/basket"})
        self.assertEqual(scopes("user_enumeration", ["/rest/user/security-question"])[0], {"/rest/user/security-question"})
        self.assertEqual(scopes("credential_stuffing", ["/rest/user/login"])[0], {"/rest/user/login"})

    def test_falls_back_to_the_old_defaults_when_no_endpoint_is_usable(self):
        for eps in ([], ["/"], [""], ["/socket.io/x"]):
            self.assertEqual(scopes("idor_bola", eps)[0], {"/rest/basket"})
            self.assertEqual(scopes("user_enumeration", eps)[0], {"/rest/user/security-question"})
            self.assertEqual(scopes("credential_stuffing", eps)[0], {"/rest/user/login"})

    def test_methods_and_counts_are_untouched(self):
        _, cs = scopes("idor_bola", ["/api/orders/{id}"])
        self.assertTrue(all(c["scope"]["methods"] == ["GET"] for c in cs))
        self.assertEqual(sorted({c["rate"]["count"] for c in cs}), [8, 15])


if __name__ == "__main__":
    unittest.main()
