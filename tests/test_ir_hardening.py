"""The IR comes from a model, so it is untrusted JSON. validate()/compile_rule() must turn every malformed
or hostile input into an IRError (a rejected candidate) -- never a crash, never rule text the gateway
would refuse or misread. Each case here was found by fuzzing the compiler."""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ir"))
import compile as irc  # noqa: E402

BASE = {"id": "aegis-sqli-1", "attack_class": "sqli", "mechanism": "signature", "action": "block",
        "match": {"target": "args", "operator": "rx", "value": r"union\s+select"}}


def mut(f):
    d = copy.deepcopy(BASE)
    f(d)
    return d


class Hostile(unittest.TestCase):
    def rejected(self, ir):
        with self.assertRaises(irc.IRError):
            irc.compile_rule(ir, deny=False)

    def test_trailing_newline_in_id(self):      # `$` matched before a final newline: a 2-line rule
        self.rejected(mut(lambda d: d.update(id="aegis-sqli-1\n")))
        self.rejected(mut(lambda d: d.update(id="aegis-sqli-1\nSecRuleEngine Off")))

    def test_wrongly_typed_fields_are_rejections_not_crashes(self):
        for f in (lambda d: d["match"].update(transformations=[[]]),
                  lambda d: d["match"].update(transformations=[{}]),
                  lambda d: d["match"].update(transformations="lowercase"),
                  lambda d: d["match"].update(target=["args"]),
                  lambda d: d["match"].update(operator={}),
                  lambda d: d["match"].update(value=["x"]),
                  lambda d: d["match"].update(value=True),
                  lambda d: d.update(attack_class=[]),
                  lambda d: d.update(mechanism=[]),
                  lambda d: d.update(id=5),
                  lambda d: d.update(scope={"methods": [[]]}),
                  lambda d: d.update(scope={"methods": "GET"}),
                  lambda d: d.update(ttl_s=True),
                  lambda d: d.update(match="not an object")):
            self.rejected(mut(f))

    def test_non_dict_ir(self):
        for bad in (None, [], "x", 5):
            with self.assertRaises(irc.IRError):
                irc.validate(bad)

    def test_macro_expansion_refused(self):
        self.rejected(mut(lambda d: d["match"].update(operator="contains", value="%{REQUEST_HEADERS.Host}")))
        self.rejected(mut(lambda d: d.update(scope={"endpoint_prefix": "/a%{TX.x}"})))

    def test_unicode_line_separators_refused(self):
        self.rejected(mut(lambda d: d["match"].update(operator="contains", value="a b")))

    def test_regex_features_the_engine_lacks(self):
        for rx in ("a(?=b)", "a(?!b)", "(?<=a)b", "(?<!a)b", "(?>a)", r"(a)\1", "a*+", "a++"):
            self.rejected(mut(lambda d, rx=rx: d["match"].update(value=rx)))

    def test_regex_matching_every_request_refused(self):
        for rx in (".*", "x*", "(a|)", "^"):
            self.rejected(mut(lambda d, rx=rx: d["match"].update(value=rx)))

    def test_valid_rule_still_compiles_and_has_no_stray_lines(self):
        out = irc.compile_rule(BASE, deny=False)
        self.assertEqual(len(out.strip().splitlines()), 1)
        self.assertIn("aegis-rule:aegis-sqli-1", out)

    def test_legitimate_regexes_not_over_blocked(self):
        for rx in (r"union\s+select", r"(?i)select.+from", r"\bor\b\s+1=1", r"[a-z]{2,5}\d+", r"\+\+", r"a|b"):
            irc.validate(mut(lambda d, rx=rx: d["match"].update(value=rx)))


if __name__ == "__main__":
    unittest.main()


class IdCollisions(unittest.TestCase):
    """aegis-idor_bola-8 and aegis-idor_bola-48 hash to the same Coraza id; Coraza refuses a ruleset with a
    duplicate id, which wedged every later manifest reload (found live)."""

    A, B = "aegis-idor_bola-8", "aegis-idor_bola-48"

    def ir(self, rid, v):
        return {"id": rid, "attack_class": "other", "mechanism": "signature", "action": "block",
                "match": {"target": "args", "operator": "contains", "value": v}}

    def test_the_collision_exists(self):
        self.assertEqual(irc.numeric_id({"id": self.A}), irc.numeric_id({"id": self.B}))

    def test_rule_store_gives_colliding_rules_different_ids(self):
        import re
        import tempfile
        sys.path.insert(0, str(ROOT / "gate"))
        import rulestore
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "m.json"
            rulestore.upsert(self.ir(self.A, "aaa"), "shadow", path=p)
            rulestore.upsert(self.ir(self.B, "bbb"), "shadow", path=p)
            rules = rulestore.load(p)["rules"]
            ids = [re.search(r"\bid:(\d+)", r["secrule"]).group(1) for r in rules]
            self.assertEqual(len(rules), 2)
            self.assertEqual(len(set(ids)), 2, ids)
            # re-upserting the SAME rule keeps its own slot (it is not 'taken' by itself)
            rulestore.upsert(self.ir(self.A, "aaa"), "enforce", path=p)
            again = {r["id"]: re.search(r"\bid:(\d+)", r["secrule"]).group(1) for r in rulestore.load(p)["rules"]}
            self.assertEqual(again[self.A], ids[0])

    def test_numeric_override_is_range_checked(self):
        with self.assertRaises(irc.IRError):
            irc.compile_rule(self.ir(self.A, "x"), deny=False, numeric=942100)
