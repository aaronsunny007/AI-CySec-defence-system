"""gateway/redact.go decides whether a value in a secret-named field "looks like an attack" (and so must NOT be
redacted: the observer needs the payload to see the campaign). Its signature list is a copy of
observer/detector.py SIGS. If the two drift, redaction would silently hide payloads from the detector (or keep
secrets in the log). This test fails when they differ."""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "observer"))
import detector  # noqa: E402


def go_signatures() -> dict[str, str]:
    src = (ROOT / "gateway" / "redact.go").read_text(encoding="utf-8")
    block = src[src.index("var injectionSigs"):src.index("var injectionRE")]
    out: dict[str, str] = {}
    for name, rest in re.findall(r'"(\w+)":\s*([^\n]+)', block):
        parts = re.findall(r"`([^`]*)`|\"([^\"]*)\"", rest)
        out[name] = "".join(a or b for a, b in parts)
    return out


class Parity(unittest.TestCase):
    def test_same_families(self):
        self.assertEqual(set(go_signatures()), set(detector.SIGS))

    def test_same_patterns(self):
        go = go_signatures()
        for name, rx in detector.SIGS.items():
            self.assertEqual(go[name], rx.pattern, f"{name}: gateway/redact.go differs from observer/detector.py SIGS")

    def test_same_case_insensitivity(self):
        for rx in detector.SIGS.values():
            self.assertTrue(rx.flags & re.I)
        self.assertIn("(?i)", (ROOT / "gateway" / "redact.go").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
