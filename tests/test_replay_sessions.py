"""The live replay driver replays whole real visitors, not random requests under pseudo-users."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))
import traffic  # noqa: E402


def rec(sess, uri, ts):
    return {"session": sess, "uri": uri, "method": "GET", "ts": ts, "user_agent": "Mozilla/5.0"}


class Sessions(unittest.TestCase):
    def corpus(self, rows):
        f = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8")
        f.write("\n".join(json.dumps(r) for r in rows))
        f.close()
        return Path(f.name)

    def test_groups_by_session_in_time_order_and_drops_tiny_visitors(self):
        p = self.corpus([rec("a", "/2", "2026-01-01T00:00:02Z"), rec("b", "/x", "2026-01-01T00:00:00Z"),
                         rec("a", "/1", "2026-01-01T00:00:01Z"), rec("a", "/3", "2026-01-01T00:00:03Z"),
                         rec("b", "/y", "2026-01-01T00:00:01Z")])
        v = traffic.load_sessions(p)
        self.assertEqual([[q["uri"] for q in s] for s in v], [["/1", "/2", "/3"]])   # b has 2 requests: dropped

    def test_corpus_without_sessions_falls_back_to_random_mode(self):
        p = self.corpus([{"uri": "/a", "method": "GET", "user_agent": "x"}] * 5)
        self.assertIsNone(traffic.load_sessions(p))

    def test_skips_attack_tools_and_socketio(self):
        p = self.corpus([rec("a", "/1", "1"), rec("a", "/socket.io/?x", "2"), rec("a", "/2", "3"),
                         dict(rec("a", "/3", "4"), user_agent="sqlmap/1.0"), rec("a", "/4", "5")])
        self.assertEqual([[q["uri"] for q in s] for s in traffic.load_sessions(p)], [["/1", "/2", "/4"]])


if __name__ == "__main__":
    unittest.main()
