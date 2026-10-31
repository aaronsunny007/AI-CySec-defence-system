"""Safety properties of the `aegis` command line: secrets are private from the first byte, `stop` never
kills a process that is not ours (a stale/edited pid file), the config is validated, and a corpus built
from learned traffic is private and honest about attack-like content."""

import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import aegis  # noqa: E402

POSIX = os.name != "nt"


class Secrets(unittest.TestCase):
    @unittest.skipUnless(POSIX, "POSIX permissions")
    def test_secret_files_are_0600_and_dir_0700(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(aegis, "STATE", Path(d) / ".aegis"):
            env = aegis.ensure_secrets()
            self.assertEqual(len(env), 2)
            for f in env.values():
                self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o600)
                self.assertGreaterEqual(len(Path(f).read_text()), 64)
            self.assertEqual(stat.S_IMODE(os.stat(Path(d) / ".aegis").st_mode), 0o700)
            first = {k: Path(v).read_text() for k, v in env.items()}
            aegis.ensure_secrets()                      # idempotent: never rotates a key under a running gateway
            self.assertEqual(first, {k: Path(v).read_text() for k, v in env.items()})


@unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "darwin", "ps//proc")
class PidSafety(unittest.TestCase):
    def test_unrelated_process_is_not_ours_and_survives_stop(self):
        victim = subprocess.Popen(["sleep", "60"])
        try:
            with tempfile.TemporaryDirectory() as d, mock.patch.object(aegis, "PIDS", Path(d) / "aegis.pids"):
                aegis.PIDS.write_text(json.dumps({"gateway": victim.pid, "controller": victim.pid, "mode": "protect"}))
                self.assertIsNone(aegis.owned(aegis.read_pids(), "gateway"))
                self.assertIsNone(aegis.owned(aegis.read_pids(), "controller"))
                aegis._stop_all()
                time.sleep(0.3)
                self.assertIsNone(victim.poll(), "`aegis stop` killed a process it does not own")
                self.assertFalse(aegis.PIDS.exists())
        finally:
            victim.kill()

    def test_a_process_that_looks_like_ours_is_recognised(self):
        fake = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", "gateway"])   # argv contains the marker
        try:
            self.assertEqual(aegis.owned({"gateway": fake.pid}, "gateway"), fake.pid)
        finally:
            fake.kill()

    def test_dead_or_missing_pid(self):
        self.assertIsNone(aegis.owned({}, "gateway"))
        self.assertIsNone(aegis.owned({"gateway": 2 ** 22 + 12345}, "gateway"))


class Config(unittest.TestCase):
    def ok(self, **kw):
        return aegis.validate_config({**aegis.DEFAULTS, **kw})

    def test_good_defaults(self):
        self.assertIsNone(self.ok())

    def test_bad_values_are_named(self):
        for kw in ({"target": "ftp://x"}, {"target": "localhost:3000"}, {"target": "http://"}, {"target": ""},
                   {"listen": "8080"}, {"listen": "127.0.0.1:99999"}, {"listen": "127.0.0.1:abc"},
                   {"llm": "openai"}, {"target": "http://127.0.0.1:8080", "listen": "127.0.0.1:8080"}):
            self.assertTrue(self.ok(**kw), kw)


class Windows(unittest.TestCase):
    def ok(self, **kw):
        return aegis.validate_config({**aegis.DEFAULTS, **kw})

    def test_defaults_are_the_documented_ones(self):
        self.assertEqual((aegis.DEFAULTS["shadow_s"], aegis.DEFAULTS["canary_s"]), (30.0, 45.0))

    def test_short_but_sane_windows_are_allowed_and_silly_ones_are_not(self):
        self.assertIsNone(self.ok(shadow_s=8, canary_s=12))
        for bad in (0, 1, 4.9, -5, "soon", None):
            self.assertTrue(self.ok(shadow_s=bad), bad)
            self.assertTrue(self.ok(canary_s=bad), bad)


class Events(unittest.TestCase):
    def test_every_event_the_controller_emits_reads_as_a_sentence(self):
        t = 1793415314.5
        samples = [
            {"t": t, "event": "controller_start", "ext_benign_actors": 30},
            {"t": t, "event": "campaign_detected", "actor": "h:428e0be929d76de8", "technique": "sqli", "n_requests": 3, "ttd_s": 0.4},
            {"t": t, "event": "mitigation", "technique": "sqli", "source": "fresh", "rule": "aegis-sqli-3", "ttm_s": 0.26},
            {"t": t, "event": "mitigation", "technique": "sqli", "source": "none", "rule": None, "ttm_s": 0.5},
            {"t": t, "event": "candidate", "id": "aegis-credential_stuffing-1", "ok": False, "rejected_at": "benign_accounts"},
            {"t": t, "event": "live_start", "rule": "aegis-sqli-3", "shadow_s": 30.0, "canary_s": 45.0, "canary_pct": 25},
            {"t": t, "event": "live_stage", "rule": "r", "stage": "shadow", "passed": True, "detail": "1838 live requests; suspected FPs 0/1759"},
            {"t": t, "event": "enforced", "rule": "aegis-sqli-3"},
            {"t": t, "event": "rejected_live", "rule": "aegis-sqli-3"},
            {"t": t, "event": "rule_bypassed", "rule": "aegis-sqli-3", "leaked": 4, "of": 9},
            {"t": t, "event": "cooldown_skip", "technique": "sqli"},
            {"t": t, "event": "identity_rotation_detected", "identities": 3},
            {"t": t, "event": "error", "where": "handle", "error": "boom"},
            {"t": t, "event": "controller_stop"},
        ]
        for e in samples:
            line = aegis.format_event(e)
            self.assertTrue(line and len(line) < 220, e)
            self.assertNotIn("{", line, "raw JSON leaked into the readable stream")
        self.assertIn("ENFORCED", aegis.format_event(samples[7]))
        self.assertIn("REJECTED at benign_accounts", aegis.format_event(samples[4]))
        self.assertIn("none found", aegis.format_event(samples[3]))

    def test_unknown_events_are_skipped_not_crashed_on(self):
        self.assertIsNone(aegis.format_event({"t": 1.0, "event": "something_new"}))
        self.assertIsNone(aegis.format_event({}))

    def test_events_command_reads_the_file_and_tolerates_junk(self):
        import io
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "events.jsonl"
            f.write_text('{"t": 1, "event": "enforced", "rule": "aegis-x-1"}\nnot json\n{"t": 2, "event": "who_knows"}\n')
            buf = io.StringIO()
            with mock.patch.object(aegis, "EVENTS", f), redirect_stdout(buf):
                aegis.cmd_events(type("A", (), {"follow": False})())
            self.assertEqual(len(buf.getvalue().strip().splitlines()), 1)
            self.assertIn("aegis-x-1", buf.getvalue())


class Corpus(unittest.TestCase):
    def test_corpus_is_private_drops_attackers_and_counts_attack_like_requests(self):
        def rec(i, sess, uri, body=""):
            return {"ts": f"2026-10-30T10:00:{i % 60:02d}Z", "method": "GET", "uri": uri, "body": body,
                    "status": 200, "session": sess, "user_agent": "Mozilla/5.0", "client_ip": "10.0.0.1"}
        pages = ["home", "products", "cart", "about", "help"]
        lines = [rec(i, f"h:user{u}", f"/{pages[i]}") for u in range(25) for i in range(5)]
        lines += [rec(i, "h:atk", "/search?q=" + q) for i, q in enumerate(
            ["'%20OR%201=1--", "'%20UNION%20SELECT%20a%20FROM%20b--", "1;%20DROP%20TABLE%20x--", "'%20AND%20SLEEP(5)--"])]
        lines += [rec(30, "h:oddball", "/search?q=O'Brien%27%20or%20x")]      # one attack-like request, one visit
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            log = d / "gateway" / "requests.jsonl"
            log.parent.mkdir()
            log.write_text("\n".join(json.dumps(r) for r in lines) + "\n")
            with mock.patch.object(aegis, "REQ_LOG", log), mock.patch.object(aegis, "CORPUS", d / "learned" / "corpus.jsonl"):
                n, actors, attack_like = aegis.build_corpus()
                body = (d / "learned" / "corpus.jsonl").read_text()
                self.assertNotIn("h:atk", body, "the flagged attacker must not become 'normal'")
                self.assertIn("h:user3", body)
                self.assertEqual(actors, 26)                       # 25 users + the oddball
                self.assertEqual(n, 25 * 5 + 1)
                self.assertGreaterEqual(attack_like, 1)
                if POSIX:
                    self.assertEqual(stat.S_IMODE(os.stat(d / "learned" / "corpus.jsonl").st_mode), 0o600)

    def test_rotated_log_is_included(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            log = d / "requests.jsonl"
            mk = lambda s, i: json.dumps({"ts": f"2026-10-30T10:00:{i:02d}Z", "method": "GET", "uri": f"/page-{'abcde'[i]}", "body": "",
                                          "status": 200, "session": s, "user_agent": "x", "client_ip": "1.1.1.1"})
            Path(str(log) + ".1").write_text("\n".join(mk("h:old", i) for i in range(5)) + "\n")
            log.write_text("\n".join(mk("h:new", i) for i in range(5)) + "\n")
            with mock.patch.object(aegis, "REQ_LOG", log), mock.patch.object(aegis, "CORPUS", d / "c.jsonl"):
                n, actors, _ = aegis.build_corpus()
                self.assertEqual((n, actors), (10, 2))


if __name__ == "__main__":
    unittest.main()
