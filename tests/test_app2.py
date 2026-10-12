"""BookNook (second target app): it is vulnerable in the intended ways and ONLY those."""

import json
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORT = 3987


def call(method, path, body=None):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


class App2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = subprocess.Popen([sys.executable, str(ROOT / "range" / "app2" / "server.py"), "--port", str(PORT)])
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=1)
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("app2 did not start")

    @classmethod
    def tearDownClass(cls):
        cls.p.terminate()
        cls.p.wait(timeout=5)

    def test_normal_use(self):
        self.assertEqual(call("GET", "/api/books?q=Dune")[1]["books"][0]["title"], "Dune")
        self.assertEqual(call("POST", "/api/login", {"email": "jim@booknook.test", "password": "ncc-1701"})[0], 200)
        self.assertEqual(call("POST", "/api/login", {"email": "jim@booknook.test", "password": "nope"})[0], 401)

    def test_weird_but_legit_input_is_fine(self):
        q = urllib.parse.quote("O''Brien")   # an apostrophe typed by a user, escaped by the client
        self.assertEqual(call("GET", "/api/books?q=" + q)[0], 200)

    def test_sqli_works_as_intended(self):
        self.assertEqual(call("POST", "/api/login", {"email": "' OR 1=1--", "password": "x"})[0], 200)
        u = urllib.parse.quote("zzz' UNION SELECT id,email,password,0 FROM users--")
        got = call("GET", "/api/books?q=" + u)[1]["books"]
        self.assertTrue(any(b["author"] == "admin123" for b in got))

    def test_idor_works_as_intended(self):
        self.assertEqual(call("GET", "/api/orders/7")[0], 200)

    def test_command_sink_is_simulated_never_executed(self):
        out = call("GET", "/api/diagnostics?host=" + urllib.parse.quote("x; id"))[1]["output"]
        self.assertIn("uid=1000", out)                    # canned text
        marker = ROOT / "logs" / "app2_exec_marker"
        marker.unlink(missing_ok=True)
        call("GET", "/api/diagnostics?host=" + urllib.parse.quote(f"x; echo hi > {marker}"))
        self.assertFalse(marker.exists())                  # nothing was run

    def test_no_file_or_network_primitives_in_the_source(self):
        src = (ROOT / "range" / "app2" / "server.py").read_text(encoding="utf-8")
        for bad in ("subprocess", "os.system", "os.popen", "open(", "socket", "urlopen", "eval(", "exec("):
            code = [l for l in src.splitlines() if not l.strip().startswith(("#", '"'))]
            self.assertFalse(any(bad in l for l in code if "no subprocesses" not in l and "never executed" not in l),
                             bad)


if __name__ == "__main__":
    unittest.main()
