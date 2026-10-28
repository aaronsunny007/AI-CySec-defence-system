"""Benign traffic for DVWA (the third target): users who log in with the HTML form and use the pages,
including weird-but-legitimate input (apostrophes, SQL words in text, HTML, unicode, '--', '%', long
strings). stdlib only (http.client, manual cookies).

    python range/dvwa/benign.py --requests 30000 --threads 6 [--seed 1]
    python range/dvwa/benign.py --duration 600 --threads 4      # background load for an experiment

A simulated user = one visitor id (cookie aegis_vid=benign-b3-N) and a PHP session; sessions are short
and touch few ids so they do not look like enumeration. Local range only, through the gateway on :8080.
Note: DVWA runs under php's single-threaded built-in server, so this generator is deliberately modest.
"""

from __future__ import annotations

import argparse
import http.client
import random
import re
import threading
import time
import urllib.parse

HOST, PORT = "127.0.0.1", 8080          # NOT "localhost": ~2 s per new connection on Windows
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
       "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
       "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"]
USERS = [("admin", "password"), ("gordonb", "abc123"), ("1337", "charley"), ("pablo", "letmein"),
         ("smithy", "password")]
NAMES = ["Alice", "O'Brien", "Bobby Tables", "Zoë", "Ünal", "日本語", "María-José", "D'Angelo", "Mr. X",
         "select", "a--b", "100%", "<b>me</b>", "x" * 90, "it's", "union station", "drop", "or else"]
MESSAGES = ["Hello!", "It's great -- really", "O'Brien's note; thanks", "DROP the beat", "<i>nice</i> page",
            "Très bien, 100% sure", "日本語のメッセージ", "'quoted' and \"double\"", "a" * 250,
            "select a seat; any seat", "1=1 is true in math", "wait -- what?"]
HOSTS = ["256.256.256.256", "999.1.1.1", "300.1.2.3"]   # mistyped IPs: ping fails at once (an unresolvable NAME stalls the single-threaded server for 2+ s)


class Conn:
    """One user's HTTP state: persistent connection + cookie dict."""

    def __init__(self, vid: str, ua: str):
        self.vid, self.ua = vid, ua
        self.cookies: dict[str, str] = {}

    def _cookie(self) -> str:
        return "; ".join([f"aegis_vid={self.vid}"] + [f"{k}={v}" for k, v in self.cookies.items()])

    def call(self, method: str, path: str, form: dict | None = None) -> tuple[int, str]:
        body = urllib.parse.urlencode(form).encode() if form is not None else None
        hdrs = {"User-Agent": self.ua, "Cookie": self._cookie(), "Host": "localhost:8080"}
        if body is not None:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            c = http.client.HTTPConnection(HOST, PORT, timeout=20)
            c.request(method, path, body=body, headers=hdrs)
            r = c.getresponse()
            data = r.read(65536).decode("utf-8", "replace")
            for k, v in r.getheaders():
                if k.lower() == "set-cookie":
                    nv = v.split(";", 1)[0]
                    if "=" in nv:
                        name, val = nv.split("=", 1)
                        self.cookies[name.strip()] = val.strip()
            loc = r.getheader("Location")
            status = r.status
            c.close()
            if status in (301, 302, 303) and loc and method != "HEAD":
                p = urllib.parse.urlparse(urllib.parse.urljoin(path, loc))
                return self.call("GET", (p.path or "/") + (("?" + p.query) if p.query else ""))
            return status, data
        except Exception:        # a dropped connection / malformed reply is data, never a dead worker
            return 0, ""


def token(html: str) -> str:
    m = re.search(r"name=['\"]user_token['\"] value=['\"]([0-9a-f]+)['\"]", html)
    return m.group(1) if m else ""


def login(c: Conn, user: str, pw: str) -> bool:
    st, html = c.call("GET", "/login.php")
    st, html = c.call("POST", "/login.php", {"username": user, "password": pw, "Login": "Login",
                                              "user_token": token(html)})
    return "Logout" in html


def session(rng: random.Random, vid: str) -> int:
    c = Conn(vid, rng.choice(UAS))
    n = 2
    u, p = rng.choice(USERS)
    if rng.random() < 0.2:                       # a typo first, sometimes
        login(c, u, p + "x")
        n += 2
    if not login(c, u, p):
        return n
    n += 2
    for _ in range(rng.randint(2, 6)):
        r = rng.random()
        if r < 0.20:
            c.call("GET", f"/vulnerabilities/sqli/?id={rng.randint(1, 5)}&Submit=Submit")
        elif r < 0.40:
            c.call("GET", "/vulnerabilities/xss_r/?name=" + urllib.parse.quote(rng.choice(NAMES)))
        elif r < 0.55:
            c.call("POST", "/vulnerabilities/xss_s/", {"txtName": rng.choice(NAMES)[:10],
                                                       "mtxMessage": rng.choice(MESSAGES), "btnSign": "Sign Guestbook"})
        elif r < 0.65:
            c.call("POST", "/vulnerabilities/exec/", {"ip": rng.choice(HOSTS), "Submit": "Submit"})
        elif r < 0.75:
            c.call("GET", "/vulnerabilities/brute/?username=" + urllib.parse.quote(u) + "&password="
                   + urllib.parse.quote(rng.choice(["password", "abc123", "it's-mine", "p@ss|word#1"])) + "&Login=Login")
        else:
            c.call("GET", rng.choice(["/index.php", "/instructions.php", "/about.php", "/security.php",
                                      "/vulnerabilities/sqli/", "/vulnerabilities/xss_r/"]))
        n += 1
    return n


def run(requests: int, duration: float, threads: int, seed: int, stop: threading.Event | None = None):
    counter = [0]
    lock = threading.Lock()
    t_end = time.time() + duration if duration else None

    def worker(w):
        rng = random.Random(seed * 1000 + w)
        i = 0
        while not (stop and stop.is_set()):
            if requests and counter[0] >= requests:
                return
            if t_end and time.time() > t_end:
                return
            i += 1
            n = session(rng, f"benign-b3-{w}-{i}")
            with lock:
                counter[0] += n
            time.sleep(rng.random() * 0.2)
    ths = [threading.Thread(target=worker, args=(w,), daemon=True) for w in range(threads)]
    for t in ths:
        t.start()
    return ths, counter


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--requests", type=int, default=0)
    ap.add_argument("--duration", type=float, default=0, help="seconds")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    if not a.requests and not a.duration:
        ap.error("give --requests and/or --duration")
    ths, counter = run(a.requests, a.duration, a.threads, a.seed)
    for t in ths:
        t.join()
    print(f"sent ~{counter[0]} requests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
