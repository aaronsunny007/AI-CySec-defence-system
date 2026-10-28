"""Benign traffic for BookNook: realistic-ish users, including weird-but-legitimate input
(apostrophes, SQL keywords in text, HTML, unicode, '--', '%', long strings). stdlib only.

    python range/app2/benign.py --requests 30000 --threads 8 [--seed 1]
    python range/app2/benign.py --duration 600 --threads 4      # background load for an experiment

Each simulated user keeps one visitor id (cookie aegis_vid=benign-b2-N) for a short session of
a few requests, then a new user starts; sessions stay small and touch few distinct ids so they do
not look like enumeration. Local range only.
"""

from __future__ import annotations

import argparse
import json
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8080"   # NOT "localhost": on Windows that costs ~2 s per new connection (IPv6 fallback)
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
       "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
       "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"]
SEARCH = ["Dune", "hobbit", "snow", "O'Brien", "SELECT * FROM", "Bobby Tables", "naïve café", "100% pure",
          "a--b", "rock & roll", "<b>bold</b>", "Ünïcödé 日本語", "it's", "x" * 120, "foundation", "emma",
          "what's new; really", "1=1 perfect", "union station", "drop the bass", "or else"]
REVIEWS = ["Loved it!", "It's a good book -- really", "O'Brien's recipe; 5 stars", "DROP TABLE of contents lol",
           "<i>great</i> read", "Très bien, 100% recommended", "late but worth it -- 4/5", "日本語のレビュー",
           "'quoted' and \"double\"", "a" * 300]
CREDS = [("admin@booknook.test", "admin123"), ("jim@booknook.test", "ncc-1701"),
         ("bender@booknook.test", "OhGod10%close"), ("ada@booknook.test", "Tr1cky!pass")]


def req(method, path, vid, ua, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method, headers={
        "User-Agent": ua, "Cookie": f"aegis_vid={vid}", "Host": "localhost:8080",
        **({"Content-Type": "application/json"} if data else {})})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            resp.read()
            return resp.status
    except urllib.error.HTTPError as e:
        e.read()
        return e.code
    except Exception:       # a dropped connection / malformed reply is data, never a dead worker
        return 0


def session(rng: random.Random, vid: str) -> int:
    ua = rng.choice(UAS)
    n = 1
    req("GET", "/", vid, ua)
    for _ in range(rng.randint(1, 3)):
        req("GET", "/api/books?q=" + urllib.parse.quote(rng.choice(SEARCH)), vid, ua)
        n += 1
    for _ in range(rng.randint(0, 2)):
        req("GET", f"/api/books/{rng.randint(1, 20)}", vid, ua)
        n += 1
    if rng.random() < 0.35:                                     # login, sometimes one typo first
        e, p = rng.choice(CREDS)
        if rng.random() < 0.2:
            req("POST", "/api/login", vid, ua, {"email": e, "password": p + "x"})
            n += 1
        req("POST", "/api/login", vid, ua, {"email": e, "password": p})
        n += 1
        if rng.random() < 0.5:
            req("GET", f"/api/orders/{rng.randint(1, 60)}", vid, ua)
            n += 1
    if rng.random() < 0.3:
        req("POST", "/api/reviews", vid, ua, {"book": rng.randint(1, 20), "text": rng.choice(REVIEWS)})
        n += 1
    if rng.random() < 0.1:
        req("GET", "/api/diagnostics?host=" + urllib.parse.quote(rng.choice(["localhost", "example.com", "8.8.8.8"])),
            vid, ua)
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
            n = session(rng, f"benign-b2-{w}-{i}")
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
