"""Diverse benign traffic for Juice Shop: many DISTINCT, input-bearing legitimate requests.

The original corpus has 443k rows but only ~4.1k distinct non-socket.io requests (mostly the same
page loads repeated), so a false-positive rate measured on it says little about odd user input.
This generator concentrates on the endpoints that carry user input and fills them with the kind of
text real users type, including the awkward-but-legitimate kind that trips naive signatures:

  * search queries and review/feedback text built from a vocabulary of everyday words, names with
    apostrophes and accents, other scripts, emoji, prices, hashtags, dates, markdown, URLs,
    SQL/shell/HTML words used in ordinary prose ("select the best", "drop me a line", "union of
    states", "see ../docs", "$(10) off", "a && b", "<3", "1=1 perfect");
  * registrations and logins with random strong passwords drawn from the full printable-ASCII set
    (quotes, semicolons, pipes, hashes, dashes, backticks, backslashes, braces);
  * normal API use around them (product pages, baskets, reviews, whoami, captcha-solved feedback).

stdlib only; every simulated user has its own visitor id (cookie aegis_vid=benign-div-W-N), so the
gateway labels the traffic benign. Local range only.

    python range/benign/diverse.py --requests 60000 --threads 8 [--seed 1]
"""

from __future__ import annotations

import argparse
import json
import random
import string
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8080"
HOSTHDR = "localhost:8080"
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]
WORDS = """apple juice banana carrot berry green smoothie fresh organic sweet sour bitter cold warm pressed
bottle glass pack box gift order delivery shipping price cheap expensive quality taste flavour flavor
good great bad awful love hate recommend again never always maybe really very quite almost nearly
quick slow late early today tomorrow yesterday morning evening weekend holiday birthday party family
friend mother father sister brother child kids dog cat office home garden kitchen market store shop
best choice state line table update create group right left inner outer true false between limit
fruit vegetable vitamin protein sugar water milk coffee tea beer wine soda lemon orange grape mango
thanks please sorry hello hi bye welcome cheers congrats wow nice cool awesome amazing terrible ok
the a an and or but if then so because while when where which who what why how this that these those
is are was were be been have has had do does did will would can could should may might must""".split()
# words that are also SQL / shell / HTML / script vocabulary; real prose uses them, but rarely and
# almost never two of them side by side, so they enter the word stream at a low, independent rate
SENSITIVE = """select union drop delete insert alter grant having echo print ls id whoami ping sleep curl wget
bash sh cmd exec system eval include require import script alert prompt onclick onload image video frame
object embed link style class admin root test guest password secret token session cookie login logout""".split()
NAMES = ["O'Brien", "D'Angelo", "McDonald", "Müller", "Nguyễn", "García", "Åsa", "Zoë", "François", "Søren",
         "Łukasz", "Иван", "Мария", "李雷", "田中", "김민수", "محمد", "Σοφία", "Jean-Luc", "Anne-Marie", "St. John",
         "van der Berg", "de la Cruz", "O’Neil", "N'Golo", "Bobby Tables"]
PIECES = ["100% organic", "50% off", "$9.99", "EUR 5,00", "#bestjuice", "@support", "x > y", "x < y", ":-)",
          "2 + 2 = 4", "it's", "don't", "can't", "\"quoted\"", "'single'", "**bold**", "[link](http://example.com)",
          "https://example.com/a?b=c&d=e", "50-60%", "2026-10-15", "10/15/2026", "12:30", "re: order #1234",
          "foo--bar", "naive cafe", "uber", "senor", "...", "smart \u201cquotes\u201d", "(parens)", "[brackets]",
          "<3", "\U0001F600", "\U0001F34E\U0001F34C", "\u00fcber", "caf\u00e9", "\u00df", "\u00f1", "\u2014", "\u2013"]
# legitimate-but-awkward strings: the ones naive signatures trip over. Rate: ~1% of tokens.
EDGY = ["SELECT the best", "drop me a line", "union of states", "union station", "or else", "this and that",
        "1 or 2", "1=1 perfect", "select * from happiness", "$(10) off", "`code`", "a && b", "a || b", "see ../docs",
        "C:\\temp\\file.txt", "/usr/bin/env", "{braces}", "a;b;c", "a|b|c", "--help", "#!/bin/sh", "re: <b>bold</b>",
        "&amp;", "<i>it</i>", "' and '", "O'Brien's"]
PUNCT = string.punctuation
ALNUM = string.ascii_letters + string.digits
SECURITY = ["name of your first pet", "mother's maiden name", "favourite teacher", "city of birth"]


def text(r: random.Random, lo: int = 2, hi: int = 14) -> str:
    out = []
    for _ in range(r.randint(lo, hi)):
        k = r.random()
        if k < 0.78:
            out.append(r.choice(WORDS))
        elif k < 0.84:
            out.append(r.choice(NAMES))
        elif k < 0.92:
            out.append(r.choice(PIECES))
        elif k < 0.935:
            out.append(r.choice(SENSITIVE))          # 1.5%: SQL/shell/HTML words used as plain words
        elif k < 0.945:
            out.append(r.choice(EDGY))               # 1.0%: deliberately awkward but legitimate
        elif k < 0.975:
            out.append(str(r.randint(0, 99999)))
        else:
            out.append("".join(r.choice(ALNUM + " .,!?'-") for _ in range(r.randint(2, 12))))
    s = " ".join(out)
    if r.random() < 0.2:
        s = s.capitalize()
    if r.random() < 0.3:
        s += r.choice([".", "!", "?", "...", " :)", " --", " ;", " #"])
    return s


def password(r: random.Random) -> str:
    n = r.randint(8, 24)
    mode = r.random()
    if mode < 0.5:
        pool = ALNUM + PUNCT                       # full printable ASCII, quotes/#/;/|/-/` all possible
    elif mode < 0.8:
        pool = ALNUM + "!@#$%^&*"
    else:
        pool = ALNUM
    return "".join(r.choice(pool) for _ in range(n))


def email(r: random.Random) -> str:
    local = r.choice(["jean-luc", "o.brien", "d'angelo", "anna+shop", "max_mustermann", "li.lei", "test.user", "a"])
    return f"{local}{r.randint(0, 10**6)}@{r.choice(['example.com', 'mail.example.org', 'web.de', 'proton.me', 'uni-bonn.de'])}"


class User:
    def __init__(self, r: random.Random, vid: str):
        self.r, self.vid, self.ua = r, vid, r.choice(UAS)
        self.token = None
        self.email = email(r)
        self.pw = password(r)
        self.bid = None
        self.sent = 0

    def call(self, method: str, path: str, body=None, auth=False):
        data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None
        h = {"User-Agent": self.ua, "Cookie": f"aegis_vid={self.vid}", "Host": HOSTHDR,
             "Accept-Language": self.r.choice(["en-US,en;q=0.9", "de-DE,de;q=0.8", "fr;q=0.9", "ja,en;q=0.5"])}
        if data:
            h["Content-Type"] = "application/json"
        if auth and self.token:
            h["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read(200000)
                self.sent += 1
                return resp.status, raw
        except urllib.error.HTTPError as e:
            try:
                raw = e.read(20000)
            except Exception:
                raw = b""
            self.sent += 1
            return e.code, raw
        except Exception:
            return 0, b""


def session(r: random.Random, vid: str) -> int:
    u = User(r, vid)
    q = lambda s: urllib.parse.quote(s, safe="")  # noqa: E731
    u.call("GET", "/")
    for _ in range(r.randint(1, 5)):                         # searches
        term = text(r, 1, 6)
        if r.random() < 0.15:
            term = r.choice(NAMES)
        u.call("GET", f"/rest/products/search?q={q(term)}")
    for _ in range(r.randint(0, 3)):
        u.call("GET", f"/api/Products/{r.randint(1, 40)}")
    if r.random() < 0.7:                                       # register + login
        st, _ = u.call("POST", "/api/Users/", {"email": u.email, "password": u.pw, "passwordRepeat": u.pw,
                       "securityQuestion": {"id": r.randint(1, 4), "question": r.choice(SECURITY),
                                            "createdAt": "2026-01-01T00:00:00.000Z", "updatedAt": "2026-01-01T00:00:00.000Z"},
                       "securityAnswer": text(r, 1, 3)})
        if r.random() < 0.15:                                  # a typo'd password first
            u.call("POST", "/rest/user/login", {"email": u.email, "password": u.pw + r.choice(PUNCT)})
        st, raw = u.call("POST", "/rest/user/login", {"email": u.email, "password": u.pw})
        if st == 200:
            try:
                d = json.loads(raw)["authentication"]
                u.token, u.bid = d.get("token"), d.get("bid")
            except Exception:
                pass
    if u.token:
        u.call("GET", "/rest/user/whoami", auth=True)
        if u.bid:
            u.call("GET", f"/rest/basket/{u.bid}", auth=True)
            if r.random() < 0.6:
                u.call("POST", "/api/BasketItems/", {"ProductId": r.randint(1, 30), "BasketId": str(u.bid),
                                                    "quantity": r.randint(1, 5)}, auth=True)
        for _ in range(r.randint(0, 3)):                       # reviews
            u.call("PUT", f"/rest/products/{r.randint(1, 30)}/reviews",
                   {"message": text(r, 3, 40), "author": u.email}, auth=True)
        if r.random() < 0.5:                                   # captcha-solved feedback
            st, raw = u.call("GET", "/rest/captcha", auth=True)
            try:
                c = json.loads(raw)
                u.call("POST", "/api/Feedbacks/", {"comment": text(r, 4, 60), "rating": r.randint(1, 5),
                                                   "captchaId": c["captchaId"], "captcha": str(c["answer"])}, auth=True)
            except Exception:
                pass
    for _ in range(r.randint(0, 2)):
        u.call("GET", f"/rest/products/{r.randint(1, 40)}/reviews")
    if r.random() < 0.15:
        u.call("GET", f"/rest/user/security-question?email={q(email(r))}")
    return u.sent


def run(requests: int, duration: float, threads: int, seed: int, stop: threading.Event | None = None):
    counter = [0]
    lock = threading.Lock()
    t_end = time.time() + duration if duration else None

    def worker(w: int):
        r = random.Random(seed * 1000 + w)
        i = 0
        while not (stop and stop.is_set()):
            if requests and counter[0] >= requests:
                return
            if t_end and time.time() > t_end:
                return
            i += 1
            n = session(r, f"benign-div-{seed}-{w}-{i}")
            with lock:
                counter[0] += n
    ths = [threading.Thread(target=worker, args=(w,), daemon=True) for w in range(threads)]
    for t in ths:
        t.start()
    return ths, counter


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--requests", type=int, default=0)
    ap.add_argument("--duration", type=float, default=0, help="seconds")
    ap.add_argument("--threads", type=int, default=8)
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
