"""BookNook: a second, deliberately vulnerable target app (stdlib only, no installs).

Exists to test whether AEGIS generalises beyond OWASP Juice Shop: different paths, different
request shapes, different parameter names. Local range only (listens on 127.0.0.1:3000, the
port the gateway proxies to).

Vulnerabilities (intentional):
  GET  /api/books?q=         SQL injection: q is concatenated into a SQLite LIKE query
  POST /api/login            SQL injection (auth bypass) AND unlimited password guessing
  GET  /api/orders/<id>      IDOR: any order readable without authentication
  GET  /api/diagnostics?host=  "command injection" sink. SIMULATED: nothing is ever executed;
                             a shell metacharacter + command in `host` makes it return canned
                             command output, so a campaign has a visible objective.
No file access, no outbound requests, no subprocesses.

    python range/app2/server.py [--port 3000]
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

DB = sqlite3.connect(":memory:", check_same_thread=False)
LOCK = threading.Lock()


def seed() -> None:
    c = DB.cursor()
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password TEXT)")
    c.execute("CREATE TABLE books(id INTEGER PRIMARY KEY, title TEXT, author TEXT, price REAL)")
    c.execute("CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT)")
    c.execute("CREATE TABLE reviews(id INTEGER PRIMARY KEY, book_id INTEGER, text TEXT)")
    users = [("admin@booknook.test", "admin123"), ("jim@booknook.test", "ncc-1701"),
             ("bender@booknook.test", "OhGod10%close"), ("ada@booknook.test", "Tr1cky!pass")]
    c.executemany("INSERT INTO users(email,password) VALUES(?,?)", users)
    titles = ["The Hobbit", "Dune", "Neuromancer", "Snow Crash", "Foundation", "Hyperion", "Emma",
              "Ulysses", "Middlemarch", "Kafka on the Shore", "O'Brien's Bakery Handbook",
              "SELECT * FROM Cookbook", "Bobby Tables for Beginners", "Moby-Dick", "Persuasion",
              "Dracula", "Frankenstein", "Beloved", "Gilead", "Piranesi"]
    for i, t in enumerate(titles, 1):
        c.execute("INSERT INTO books(title,author,price) VALUES(?,?,?)", (t, f"Author {i}", 5.0 + i))
    for i in range(1, 61):
        c.execute("INSERT INTO orders(user_id,item) VALUES(?,?)", (1 + i % 4, f"item-{i}"))
    DB.commit()


def rows(sql: str):
    with LOCK:
        cur = DB.execute(sql)
        cols = [d[0] for d in cur.description or []]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


class H(BaseHTTPRequestHandler):
    server_version = "BookNook/1.0"

    def log_message(self, *a):
        pass

    def _send(self, code: int, obj) -> None:
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(n, 65536)) if n else b""
        try:
            d = json.loads(raw or b"{}")
            return d if isinstance(d, dict) else {}
        except json.JSONDecodeError:
            return {}

    def do_GET(self) -> None:
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        try:
            if u.path == "/":
                b = b"<html><body><h1>BookNook</h1><a href='/api/books'>books</a></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
            elif u.path == "/api/books":
                term = (q.get("q") or [""])[0]
                self._send(200, {"books": rows(
                    f"SELECT id,title,author,price FROM books WHERE title LIKE '%{term}%'")})
            elif re.fullmatch(r"/api/books/\d+", u.path):
                self._send(200, {"books": rows(f"SELECT * FROM books WHERE id={u.path.split('/')[-1]}")})
            elif re.fullmatch(r"/api/orders/\d+", u.path):
                self._send(200, {"order": rows(f"SELECT * FROM orders WHERE id={u.path.split('/')[-1]}")})
            elif u.path == "/api/diagnostics":
                host = (q.get("host") or ["localhost"])[0]
                out = f"PING {host}: 64 bytes from {host}: icmp_seq=1 ttl=64 time=0.04 ms"
                if re.search(r"[;|&`$(]\s*(id|whoami|cat|ls|uname|sleep)\b", host):
                    out += "\nuid=1000(booknook) gid=1000(booknook) groups=1000(booknook)"  # canned, never executed
                self._send(200, {"output": out})
            else:
                self._send(404, {"error": "not found"})
        except sqlite3.Error as e:
            self._send(500, {"error": str(e)})

    def do_POST(self) -> None:
        u = urlsplit(self.path)
        d = self._body()
        try:
            if u.path == "/api/login":
                e, p = str(d.get("email", "")), str(d.get("password", ""))
                r = rows(f"SELECT id,email FROM users WHERE email='{e}' AND password='{p}'")
                if r:
                    self._send(200, {"token": "bn-" + str(r[0]["id"]), "email": r[0]["email"]})
                else:
                    self._send(401, {"error": "invalid credentials"})
            elif u.path == "/api/reviews":
                with LOCK:
                    DB.execute("INSERT INTO reviews(book_id,text) VALUES(?,?)",
                               (int(d.get("book", 1)), str(d.get("text", ""))[:2000]))
                    DB.commit()
                self._send(201, {"ok": True})
            else:
                self._send(404, {"error": "not found"})
        except (sqlite3.Error, ValueError) as e:
            self._send(500, {"error": str(e)})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=3000)
    a = ap.parse_args()
    seed()
    ThreadingHTTPServer(("127.0.0.1", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
