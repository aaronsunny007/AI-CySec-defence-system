"""Live traffic drivers for the gate's shadow and canary stages.

ReplayDriver  - replays REAL benign requests sampled uniformly from the benign
                corpus against the live gateway at a controlled rate, spread over
                a pool of synthetic users (each gets its own aegis_vid so the
                gateway sees many actors). This gives a canary the realistic
                benign volume it needs, without launching a browser per request.
AttackDriver  - fires fresh campaign actors of one class on an interval.

Neither driver looks at gateway decisions to choose traffic; they only count
what came back.
"""

from __future__ import annotations

import http.client
import json
import os
import random
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "range" / "attacks"))

SKIP_PREFIXES = ("/socket.io",)       # push-channel polling is not replayable
ATTACK_UA_MARKERS = ("sqlmap", "xsstrike", "nuclei", "commix", "ssrfmap",
                     "aegis-enum", "autorize", "openbullet")


def sample_corpus(path: Path, n: int, seed: int = 1) -> list[dict]:
    """Uniform random sample of n replayable requests via random byte seeks
    (the corpus is hundreds of MB; never load it whole)."""
    rng = random.Random(seed)
    size = os.path.getsize(path)
    out: list[dict] = []
    with path.open("rb") as f:
        while len(out) < n:
            f.seek(rng.randrange(0, max(1, size - 4096)))
            f.readline()                      # discard the partial line
            line = f.readline()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            uri = r.get("uri") or ""
            ua = (r.get("user_agent") or "").lower()
            if (not uri.startswith("/") or uri.startswith(SKIP_PREFIXES)
                    or any(m in ua for m in ATTACK_UA_MARKERS)
                    or r.get("method") not in ("GET", "POST", "PUT", "DELETE", "PATCH")):
                continue
            out.append({"method": r["method"], "uri": uri, "body": r.get("body") or "",
                        "ct": r.get("content_type") or "", "ua": r.get("user_agent") or ""})
    return out


class ReplayDriver:
    def __init__(self, corpus: Path, host: str = "127.0.0.1", port: int = 8080,
                 rps: float = 60.0, threads: int = 6, users: int = 200, seed: int = 7,
                 pool: int = 30000):
        self.host, self.port = host, port
        self.interval = threads / rps
        self.threads_n, self.users = threads, users
        self.rng = random.Random(seed)
        self.pool = sample_corpus(corpus, pool, seed)
        self.stop_flag = threading.Event()
        self.threads: list[threading.Thread] = []
        self.sent = self.errors = 0
        self.statuses: dict[int, int] = {}
        self._lock = threading.Lock()

    def _worker(self, wid: int) -> None:
        rng = random.Random(wid * 7919 + 1)
        conn = http.client.HTTPConnection(self.host, self.port, timeout=15)
        while not self.stop_flag.is_set():
            t0 = time.time()
            r = self.pool[rng.randrange(len(self.pool))]
            headers = {"Cookie": f"aegis_vid=benign-replay-{rng.randrange(self.users)}",
                       "User-Agent": r["ua"] or "Mozilla/5.0"}
            if r["ct"]:
                headers["Content-Type"] = r["ct"]
            body = r["body"].encode() if r["body"] else None
            try:
                conn.request(r["method"], r["uri"], body=body, headers=headers)
                resp = conn.getresponse()
                resp.read()
                with self._lock:
                    self.sent += 1
                    self.statuses[resp.status] = self.statuses.get(resp.status, 0) + 1
            except (OSError, http.client.HTTPException):
                with self._lock:
                    self.errors += 1
                conn.close()
                conn = http.client.HTTPConnection(self.host, self.port, timeout=15)
            time.sleep(max(0.0, self.interval - (time.time() - t0)))

    def start(self) -> "ReplayDriver":
        for i in range(self.threads_n):
            t = threading.Thread(target=self._worker, args=(i,), daemon=True)
            t.start()
            self.threads.append(t)
        return self

    def stop(self) -> None:
        self.stop_flag.set()
        for t in self.threads:
            t.join(timeout=10)


class AttackDriver:
    """Fires one campaign class repeatedly, a fresh actor each time."""
    def __init__(self, campaign: str, interval_s: float = 5.0, base: str = "http://localhost:8080",
                 log_path: Path | None = None):
        import campaigns as C
        from client import Actor
        self.C, self.Actor, self.campaign = C, Actor, campaign
        self.interval, self.base = interval_s, base
        self.log_path = log_path or (ROOT / "logs" / "attacks" / "stages.jsonl")
        self.stop_flag = threading.Event()
        self.thread: threading.Thread | None = None
        self.runs = 0

    def _loop(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as fh:
            while not self.stop_flag.is_set():
                a = self.Actor(base=self.base, campaign=self.campaign, attack_class=self.campaign,
                               user_agent=self.C.user_agent_for(self.campaign), out=fh)
                try:
                    self.C.CAMPAIGNS[self.campaign](a, 0.05)
                    self.runs += 1
                except Exception:
                    pass
                self.stop_flag.wait(self.interval)

    def start(self) -> "AttackDriver":
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        return self

    def stop(self) -> None:
        self.stop_flag.set()
        if self.thread:
            self.thread.join(timeout=30)
