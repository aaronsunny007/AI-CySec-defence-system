"""Range lifecycle from Python: start/stop Juice Shop + the AEGIS gateway.

Replaces the PowerShell start/stop loop for orchestrated experiments: it spawns
the two processes directly, records ONLY the PIDs it created, waits for real
readiness, and on exit terminates exactly those PIDs (never by image name, so it
cannot touch unrelated node/other processes).

    with Range(mode="enforce") as r:
        ...  # http://localhost:8080 is Juice Shop behind the gateway;
             # the admin API is on http://127.0.0.1:8081
"""

from __future__ import annotations

import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JUICE = Path(os.environ.get("AEGIS_JUICESHOP", str(Path.home() / "tools" / "juice-shop")))
GATEWAY = ROOT / "bin" / ("gateway.exe" if os.name == "nt" else "gateway")
PIDFILE = ROOT / "logs" / "range.pids"


def _up(url: str) -> bool:
    try:
        urllib.request.urlopen(url, timeout=2)
        return True
    except urllib.error.HTTPError:
        return True
    except (urllib.error.URLError, OSError):
        return False


def _wait(url: str, seconds: int) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if _up(url):
            return True
        time.sleep(1)
    return False


# CREATE_NO_WINDOW on Windows; nothing on POSIX (where a non-zero creationflags is an error).
NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def _kill_pid(pid: int) -> None:
    """End exactly this process (by PID only, never by image name)."""
    if os.name == "nt":
        # /T also ends children
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, check=False)
        return
    import signal
    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(50):
            time.sleep(0.1)
            try:
                os.kill(pid, 0)
            except OSError:
                return
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def stop_recorded() -> None:
    """Terminate processes recorded by a previous run (stale pidfile)."""
    if PIDFILE.exists():
        for tok in PIDFILE.read_text().split():
            if tok.isdigit():
                _kill_pid(int(tok))
        PIDFILE.unlink(missing_ok=True)


def _reset_dvwa_state() -> None:
    """DVWA locks an account for 15 minutes after 3 failed logins and keeps every guestbook post; a
    stuffing run in one replicate must not lock accounts for the next, so each range starts clean."""
    mysql = Path.home() / "tools" / "mariadb" / "bin" / "mysql.exe"
    subprocess.run([str(mysql), "-u", "root", "-h", "127.0.0.1", "-P", "3307", "-e",
                    "UPDATE dvwa.users SET failed_login=0, last_login=NULL; "
                    "DELETE FROM dvwa.guestbook WHERE comment_id>1;"], capture_output=True, check=False,
                   creationflags=NO_WINDOW)


def _ensure_mariadb(logs: Path) -> None:
    """DVWA's database: ~/tools/mariadb on 127.0.0.1:3307 (data in ~/tools/mariadb_data). Left running between
    ranges; it is ours, bound to loopback, and holds nothing but DVWA's seed data."""
    import socket
    try:
        socket.create_connection(("127.0.0.1", 3307), timeout=1).close()
        return
    except OSError:
        pass
    tools = Path.home() / "tools"
    subprocess.Popen([str(tools / "mariadb" / "bin" / "mysqld.exe"), f"--datadir={tools / 'mariadb_data'}",
                      "--port=3307", "--bind-address=127.0.0.1", "--console"], cwd=ROOT,
                     creationflags=NO_WINDOW, stdout=open(logs / "mariadb.out.log", "w"),
                     stderr=subprocess.STDOUT)
    for _ in range(60):
        time.sleep(1)
        try:
            socket.create_connection(("127.0.0.1", 3307), timeout=1).close()
            return
        except OSError:
            continue
    raise RuntimeError("MariaDB did not come up (see logs/mariadb.out.log)")


class Range:
    def __init__(self, mode: str = "enforce", log: str = "logs/gateway/requests.jsonl",
                 manifest: str = "rules/active/manifest.json", extra_args: list[str] | None = None,
                 app: str = "juiceshop"):
        """app='juiceshop' (default), 'booknook' (range/app2/server.py, the second target) or 'dvwa'
        (the third: PHP built-in server + MariaDB from ~/tools, security level low)."""
        self.app = app
        self.mode, self.log, self.manifest = mode, log, manifest
        self.extra = extra_args or []
        self.procs: list[subprocess.Popen] = []

    def __enter__(self) -> "Range":
        stop_recorded()
        if _up("http://127.0.0.1:3000") or _up("http://127.0.0.1:8080"):
            raise RuntimeError("ports 3000/8080 already in use by something this tool did not "
                               "start; refusing to kill unknown processes")
        logs = ROOT / "logs"
        logs.mkdir(exist_ok=True)
        flags = NO_WINDOW
        if self.app == "booknook":
            import sys
            js = subprocess.Popen(
                [sys.executable, str(ROOT / "range" / "app2" / "server.py"), "--port", "3000"],
                cwd=ROOT, creationflags=flags,
                stdout=open(logs / "juiceshop.out.log", "w"), stderr=open(logs / "juiceshop.err.log", "w"))
        elif self.app == "dvwa":
            _ensure_mariadb(logs)
            _reset_dvwa_state()
            env = dict(os.environ, DB_PORT="3307", DEFAULT_SECURITY_LEVEL="low")
            tools = Path.home() / "tools"
            js = subprocess.Popen(
                [str(tools / "php" / "php.exe"), "-c", str(tools / "php" / "php.ini"), "-S", "127.0.0.1:3000",
                 "-t", str(tools / "dvwa")], cwd=ROOT, env=env, creationflags=flags,
                stdout=open(logs / "juiceshop.out.log", "w"), stderr=open(logs / "juiceshop.err.log", "w"))
        else:
            js = subprocess.Popen(
                ["node", "build/app" if (JUICE / "build" / "app.js").exists() else "app"], cwd=JUICE, creationflags=flags,
                stdout=open(logs / "juiceshop.out.log", "w"), stderr=open(logs / "juiceshop.err.log", "w"))
        self.procs.append(js)
        if not _wait("http://127.0.0.1:3000", 180):
            self.__exit__(None, None, None)
            raise RuntimeError("Juice Shop did not come up (see logs/juiceshop.*.log)")
        gw = subprocess.Popen(
            # -range: the lab's clients are all 127.0.0.1 and tell themselves apart with the aegis_vid cookie.
            # Never pass it outside the lab: it makes a visitor-chosen cookie the visitor's identity.
            [str(GATEWAY), "-mode", self.mode, "-log", self.log, "-manifest", self.manifest, "-range",
             *self.extra], cwd=ROOT, creationflags=flags,
            stdout=open(logs / "gateway.out.log", "w"), stderr=open(logs / "gateway.err.log", "w"))
        self.procs.append(gw)
        if not _wait("http://127.0.0.1:8080", 90) or not _wait("http://127.0.0.1:8081/health", 30):
            self.__exit__(None, None, None)
            raise RuntimeError("gateway did not come up (see logs/gateway.err.log)")
        PIDFILE.write_text(" ".join(str(p.pid) for p in self.procs))
        return self

    def __exit__(self, *exc) -> None:
        for p in reversed(self.procs):
            _kill_pid(p.pid)
        PIDFILE.unlink(missing_ok=True)
        self.procs.clear()
        time.sleep(1.0)
