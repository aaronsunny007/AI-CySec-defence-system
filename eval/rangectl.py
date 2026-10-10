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
GATEWAY = ROOT / "bin" / "gateway.exe"
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


def _kill_pid(pid: int) -> None:
    # /T also ends children; targeted by PID only.
    subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                   capture_output=True, check=False)


def stop_recorded() -> None:
    """Terminate processes recorded by a previous run (stale pidfile)."""
    if PIDFILE.exists():
        for tok in PIDFILE.read_text().split():
            if tok.isdigit():
                _kill_pid(int(tok))
        PIDFILE.unlink(missing_ok=True)


class Range:
    def __init__(self, mode: str = "enforce", log: str = "logs/gateway/requests.jsonl",
                 manifest: str = "rules/active/manifest.json", extra_args: list[str] | None = None):
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
        flags = 0x08000000  # CREATE_NO_WINDOW
        js = subprocess.Popen(
            ["node", "build/app"], cwd=JUICE, creationflags=flags,
            stdout=open(logs / "juiceshop.out.log", "w"), stderr=open(logs / "juiceshop.err.log", "w"))
        self.procs.append(js)
        if not _wait("http://127.0.0.1:3000", 180):
            self.__exit__(None, None, None)
            raise RuntimeError("Juice Shop did not come up (see logs/juiceshop.*.log)")
        gw = subprocess.Popen(
            [str(GATEWAY), "-mode", self.mode, "-log", self.log, "-manifest", self.manifest,
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
