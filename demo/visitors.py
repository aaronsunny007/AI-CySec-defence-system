"""Normal users of BookNook for the demo.

Reuses the lab's BookNook visitor sessions (searches with apostrophes and SQL words, logins with the odd typo,
reviews, order lookups) but identifies each visitor the way a real API client does: a bearer token. The gateway
does not trust the lab-only visitor cookie in production, and neither does this demo.
"""

from __future__ import annotations

import importlib.util
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("booknook_benign", ROOT / "range" / "app2" / "benign.py")
B = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(B)

LOCK = threading.Lock()
STATS = {"sent": 0, "blocked_by_aegis_rule": 0, "blocked_by_crs": 0}


def _req(method, path, vid, ua, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(B.BASE + path, data=data, method=method, headers={
        "User-Agent": ua, "Authorization": f"Bearer {vid}", **({"Content-Type": "application/json"} if data else {})})
    status, text = 0, ""
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read(200).decode("utf-8", "replace")
    except Exception:
        status = 0
    with LOCK:
        STATS["sent"] += 1
        if status in (403, 429):
            STATS["blocked_by_aegis_rule" if "AEGIS rule" in text else "blocked_by_crs"] += 1
    return status


B.req = _req


def start(requests: int = 0, duration: float = 0, threads: int = 6, seed: int = 1, stop=None):
    """Begin normal traffic; returns (threads, counter)."""
    return B.run(requests, duration, threads, seed, stop)
