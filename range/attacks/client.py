"""Attack client: one actor firing a progressing sequence of requests.

An Actor is a single attacker identity -- stable User-Agent and cookie jar --
so that later (M1) actor reconstruction has something to reconstruct, and so a
campaign reads as a correlated sequence, not scattered requests.

Dependency-free (urllib only): the attack corpus must be reproducible with a
plain Python, no venv, no installs.

Every request is recorded to logs/attacks/requests.jsonl with the labels that
make it ground truth for scoring: campaign, actor, stage, technique,
attack_class, whether it was malicious, and the status the gateway returned.
`blocked` means the gateway returned 403 (its block verdict in enforce mode);
in detect mode nothing is blocked, so score blocks from the gateway's own log
(anomaly_score >= threshold) instead -- see the eval harness.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG = ROOT / "logs" / "attacks" / "requests.jsonl"

# Stages of a campaign, in the order a real intrusion progresses. Kept as a
# vocabulary so the observer/eval can reason about progression later.
STAGES = ("recon", "enumerate", "probe", "exploit", "exfil")


@dataclass
class Result:
    status: int | None
    blocked: bool
    body: str
    elapsed_ms: float
    error: str | None = None


@dataclass
class Actor:
    base: str
    campaign: str
    attack_class: str
    user_agent: str
    out: Any  # open file handle for JSONL, or None
    actor_id: str = ""
    token: str | None = None  # bearer token once authenticated
    jar: CookieJar = field(default_factory=CookieJar)
    _opener: Any = None
    fired: int = 0
    blocked_count: int = 0

    def __post_init__(self) -> None:
        if not self.actor_id:
            self.actor_id = f"{self.campaign}-{int(time.time() * 1000) % 100000:05d}"
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def fire(self, method: str, path: str, *, stage: str, technique: str,
             malicious: bool = True, params: dict | None = None,
             json_body: dict | None = None, data: bytes | None = None,
             headers: dict | None = None, note: str = "") -> Result:
        """Send one request as this actor and record it. Never raises on HTTP
        errors -- a 403/500 is data, not an exception."""
        assert stage in STAGES, stage
        url = self.base.rstrip("/") + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        # Per-actor visitor nonce so the observer groups this campaign's
        # requests into one actor (stands in for a distinct source IP on the
        # single-host range). Not a detection feature.
        hdrs = {"User-Agent": self.user_agent, "Cookie": f"aegis_vid=atk-{self.actor_id}"}
        body = data
        if json_body is not None:
            body = json.dumps(json_body).encode()
            hdrs["Content-Type"] = "application/json"
        if self.token:
            hdrs["Authorization"] = "Bearer " + self.token
        if headers:
            hdrs.update(headers)

        req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
        t0 = time.time()
        status: int | None = None
        resp_body = ""
        err = None
        try:
            with self._opener.open(req, timeout=15) as r:
                status = r.status
                resp_body = r.read(8192).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status = e.code
            resp_body = e.read(8192).decode("utf-8", "replace") if e.fp else ""
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            err = f"{type(e).__name__}: {e}"
        elapsed = (time.time() - t0) * 1000

        blocked = status in (403, 429)
        self.fired += 1
        self.blocked_count += blocked
        if self.out is not None:
            rec = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t0)),
                "campaign": self.campaign, "actor": self.actor_id,
                "attack_class": self.attack_class, "stage": stage,
                "technique": technique, "malicious": malicious,
                "method": method, "uri": path + (("?" + urllib.parse.urlencode(params)) if params else ""),
                "body": (json.dumps(json_body) if json_body is not None
                         else (data.decode("utf-8", "replace") if data else "")),
                "status": status, "blocked": blocked,
                "elapsed_ms": round(elapsed, 1), "note": note, "error": err,
            }
            self.out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.out.flush()
        return Result(status, blocked, resp_body, elapsed, err)
