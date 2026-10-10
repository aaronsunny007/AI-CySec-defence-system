"""Actor reconstruction: group a raw request stream into actors.

An actor is one logical client followed across its requests. On a real
deployment it would be reconstructed from session + fingerprint + behavioural
signature (not IP alone). On our single-host range every client shares
127.0.0.1, so the gateway stamps a per-client nonce (`aegis_vid`) that the
range sets and the gateway hashes into the `session` field; that nonce stands
in for the distinct source IPs a real deployment has. See docs/DECISIONS.md.

Grouping key, in order of preference:
  1. session fingerprint from the gateway (hashed token / visitor nonce)
  2. (client_ip, user_agent) fingerprint as a fallback

IMPORTANT: the key only decides *which requests belong together*. Whether an
actor is attacking is decided later, in campaigns.py, from BEHAVIOUR only --
never from the user-agent string or the grouping key.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator


@dataclass
class Request:
    ts: datetime
    method: str
    path: str          # URI without query
    query: str
    body: str
    status: int | None
    anomaly_score: int
    attack_tags: list[str]
    raw: dict

    @property
    def endpoint(self) -> str:
        """Path with trailing numeric id collapsed to {id}, so /rest/basket/3
        and /rest/basket/4 count as the same endpoint (enumeration signal)."""
        parts = self.path.split("/")
        return "/".join("{id}" if p.isdigit() else p for p in parts)


@dataclass
class Actor:
    key: str
    requests: list[Request] = field(default_factory=list)

    @property
    def start(self) -> datetime:
        return self.requests[0].ts

    @property
    def end(self) -> datetime:
        return self.requests[-1].ts

    @property
    def duration_s(self) -> float:
        return (self.end - self.start).total_seconds()


def _parse_ts(s: str) -> datetime:
    # Gateway writes RFC3339Nano (UTC, trailing Z); normaliser may write other.
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.min


def actor_key(rec: dict) -> str:
    sess = rec.get("session") or ""
    if sess and not sess.startswith("ip:"):
        return sess
    ip = rec.get("client_ip") or "?"
    ua = (rec.get("user_agent") or "")[:80]
    return f"{ip}|{ua}"


def iter_records(path: Path) -> Iterator[dict]:
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def to_request(rec: dict) -> Request:
    uri = rec.get("uri") or ""
    path, _, query = uri.partition("?")
    return Request(
        ts=_parse_ts(rec.get("ts", "")),
        method=rec.get("method") or "",
        path=path, query=query,
        body=rec.get("body") or "",
        status=rec.get("status"),
        anomaly_score=rec.get("anomaly_score") or 0,
        attack_tags=rec.get("attack_tags") or [],
        raw=rec,
    )


def reconstruct(path: Path) -> dict[str, Actor]:
    """Group all requests in a gateway/normalised log into actors, time-sorted."""
    actors: dict[str, Actor] = {}
    for rec in iter_records(path):
        actors.setdefault(actor_key(rec), Actor(key=actor_key(rec))).requests.append(
            to_request(rec))
    for a in actors.values():
        a.requests.sort(key=lambda r: r.ts)
    return actors
