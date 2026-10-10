"""Rule store client: edit the gateway's manifest and drive its admin API.

The gateway watches a manifest (rules/active/manifest.json) and hot-reloads it.
This module is the trusted writer: it compiles validated IR into manifest
entries (SecRule text in `pass` form, or a rate spec), writes the manifest
atomically, and talks to the gateway's loopback admin API for stats, mode
changes and rollback.

Nothing here accepts raw rule text from the LLM: entries are built only from IR
that ir/compile.py has validated.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ir"))
import compile as irc  # noqa: E402

DEFAULT_MANIFEST = ROOT / "rules" / "active" / "manifest.json"
ADMIN = "http://127.0.0.1:8081"


def load(path: Path = DEFAULT_MANIFEST) -> dict:
    if not path.exists():
        return {"version": 1, "rules": []}
    return json.loads(path.read_text(encoding="utf-8"))


def save(m: dict, path: Path = DEFAULT_MANIFEST) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(m, indent=2), encoding="utf-8")
    # os.replace is atomic (a reader sees old or new, never partial) but on
    # Windows it fails with PermissionError while another process -- here the
    # gateway's watcher -- has the destination open. Retry briefly.
    for _ in range(200):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            time.sleep(0.02)
    os.replace(tmp, path)  # let the final failure surface


def entry_from_ir(ir: dict, mode: str = "shadow", canary_pct: int = 0) -> dict:
    """Validated IR -> manifest entry. Raises irc.IRError on invalid IR."""
    if ir["mechanism"] == "rate_limit":
        spec = irc.compile_rate(ir)
        return {"id": ir["id"], "type": "rate", "mode": mode, "canary_pct": canary_pct,
                "attack_class": ir["attack_class"],
                "endpoint_prefix": spec["endpoint_prefix"], "methods": spec["methods"],
                "count": spec["count"], "window_s": spec["window_s"]}
    return {"id": ir["id"], "type": "sec", "mode": mode, "canary_pct": canary_pct,
            "attack_class": ir["attack_class"],
            "secrule": irc.compile_rule(ir, deny=False)}


def upsert(ir: dict, mode: str = "shadow", canary_pct: int = 0,
           path: Path = DEFAULT_MANIFEST) -> dict:
    m = load(path)
    e = entry_from_ir(ir, mode, canary_pct)
    m["rules"] = [r for r in m["rules"] if r["id"] != e["id"]] + [e]
    m["version"] = m.get("version", 1) + 1
    save(m, path)
    return e


def clear(path: Path = DEFAULT_MANIFEST) -> None:
    m = load(path)
    m["rules"], m["version"] = [], m.get("version", 1) + 1
    save(m, path)


# --- admin API ---------------------------------------------------------------

def _call(method: str, route: str, params: dict | None = None, timeout: float = 20.0):
    url = ADMIN + route + (("?" + urllib.parse.urlencode(params)) if params else "")
    req = urllib.request.Request(url, method=method, data=b"" if method == "POST" else None)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode()


def stats() -> dict:
    return json.loads(_call("GET", "/stats"))


def set_mode(rule_id: str, mode: str, pct: int = 0) -> str:
    return _call("POST", "/mode", {"id": rule_id, "mode": mode, "pct": pct})


def rollback(rule_id: str) -> str:
    return _call("POST", "/rollback", {"id": rule_id})


def wait_version(version: int, timeout: float = 30.0) -> bool:
    """Block until the gateway reports it has loaded manifest >= version."""
    import time
    end = time.time() + timeout
    while time.time() < end:
        try:
            if stats()["version"] >= version:
                return True
        except (urllib.error.URLError, OSError, ValueError):
            pass
        time.sleep(0.25)
    return False
