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

import hashlib
import hmac
import json
import re
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


def secret(name: str) -> bytes | None:
    """A secret from env var NAME, or from the file named by NAME_FILE (kept outside git).
    Never printed or logged."""
    v = os.environ.get(name, "").strip()
    if v:
        return v.encode()
    f = os.environ.get(name + "_FILE")
    if f and Path(f).exists():
        return Path(f).read_text(encoding="utf-8").strip().encode()
    return None


def sign(key: bytes, payload: str) -> str:
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _norm(m: dict) -> dict:
    """A fresh gateway writes `"rules": null` for an empty store; callers iterate it."""
    if isinstance(m, dict) and m.get("rules") is None:
        m["rules"] = []
    return m


def _high_water(path: Path) -> int:
    """The newest manifest version the gateway has ever loaded (<manifest>.hw, see gateway/rules.go).
    0 when absent or when its signature does not verify."""
    try:
        h = json.loads(Path(str(path) + ".hw").read_text(encoding="utf-8"))
        v = int(h["v"])
    except (OSError, ValueError, KeyError, TypeError):
        return 0
    key = secret("AEGIS_MANIFEST_KEY")
    if key and not hmac.compare_digest(sign(key, f"aegis-hw:{v}"), str(h.get("sig", "")).lower()):
        return 0
    return max(v, 0)


def load(path: Path = DEFAULT_MANIFEST) -> dict:
    if not path.exists():
        return {"version": 1, "rules": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    key = secret("AEGIS_MANIFEST_KEY")
    if isinstance(data, dict) and "payload" in data and "sig" in data:   # signed envelope
        if key and not hmac.compare_digest(sign(key, data["payload"]), str(data["sig"]).lower()):
            raise ValueError("manifest signature does not verify")
        m = _norm(json.loads(data["payload"]))
    elif key:
        raise ValueError("manifest is not signed but AEGIS_MANIFEST_KEY is set")
    else:
        m = _norm(data)
    if key:
        hw = _high_water(path)
        if int(m.get("version", 0)) < hw:
            # A validly signed but OLDER manifest. Refusing (instead of re-signing its rules at hw+1 on
            # the next write) keeps a rollback visible; the operator restores the manifest or runs clear().
            raise ValueError(f"manifest v{m.get('version')} is older than the high-water mark v{hw} "
                             "(possible rollback); restore it or reset the rule store")
    return m


def save(m: dict, path: Path = DEFAULT_MANIFEST) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    key = secret("AEGIS_MANIFEST_KEY")
    text = json.dumps(m, indent=2)
    if key:       # the gateway refuses anything else in this mode
        text = json.dumps({"payload": text, "sig": sign(key, text)}, indent=2)
    tmp.write_text(text, encoding="utf-8")
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


_ID_IN_RULE = re.compile(r"\bid:(\d+)")


def _taken_numeric_ids(rules: list[dict], skip_id: str) -> set[int]:
    """Coraza ids already used by the other sec rules of a manifest."""
    return {int(n) for r in rules if r.get("id") != skip_id and r.get("type") == "sec"
            for n in _ID_IN_RULE.findall(r.get("secrule", ""))}


def free_numeric_id(ir: dict, taken: set[int]) -> int:
    """The id irc.numeric_id(ir) gives, or the next free slot if another rule already holds it."""
    rid = irc.numeric_id(ir)
    if len(taken) >= 90000:
        raise irc.IRError("rule store is full: no free Coraza id")
    while rid in taken:
        rid = 100000 + (rid - 100000 + 1) % 90000
    return rid


def entry_from_ir(ir: dict, mode: str = "shadow", canary_pct: int = 0, taken: set[int] | None = None) -> dict:
    """Validated IR -> manifest entry. Raises irc.IRError on invalid IR. `taken`: Coraza ids held by the
    manifest's other rules, so that a hash collision does not make the whole ruleset fail to load."""
    if ir["mechanism"] == "rate_limit":
        spec = irc.compile_rate(ir)
        return {"id": ir["id"], "type": "rate", "mode": mode, "canary_pct": canary_pct,
                "attack_class": ir["attack_class"],
                "endpoint_prefix": spec["endpoint_prefix"], "methods": spec["methods"],
                "count": spec["count"], "window_s": spec["window_s"], "key": spec["key"]}
    numeric = free_numeric_id(ir, taken) if taken is not None else None
    return {"id": ir["id"], "type": "sec", "mode": mode, "canary_pct": canary_pct,
            "attack_class": ir["attack_class"],
            "secrule": irc.compile_rule(ir, deny=False, numeric=numeric)}


def upsert(ir: dict, mode: str = "shadow", canary_pct: int = 0,
           path: Path = DEFAULT_MANIFEST) -> dict:
    m = load(path)
    e = entry_from_ir(ir, mode, canary_pct, taken=_taken_numeric_ids(m["rules"], ir["id"]))
    m["rules"] = [r for r in m["rules"] if r["id"] != e["id"]] + [e]
    m["version"] = m.get("version", 1) + 1
    save(m, path)
    return e


def clear(path: Path = DEFAULT_MANIFEST) -> None:
    """Empty the rule set. Works even when the existing file cannot be verified (e.g. an
    unsigned manifest left over from before signing was switched on): the version then comes
    from the clock, so it still only goes up."""
    try:
        version = load(path).get("version", 1) + 1
    except (ValueError, OSError):
        version = int(time.time())
    save({"version": version, "rules": []}, path)


# --- admin API ---------------------------------------------------------------

def _call(method: str, route: str, params: dict | None = None, timeout: float = 20.0):
    url = ADMIN + route + (("?" + urllib.parse.urlencode(params)) if params else "")
    req = urllib.request.Request(url, method=method, data=b"" if method == "POST" else None)
    token = secret("AEGIS_ADMIN_TOKEN")
    if token and method == "POST":
        req.add_header("Authorization", "Bearer " + token.decode())
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
