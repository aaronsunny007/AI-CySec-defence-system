"""Hot-reload stress test: no dropped connections, bad manifests refused.

Several keep-alive client threads hammer the gateway continuously while the rule
manifest is rewritten dozens of times (rules added, modes changed, rules
cleared). Persistent connections matter: a reload that tore down listeners or
connections would surface as resets here. We also inject a CORRUPT manifest (a
rule trying to smuggle `allow`) and check the gateway keeps enforcing the
previous rules.
"""

from __future__ import annotations

import http.client
import json
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("gate", "deliberator", "ir", "eval"):
    sys.path.insert(0, str(ROOT / p))
import rulestore                      # noqa: E402
import generate as deliberator        # noqa: E402
from rangectl import Range            # noqa: E402


class Hammer(threading.Thread):
    def __init__(self, i: int):
        super().__init__(daemon=True)
        self.i, self.stop_flag = i, threading.Event()
        self.ok = 0
        self.bad: list[str] = []
        self.lat: list[float] = []

    def run(self):
        conn = http.client.HTTPConnection("127.0.0.1", 8080, timeout=15)
        while not self.stop_flag.is_set():
            t0 = time.time()
            try:
                conn.request("GET", "/rest/products/search?q=apple",
                             headers={"Cookie": f"aegis_vid=stress-{self.i}"})
                r = conn.getresponse()
                r.read()
                if r.status == 200:
                    self.ok += 1
                else:
                    self.bad.append(f"HTTP {r.status}")
            except (OSError, http.client.HTTPException) as e:
                self.bad.append(type(e).__name__)
                conn.close()
                conn = http.client.HTTPConnection("127.0.0.1", 8080, timeout=15)
            self.lat.append((time.time() - t0) * 1000)


def sqli_blocked() -> int:
    c = http.client.HTTPConnection("127.0.0.1", 8080, timeout=15)
    c.request("GET", "/rest/products/search?q=%27%20OR%201%3D1--", headers={"Cookie": "aegis_vid=probe"})
    r = c.getresponse(); r.read(); c.close()
    return r.status


def main() -> int:
    sqli = next(c for c in deliberator.candidates_for("sqli", {"endpoints": ["/rest/products/search"]})
                if c["id"] == "aegis-sqli-3")
    rate = next(c for c in deliberator.candidates_for("credential_stuffing", {})
                if c["mechanism"] == "rate_limit")
    states = [
        [], [(sqli, "shadow", 0)], [(sqli, "canary", 50)], [(sqli, "enforce", 0)],
        [(sqli, "enforce", 0), (rate, "shadow", 0)], [(sqli, "off", 0), (rate, "enforce", 0)],
        [(sqli, "enforce", 0), (rate, "canary", 30)],
    ]
    rulestore.clear()
    reload_ms, failed_reloads_injected = [], 0
    with Range(mode="enforce"):
        hammers = [Hammer(i) for i in range(8)]
        for h in hammers:
            h.start()
        time.sleep(2)
        t_end, n = time.time() + 40, 0
        while time.time() < t_end:
            st = states[n % len(states)]
            n += 1
            rulestore.clear()
            for ir, mode, pct in st:
                rulestore.upsert(ir, mode=mode, canary_pct=pct)
            t0 = time.time()
            ok = rulestore.wait_version(rulestore.load()["version"], timeout=20)
            reload_ms.append((time.time() - t0) * 1000)
            assert ok, "reload did not complete"
            time.sleep(0.4)

        # corrupt manifest: must be refused, previous rules must keep enforcing
        rulestore.clear(); rulestore.upsert(sqli, mode="enforce")
        rulestore.wait_version(rulestore.load()["version"])
        good_version = rulestore.stats()["version"]
        m = rulestore.load()
        m["rules"].append({"id": "evil", "type": "sec", "mode": "enforce", "canary_pct": 0,
                           "secrule": 'SecRule ARGS "@unconditionalMatch" "id:1,phase:1,allow"'})
        m["version"] += 1
        rulestore.save(m)
        time.sleep(2.5)
        still_version = rulestore.stats()["version"]
        still_blocking = sqli_blocked()
        failed_reloads_injected = 1 if still_version == good_version else 0
        rulestore.clear()

        for h in hammers:
            h.stop_flag.set()
        for h in hammers:
            h.join(timeout=20)

    ok = sum(h.ok for h in hammers)
    bad = [e for h in hammers for e in h.bad]
    lat = sorted(x for h in hammers for x in h.lat)
    pct = lambda p: lat[min(int(len(lat) * p), len(lat) - 1)]
    reload_ms.sort()
    out = {
        "client_threads": 8, "requests": ok + len(bad), "failed_requests": len(bad),
        "failure_types": sorted(set(bad)),
        "manifest_reloads": n, "reload_ms_p50": round(reload_ms[len(reload_ms) // 2]),
        "reload_ms_max": round(reload_ms[-1]),
        "client_latency_ms": {"p50": round(pct(.5), 1), "p99": round(pct(.99), 1), "max": round(lat[-1], 1)},
        "corrupt_manifest_refused": bool(failed_reloads_injected),
        "gateway_version_kept": still_version == good_version,
        "sqli_still_blocked_during_corrupt_manifest": still_blocking == 403,
    }
    print(json.dumps(out, indent=2))
    (ROOT / "logs" / "hotreload_stress.json").write_text(json.dumps(out, indent=2))
    return 0 if not bad and out["corrupt_manifest_refused"] and out["sqli_still_blocked_during_corrupt_manifest"] else 1


if __name__ == "__main__":
    sys.exit(main())
