"""Credential-stuffing A/B on ONE range boot, using hot reload.

  A) control   : CRS only          -> run the stuffing campaign
  reload       : hot-load the AEGIS rate rule (no restart) while a witness
                 client sends continuous traffic, to prove no request is dropped
  B) treatment : CRS + rate rule   -> run the stuffing campaign again
  benign       : a normal user logs in a few times (must NOT be limited)

Metrics: attack requests blocked, whether the attacker found valid credentials
(objective met), hot-reload latency, witness failures during reload.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("gate", "deliberator", "ir", "eval"):
    sys.path.insert(0, str(ROOT / p))
sys.path.insert(0, str(ROOT / "range" / "attacks"))
import rulestore                      # noqa: E402
import generate as deliberator        # noqa: E402
from rangectl import Range            # noqa: E402
import campaigns as C                 # noqa: E402
from client import Actor              # noqa: E402

BASE = "http://localhost:8080"


class Witness(threading.Thread):
    """Continuous legitimate traffic; records any failed/dropped request."""
    def __init__(self):
        super().__init__(daemon=True)
        self.stop_flag = threading.Event()
        self.ok = self.fail = 0
        self.errors: list[str] = []

    def run(self):
        while not self.stop_flag.is_set():
            req = urllib.request.Request(BASE + "/rest/products/search?q=apple",
                                         headers={"Cookie": "aegis_vid=witness-1"})
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    r.read()
                self.ok += 1
            except urllib.error.HTTPError as e:
                if e.code >= 500 or e.code in (403, 429):
                    self.fail += 1
                    self.errors.append(f"HTTP {e.code}")
                else:
                    self.ok += 1
            except (urllib.error.URLError, OSError) as e:
                self.fail += 1
                self.errors.append(type(e).__name__)
            time.sleep(0.03)


def run_stuffing(log_fh) -> dict:
    a = Actor(base=BASE, campaign="credential_stuffing", attack_class="credential_stuffing",
              user_agent=C.user_agent_for("credential_stuffing"), out=log_fh)
    res = C.credential_stuffing(a, pace=0.05)
    return {"fired": a.fired, "blocked": a.blocked_count,
            "objective_met": res["objective_met"], "evidence": res["evidence"]}


def benign_logins(n: int = 3) -> list[int]:
    codes = []
    for _ in range(n):
        req = urllib.request.Request(
            BASE + "/rest/user/login", method="POST",
            data=json.dumps({"email": "someone@example.com", "password": "not-a-real-pw"}).encode(),
            headers={"Content-Type": "application/json", "Cookie": "aegis_vid=benign-ab-1"})
        try:
            urllib.request.urlopen(req, timeout=10)
            codes.append(200)
        except urllib.error.HTTPError as e:
            codes.append(e.code)
        time.sleep(0.2)
    return codes


def main() -> int:
    rulestore.clear()
    candidate = next(c for c in deliberator.candidates_for("credential_stuffing", {})
                     if c["mechanism"] == "rate_limit")
    log_path = ROOT / "logs" / "attacks" / "ab_stuffing.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with Range(mode="enforce") as _r, log_path.open("a", encoding="utf-8") as lf:
        witness = Witness()
        witness.start()
        time.sleep(1)

        print("A) control: CRS only")
        a = run_stuffing(lf)
        print("  ", a)

        print("hot-loading rate rule (no restart) ...")
        before_ok = witness.ok
        t0 = time.time()
        entry = rulestore.upsert(candidate, mode="enforce")
        ver = rulestore.load()["version"]
        loaded = rulestore.wait_version(ver, timeout=30)
        reload_s = time.time() - t0
        print(f"   loaded={loaded} in {reload_s:.2f}s (rule {entry['id']} "
              f">{entry['count']}/{entry['window_s']}s on {entry['endpoint_prefix']})")
        time.sleep(1)

        print("B) treatment: CRS + AEGIS rate rule")
        b = run_stuffing(lf)
        print("  ", b)

        print("benign user, 3 normal logins:")
        codes = benign_logins(3)
        print("   statuses:", codes, "(401 = wrong password from the app; 429 would be a false block)")

        time.sleep(1)
        witness.stop_flag.set()
        witness.join(timeout=5)
        st = rulestore.stats()

    summary = {
        "control": a, "treatment": b, "hot_reload_s": round(reload_s, 2), "reload_ok": loaded,
        "witness_requests": witness.ok + witness.fail, "witness_failures": witness.fail,
        "witness_errors": sorted(set(witness.errors)),
        "benign_login_statuses": codes, "benign_false_blocks": sum(c == 429 for c in codes),
        "rule_counters": st["rules"],
    }
    print("\n=== A/B summary ===")
    print(json.dumps(summary, indent=2))
    (ROOT / "logs" / "ab_stuffing_summary.json").write_text(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
