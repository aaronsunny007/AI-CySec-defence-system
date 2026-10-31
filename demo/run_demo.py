#!/usr/bin/env python3
"""AEGIS in about a minute, on a real attack that the standard WAF rules cannot see.

    python demo/run_demo.py

Runs, for real, on this machine: BookNook (a small web app with a login), the AEGIS gateway in front of it, and the
controller. A credential-stuffing bot then guesses passwords. Every request is an ordinary login, so OWASP CRS has
nothing to flag. AEGIS notices the pattern, writes a rate-limit rule, proves on live traffic that the rule does not
hurt real users, and starts enforcing it, with nobody touching anything.

The gate windows are shortened to 8 s (shadow) and 12 s (canary) so it fits in a minute; the defaults are 30 s and
45 s. Every stage still runs. Nothing printed below is scripted: the numbers come from the run.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "demo"))
import aegis          # noqa: E402
import attacker       # noqa: E402
import visitors       # noqa: E402

STATE = ["aegis.json", "logs/gateway/requests.jsonl", "logs/gateway/requests.jsonl.1", "logs/controller/events.jsonl",
         "rules/active/manifest.json", "rules/active/manifest.json.hw", "rules/active/manifest.json.good",
         "memory/controller.db", "data/learned/corpus.jsonl"]
USE_COLOR = True


def c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if USE_COLOR else s


def step(n: int, title: str) -> None:
    print(f"\n{c('1;36', f'[{n}/5]')} {c('1', title)}", flush=True)


def cli(*args: str) -> str:
    print(c("32", "$ aegis " + " ".join(args)), flush=True)
    out = subprocess.run([sys.executable, str(ROOT / "aegis.py"), *args], capture_output=True, text=True, cwd=ROOT)
    text = (out.stdout + out.stderr).strip()
    for ln in text.splitlines():
        print("  " + ln[:150], flush=True)
    return text


def wait_http(url: str, seconds: float = 20) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=1).close()
            return True
        except urllib.error.HTTPError:
            return True
        except Exception:
            time.sleep(0.3)
    return False


def main() -> int:
    global USE_COLOR
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--shadow-s", type=float, default=8)
    ap.add_argument("--canary-s", type=float, default=12)
    a = ap.parse_args()
    USE_COLOR = not a.no_color
    os.chdir(ROOT)

    aegis.cmd_stop(None) if aegis.read_pids() else None
    for f in STATE:
        (ROOT / f).unlink(missing_ok=True)
    app = subprocess.Popen([sys.executable, str(ROOT / "range" / "app2" / "server.py"), "--port", "3000"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = {}
    try:
        if not wait_http("http://127.0.0.1:3000/"):
            print("BookNook did not start"); return 1
        print(c("1", "AEGIS: an autonomous defence agent for a web app") + "   (free, local, open source)")
        print("The app: BookNook, a small shop with a login page, on port 3000.")

        step(1, "Put AEGIS in front of the app")
        cli("init", "--target", "http://127.0.0.1:3000", "--shadow-s", str(a.shadow_s), "--canary-s", str(a.canary_s))
        cli("learn")

        step(2, "Let it watch normal traffic first (it never blocks while learning)")
        ths, counter = visitors.start(requests=2400, threads=8, seed=3)
        last = 0
        while any(t.is_alive() for t in ths):
            time.sleep(1.5)
            sent = visitors.STATS["sent"]
            if sent != last:
                print(f"  ... {sent:,} requests from ordinary visitors", flush=True)
                last = sent
        time.sleep(1.0)
        text = cli("protect")

        step(3, "Protection is on. Now an attack that looks like normal traffic")
        print("  A bot replays leaked passwords against /api/login, ~8 guesses a second.")
        print("  Each request is an ordinary login: the standard WAF rules (OWASP CRS) see nothing wrong.\n", flush=True)
        stop_vis = __import__("threading").Event()
        visitors.STATS.update(sent=0, blocked_by_aegis_rule=0, blocked_by_crs=0)
        vthreads, _ = visitors.start(duration=300, threads=5, seed=11, stop=stop_vis)
        bot = attacker.Stuffer(n=700, rate=8.0)
        t_attack = time.time()
        bot.start()

        step(4, "AEGIS on its own (nobody touches anything now)")
        pos, enforced_at, last_tally = 0, None, 0.0
        other = {"alerts": 0, "rules": 0}
        events = ROOT / "logs" / "controller" / "events.jsonl"
        while time.time() - t_attack < 100:
            time.sleep(0.4)
            if events.exists():
                with events.open("rb") as f:
                    f.seek(pos)
                    data = f.read()
                    nl = data.rfind(b"\n")
                    if nl >= 0:
                        pos += nl + 1
                        for ln in data[:nl].splitlines():
                            try:
                                e = json.loads(ln)
                            except ValueError:
                                continue
                            main = (e.get("technique") == "credential_stuffing"
                                    or str(e.get("id", e.get("rule", ""))).startswith("aegis-credential_stuffing"))
                            if e.get("event") == "campaign_detected" and not main:
                                other["alerts"] += 1
                            elif e.get("event") == "mitigation" and not main:
                                other["rules"] += 1 if e.get("rule") else 0
                            line = aegis.format_event(e) if main else None
                            if line and e.get("event") != "controller_start":
                                since = e["t"] - t_attack
                                print(f"  {c('2', f'+{since:4.0f}s')} {line[10:]}", flush=True)
                            if e.get("event") == "enforced" and enforced_at is None:
                                enforced_at = e["t"] - t_attack
                                result["enforce_t"] = e["t"]
            s = bot.stats
            if time.time() - last_tally >= 3.0:
                last_tally = time.time()
                print(c("33", f"        bot so far: {s['guesses']} guesses | {s['reached_app']} reached the app | "
                              f"{s['blocked']} stopped by AEGIS | real accounts found: {len(s['valid_found'])}"), flush=True)
            if enforced_at is not None and time.time() - (result["enforce_t"]) > 12:
                break
        bot.stop_flag.set()
        time.sleep(0.5)

        step(5, "What happened")
        s = bot.stats
        # a real user logs in while the rule is live
        r = urllib.request.Request("http://127.0.0.1:8080/api/login", method="POST",
                                   data=json.dumps({"email": "jim@booknook.test", "password": "ncc-1701"}).encode(),
                                   headers={"Content-Type": "application/json", "Authorization": "Bearer real-user-jim"})
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                user_code = resp.status
        except urllib.error.HTTPError as e:
            user_code = e.code
        stop_vis.set()
        v = dict(visitors.STATS)
        if enforced_at is None:
            print(c("1;31", "  AEGIS did not enforce a rule in time in this run."))
        else:
            print(f"  rule enforcing {c('1;32', f'{enforced_at:.0f}s')} after the attack began, with no human involved")
        print(f"  the bot made {s['guesses']} guesses: {c('1', str(s['reached_app']))} reached the app, "
              f"{c('1;32', str(s['blocked']))} were stopped by AEGIS")
        print(f"  real accounts the bot cracked before the rule: {len(s['valid_found'])} ({', '.join(s['valid_found']) or 'none'})")
        print(f"  a real user logging in while the rule is live: HTTP {user_code} {'(works)' if user_code == 200 else '(PROBLEM)'}")
        print(f"  ordinary visitors blocked by an AEGIS rule: {c('1;32', str(v['blocked_by_aegis_rule']))} of {v['sent']:,} requests")
        if other["alerts"]:
            print(f"  AEGIS also investigated {other['alerts']} other alerts (ordinary visitors with odd searches, and the "
                  f"bot's side effects) and made {c('1', str(other['rules']))} rules for them")
        print(c("2", "\n  (gate windows shortened to %gs + %gs for this demo; defaults are 30s + 45s)" % (a.shadow_s, a.canary_s)))
        cli("stop")
        result.update(enforced_s=enforced_at, guesses=s["guesses"], reached=s["reached_app"], stopped=s["blocked"],
                      user_login=user_code, benign_blocked_by_rule=v["blocked_by_aegis_rule"], benign_sent=v["sent"])
        Path(os.environ.get("DEMO_RESULT", "/dev/null")).write_text(json.dumps(result, indent=2)) if os.environ.get("DEMO_RESULT") else None
        return 0 if enforced_at is not None and user_code == 200 and v["blocked_by_aegis_rule"] == 0 else 2
    finally:
        try:
            aegis._stop_all()
        except Exception:
            pass
        app.terminate()
        for f in STATE:
            (ROOT / f).unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
