"""Benign traffic generator: realistic users shopping on Juice Shop, on a loop.

Each worker repeatedly picks a journey (weighted), spins up a fresh browser
context with a random persona (device, locale, timezone, slow/fast), runs the
journey through the real UI, and records the outcome.

Usage:
    python range/benign/generate.py --journeys 20            # quick check
    python range/benign/generate.py --duration 60 --workers 4 --fast
    python range/benign/generate.py --only search_weird --journeys 5 --headed

Outputs logs/benign/journeys.jsonl, one line per journey:
    {"journey", "ok", "error", "steps", "persona", "t_start", "t_end", "worker"}

Run the gateway in -mode detect while building the benign corpus, so CRS
false positives are *recorded* (in logs/gateway/requests.jsonl) without
breaking the journeys. Run in -mode enforce to measure journeys broken.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
import time
from dataclasses import asdict
from pathlib import Path

from playwright.async_api import Browser, async_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
import journeys as J  # noqa: E402
import personas as P  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
BACKGROUND = ("/socket.io/",)  # app push channel, not a user action


async def run_one(browser: Browser, devices: dict, name: str, base: str,
                  rng: random.Random, accounts: list, think: tuple[float, float],
                  shots: Path | None) -> dict:
    persona = P.random_persona(rng)
    opts = dict(devices[persona.device]) if persona.device else {}
    opts.pop("default_browser_type", None)
    ctx = await browser.new_context(**opts, locale=persona.locale, timezone_id=persona.timezone)
    ctx.set_default_timeout(J.STEP_TIMEOUT_MS)
    # Per-visitor nonce so the observer can group this context's requests into
    # one actor (stands in for a distinct source IP). Not a detection feature.
    await ctx.add_cookies([{"name": "aegis_vid",
                            "value": f"benign-{rng.getrandbits(48):012x}", "url": base}])
    page = await ctx.new_page()
    # Watch every response so a failure can be attributed: did the DEFENCE
    # block something (403), did the APP fall over (5xx), or neither (script)?
    blocked: list[str] = []
    app_errors: list[str] = []

    def on_response(r):
        if not r.url.startswith(base):
            return
        if r.status == 403:
            blocked.append(r.url[len(base):][:200])
        elif r.status >= 500:
            app_errors.append(r.url[len(base):][:200])

    page.on("response", on_response)
    jc = J.JourneyContext(base=base, rng=rng, persona=persona, accounts=accounts, think=think)
    t0 = time.time()
    ok, err, cause = True, None, None
    try:
        await J.JOURNEYS[name][0](page, jc)
    except Exception as e:  # any failure = broken journey; keep going
        ok, err = False, f"{type(e).__name__}: {str(e).splitlines()[0][:300]}"
        # Background channels (socket.io push) get blocked in passing journeys
        # too, so they are not evidence of what broke THIS journey. Only a
        # block on a foreground request is. Definitive attribution needs a
        # paired run (same seed, detect vs enforce) -- see eval harness.
        fg_blocked = [b for b in blocked if not b.startswith(BACKGROUND)]
        cause = "defence" if fg_blocked else "app" if app_errors else "script"
        if shots:
            shots.mkdir(parents=True, exist_ok=True)
            try:
                await page.screenshot(path=str(shots / f"{int(t0)}_{name}.png"))
            except Exception:
                pass
    finally:
        await ctx.close()
    return {"journey": name, "ok": ok, "error": err, "cause": cause,
            "blocked": blocked, "app_errors": app_errors, "steps": jc.steps,
            "persona": asdict(persona), "t_start": t0, "t_end": time.time()}


async def worker(wid: int, args, browser, devices, rng, accounts, out, deadline, counter, lock):
    names = list(J.JOURNEYS) if not args.only else args.only
    weights = [J.JOURNEYS[n][1] for n in names]
    think = (0.05, 0.3) if args.fast else (0.4, 2.0)
    shots = ROOT / "logs" / "benign" / "failures" if args.screenshots else None
    while time.time() < deadline:
        async with lock:
            if args.journeys and counter[0] >= args.journeys:
                return
            counter[0] += 1
        # Seed the account pool before account journeys are picked.
        name = "register" if not accounts and "register" in names and rng.random() < 0.5 \
            else rng.choices(names, weights)[0]
        rec = await run_one(browser, devices, name, args.base, rng, accounts, think, shots)
        rec["worker"] = wid
        out.write(json.dumps(rec, ensure_ascii=False) + "\n")
        out.flush()
        mark = "ok " if rec["ok"] else "FAIL"
        print(f"[w{wid}] {mark} {name:14s} {rec['t_end'] - rec['t_start']:5.1f}s"
              + (f"  [{rec['cause']}] {rec['error']}" if rec["error"] else ""), flush=True)


async def main_async(args) -> int:
    out_path = ROOT / "logs" / "benign" / "journeys.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    run_start = time.time()
    deadline = run_start +(args.duration * 60 if args.duration else 10**9)
    master = random.Random(args.seed)
    accounts: list[J.Account] = []  # Juice Shop resets its DB on restart, so per-run only
    counter, lock = [0], asyncio.Lock()
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=not args.headed)
        with out_path.open("a", encoding="utf-8") as out:
            await asyncio.gather(*[
                worker(i, args, browser, pw.devices, random.Random(master.random()),
                       accounts, out, deadline, counter, lock)
                for i in range(args.workers)])
        await browser.close()

    rows = [json.loads(l) for l in out_path.open(encoding="utf-8")]
    rows = [r for r in rows if r["t_start"] >= run_start]
    ok = sum(r["ok"] for r in rows)
    causes = {c: sum(r.get("cause") == c for r in rows) for c in ("defence", "app", "script")}
    print(f"\njourneys this run: {len(rows)}   ok: {ok}   failed: {len(rows) - ok}  "
          f"(broken by defence: {causes['defence']}, app errors: {causes['app']}, "
          f"script: {causes['script']})")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--base", default="http://localhost:8080")
    p.add_argument("--workers", type=int, default=2)
    p.add_argument("--journeys", type=int, default=0, help="stop after N journeys (0 = no limit)")
    p.add_argument("--duration", type=float, default=0, help="stop after N minutes (0 = no limit)")
    p.add_argument("--only", nargs="+", choices=list(J.JOURNEYS), help="run only these journeys")
    p.add_argument("--fast", action="store_true", help="short think-times (for corpus volume)")
    p.add_argument("--headed", action="store_true", help="show the browser windows")
    p.add_argument("--screenshots", action="store_true", help="screenshot failed journeys")
    p.add_argument("--seed", type=int, default=None)
    args = p.parse_args()
    if not args.journeys and not args.duration:
        p.error("give --journeys N and/or --duration MINUTES")
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
