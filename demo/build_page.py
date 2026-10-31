#!/usr/bin/env python3
"""Build the playable demo page from a recording.

    python demo/build_page.py demo/aegis-demo.cast demo/aegis-demo.html --standalone

Every number on the page is read out of the recording itself, so the text cannot disagree with what the viewer
watches. Without --standalone the output is a fragment (title, style, body content) for publishing as an artifact.
The player is a small, self-contained script: the recording holds only colour codes and line breaks.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def facts(cast_lines: list[str]) -> dict:
    ev = [json.loads(l) for l in cast_lines[1:]]
    text = ANSI.sub("", "".join(e[2] for e in ev)).replace("\r", "")

    def grab(pat, group=1, cast=str):
        m = re.search(pat, text)
        if not m:
            sys.exit(f"recording does not contain: {pat}")
        return cast(m.group(group).replace(",", ""))

    def first_t(marker):
        for t, _, d in ev:
            if marker in ANSI.sub("", d):
                return t
        sys.exit(f"no frame contains: {marker}")

    f = {
        "learned": grab(r"Gate evidence: (\d+) learned requests", 1, int),
        "visitors": grab(r"learned requests from (\d+) visitors", 1, int),
        "detect_s": grab(r"detected ([\d.]+)s after it began", 1, float),
        "rule_s": grab(r"made aegis-\S+ \[fresh\] in ([\d.]+)s", 1, float),
        "rule_id": grab(r"made (aegis-\S+) \[fresh\]", 1, str),
        "enforce_s": grab(r"rule enforcing (\d+)s after", 1, int),
        "guesses": grab(r"the bot made (\d+) guesses", 1, int),
        "reached": grab(r"guesses: (\d+) reached the app", 1, int),
        "stopped": grab(r"reached the app, (\d+) were stopped", 1, int),
        "cracked": grab(r"cracked before the rule: (\d+)", 1, int),
        "user_login": grab(r"while the rule is live: HTTP (\d+)", 1, int),
        "benign_blocked": grab(r"blocked by an AEGIS rule: (\d+) of", 1, int),
        "benign_sent": grab(r"blocked by an AEGIS rule: \d+ of ([\d,]+) requests", 1, int),
        "other_alerts": grab(r"investigated (\d+) other alerts", 1, int),
        "other_rules": grab(r"made (\d+) rules for them", 1, int),
        "shadow_s": grab(r"shadow (\d+)s, canary", 1, int),
        "canary_s": grab(r"canary (\d+)s", 1, int),
        "duration": round(ev[-1][0]),
        "t_learn": first_t("[2/5]"), "t_protect": first_t("PROTECT mode"), "t_attack": first_t("[3/5]"),
        "t_detect": first_t("CAMPAIGN  credential_stuffing"), "t_enforced": first_t("ENFORCED"),
        "t_result": first_t("[5/5]"),
    }
    return f


CSS = """
:root {
  /* layout: one reading column; a dark terminal card is the only loud object, everything around it stays quiet */
  --bg: #f3f6f4; --surface: #ffffff; --fg: #16201b; --muted: #55665d; --line: #d6dfd9;
  --accent: #0a6a5b; --accent-fg: #ffffff; --note-bg: #fff3dc; --note-fg: #6e4300; --good: #0f7a3f;
  --term-bg: #0b1210; --term-fg: #d0dad4; --term-line: #1d2a25; --t-dim: #72887c; --t-red: #ff7b72;
  --t-green: #6fdc8c; --t-yellow: #e6c15a; --t-cyan: #56d4dd; --t-blue: #79b8ff;
  --f-body: "IBM Plex Sans", system-ui, -apple-system, "Segoe UI", sans-serif;
  --f-mono: "IBM Plex Mono", ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {
  --bg: #0e1411; --surface: #141c18; --fg: #e2ebe6; --muted: #98ada1; --line: #26332d;
  --accent: #4cc2a8; --accent-fg: #06120e; --note-bg: #2b2210; --note-fg: #efc56e; --good: #5fd48f; color-scheme: dark; } }
:root[data-theme="dark"] {
  --bg: #0e1411; --surface: #141c18; --fg: #e2ebe6; --muted: #98ada1; --line: #26332d;
  --accent: #4cc2a8; --accent-fg: #06120e; --note-bg: #2b2210; --note-fg: #efc56e; --good: #5fd48f; color-scheme: dark; }
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--fg); font: 400 16px/1.6 var(--f-body);
  padding-block: 40px 64px; padding-left: max(16px, env(safe-area-inset-left, 0px));
  padding-right: max(16px, env(safe-area-inset-right, 0px)); }
.wrap { max-width: 900px; margin: 0 auto; display: grid; gap: 40px; }
.wrap > * { min-width: 0; }
h1 { font: 600 clamp(1.7rem, 4.5vw, 2.4rem)/1.15 var(--f-body); letter-spacing: -0.02em; margin: 0 0 12px; text-wrap: balance; }
h2 { font: 600 1.15rem/1.3 var(--f-body); margin: 0 0 14px; }
p { margin: 0 0 12px; max-width: 68ch; }
.lede { font-size: 1.1rem; color: var(--muted); }
.kicker { font: 500 0.78rem/1 var(--f-mono); letter-spacing: 0.08em; text-transform: uppercase; color: var(--accent); margin: 0 0 14px; }
a { color: var(--accent); text-underline-offset: 3px; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

.player { background: var(--term-bg); border: 1px solid var(--term-line); border-radius: 10px; overflow: hidden; min-width: 0; max-width: 100%; }
.screen { margin: 0; padding: 16px 18px; height: min(62vh, 520px); overflow: auto; color: var(--term-fg);
  font: 400 clamp(11px, 1.9vw, 13.5px)/1.5 var(--f-mono); white-space: pre; tab-size: 4; max-width: 100%; }
@media (max-width: 700px) { .screen { white-space: pre-wrap; overflow-wrap: anywhere; padding: 14px; } }
.b { font-weight: 600; } .d { color: var(--t-dim); }
.c36 { color: var(--t-cyan); } .c32 { color: var(--t-green); } .c33 { color: var(--t-yellow); } .c31 { color: var(--t-red); }
.controls { display: flex; flex-wrap: wrap; align-items: center; gap: 10px 14px; padding: 10px 14px;
  border-top: 1px solid var(--term-line); background: #0f1815; color: var(--term-fg); font: 500 0.82rem/1 var(--f-mono); }
.controls button { font: inherit; color: #06120e; background: #4cc2a8; border: 0; border-radius: 6px; padding: 9px 14px; cursor: pointer; min-width: 5.5rem; }
.controls button.quiet { background: transparent; color: var(--term-fg); border: 1px solid #2a3a33; min-width: 0; padding: 8px 11px; }
.controls input[type=range] { flex: 1 1 160px; min-width: 120px; accent-color: #4cc2a8; }
.time { font-variant-numeric: tabular-nums; color: var(--t-dim); white-space: nowrap; }
.hint { color: var(--muted); font-size: 0.9rem; margin: 10px 0 0; }

.chapters { display: grid; gap: 2px; margin: 0; padding: 0; list-style: none; }
.chapters button { all: unset; box-sizing: border-box; display: grid; grid-template-columns: 4.2rem 1fr; gap: 12px; width: 100%;
  padding: 10px 12px; border-radius: 8px; cursor: pointer; }
.chapters button:hover { background: var(--surface); }
.chapters button:focus-visible { outline: 2px solid var(--accent); }
.chapters .t { font: 500 0.85rem/1.6 var(--f-mono); color: var(--accent); font-variant-numeric: tabular-nums; }
.chapters .h { font-weight: 600; } .chapters .s { display: block; color: var(--muted); font-size: 0.93rem; }

.numbers { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 0; border: 1px solid var(--line); border-radius: 10px; background: var(--surface); overflow: hidden; }
.numbers div { padding: 16px 18px; border-bottom: 1px solid var(--line); border-right: 1px solid var(--line); margin: 0 -1px -1px 0; min-width: 0; }
.numbers dt { color: var(--muted); font-size: 0.85rem; margin: 0 0 4px; }
.numbers dd { margin: 0; font: 600 1.55rem/1.2 var(--f-body); font-variant-numeric: tabular-nums; letter-spacing: -0.01em; }
.numbers dd small { font: 400 0.85rem/1.4 var(--f-body); color: var(--muted); display: block; letter-spacing: 0; }
.numbers .good dd { color: var(--good); }

.note { background: var(--note-bg); color: var(--note-fg); border-radius: 10px; padding: 18px 20px; }
.note h2 { color: inherit; } .note ul { margin: 0; padding-left: 1.2em; display: grid; gap: 8px; } .note li { max-width: 70ch; }
pre.cmd { background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; margin: 0 0 12px; overflow-x: auto;
  font: 400 0.88rem/1.6 var(--f-mono); }
code { font-family: var(--f-mono); font-size: 0.92em; }
"""

JS = r"""
(function () {
  var cast = document.getElementById('cast').textContent.trim().split('\n').map(function (l) { return JSON.parse(l); });
  var frames = cast.slice(1).map(function (f) { return { t: f[0], s: f[2] }; });
  var DUR = frames[frames.length - 1].t + 1;
  var screen = document.getElementById('screen'), play = document.getElementById('play'), scrub = document.getElementById('scrub'),
      clock = document.getElementById('clock'), speedBtn = document.getElementById('speed'), restart = document.getElementById('restart');
  var pos = DUR, playing = false, last = 0, speed = 1, shown = -1;
  var CLS = { 36: 'c36', 32: 'c32', 33: 'c33', 31: 'c31' };

  function esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
  function toHtml(text) {
    text = text.replace(/\r\n/g, '\n').replace(/\r/g, '');
    var re = /\x1b\[([0-9;]*)m/g, out = '', at = 0, m, st = { b: false, d: false, c: '' };
    function span(chunk) {
      if (!chunk) return '';
      var cl = (st.b ? 'b ' : '') + (st.d ? 'd ' : '') + st.c;
      return cl.trim() ? '<span class="' + cl.trim() + '">' + esc(chunk) + '</span>' : esc(chunk);
    }
    while ((m = re.exec(text))) {
      out += span(text.slice(at, m.index)); at = re.lastIndex;
      (m[1] === '' ? ['0'] : m[1].split(';')).forEach(function (c) {
        c = +c;
        if (c === 0) { st = { b: false, d: false, c: '' }; } else if (c === 1) { st.b = true; } else if (c === 2) { st.d = true; }
        else if (c === 22) { st.b = false; st.d = false; } else if (c === 39) { st.c = ''; } else if (CLS[c]) { st.c = CLS[c]; }
      });
    }
    return out + span(text.slice(at));
  }
  function upto(t) { var n = 0; while (n < frames.length && frames[n].t <= t) n++; return n; }
  function draw() {
    var n = upto(pos);
    if (n !== shown) {
      shown = n;
      screen.innerHTML = toHtml(frames.slice(0, n).map(function (f) { return f.s; }).join(''));
      screen.scrollTop = screen.scrollHeight;
    }
    scrub.value = Math.round(pos * 100);
    var s = Math.floor(pos), d = Math.floor(DUR);
    clock.textContent = '0:' + String(s).padStart(2, '0') + ' / 0:' + String(d).padStart(2, '0');
    play.textContent = playing ? 'Pause' : (pos >= DUR ? 'Replay' : 'Play');
  }
  function tick(now) {
    if (!playing) return;
    pos = Math.min(DUR, pos + (now - last) / 1000 * speed); last = now;
    if (pos >= DUR) playing = false;
    draw();
    if (playing) requestAnimationFrame(tick);
  }
  function start() { if (pos >= DUR) pos = 0; playing = true; last = performance.now(); requestAnimationFrame(tick); draw(); }
  function stop() { playing = false; draw(); }
  play.addEventListener('click', function () { playing ? stop() : start(); });
  restart.addEventListener('click', function () { pos = 0; shown = -1; start(); });
  speedBtn.addEventListener('click', function () { speed = speed === 1 ? 2 : 1; speedBtn.textContent = speed + 'x'; });
  scrub.max = Math.round(DUR * 100);
  scrub.addEventListener('input', function () { pos = scrub.value / 100; draw(); });
  document.querySelectorAll('[data-seek]').forEach(function (b) {
    b.addEventListener('click', function () {
      pos = +b.getAttribute('data-seek'); draw();
      document.getElementById('player').scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    });
  });
  draw();
})();
"""


def build(cast_path: Path, standalone: bool) -> str:
    raw = cast_path.read_text(encoding="utf-8")
    f = facts(raw.splitlines())
    e = html.escape
    secs = lambda t: f"{int(t) // 60}:{int(t) % 60:02d}"
    chapters = [
        (0.4, "Put AEGIS in front of the app", "It starts in learn mode, which only watches and never blocks anything."),
        (f["t_learn"], "Let it watch normal traffic", f"{f['learned']:,} requests from {f['visitors']} ordinary visitors, including odd but legitimate ones like O'Brien and SELECT * FROM."),
        (f["t_attack"], "Protection on, then the attack starts", "A bot guesses leaked passwords at about 8 a second. Each request is an ordinary login, so the standard WAF rules see nothing wrong."),
        (f["t_detect"], f"AEGIS spots it in {f['detect_s']:g} s and writes a rule", f"A rate limit on the login endpoint, made in {f['rule_s']:g} s. It is not switched on yet."),
        (f["t_enforced"], "The rule proves itself on live traffic, then enforces", f"{f['shadow_s']} s watching only, {f['canary_s']} s blocking a quarter of visitors, then everyone. The bot's guesses start coming back stopped."),
        (f["t_result"], "The result", "Counted from the run, not written in advance."),
    ]
    chap_html = "\n".join(
        f'<li><button type="button" data-seek="{c[0]:.2f}"><span class="t">{secs(c[0])}</span>'
        f'<span><span class="h">{e(c[1])}</span><span class="s">{e(c[2])}</span></span></button></li>' for c in chapters)

    page = f"""<title>AEGIS Demo</title>
<meta name="claude:viewport-fit-sides" content="cover">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap">
<style>{CSS}</style>
<div class="wrap">
  <header>
    <p class="kicker">AEGIS · autonomous web-app defence</p>
    <h1>It noticed a password-guessing bot, wrote a rule, tested it on live traffic, and turned it on</h1>
    <p class="lede">A real {f['duration']}-second recording. Nobody touches anything after the attack starts.
    The attack is one the standard rules (OWASP CRS) cannot see, because every request is a normal login.</p>
  </header>

  <section aria-label="Recording" id="player">
    <div class="player">
      <pre class="screen" id="screen" role="img" aria-label="Terminal recording of the AEGIS demo; the chapters below describe it"></pre>
      <div class="controls">
        <button type="button" id="play">Replay</button>
        <button type="button" class="quiet" id="restart" aria-label="Restart from the beginning">Restart</button>
        <input type="range" id="scrub" min="0" max="100" value="100" aria-label="Position in the recording">
        <span class="time" id="clock">0:00 / 0:00</span>
        <button type="button" class="quiet" id="speed" aria-label="Playback speed">1x</button>
      </div>
    </div>
    <p class="hint">Shows the finished run. Press Replay to watch it happen in real time, or jump to a moment below.</p>
  </section>

  <section>
    <h2>What you are watching</h2>
    <ul class="chapters">
{chap_html}
    </ul>
  </section>

  <section>
    <h2>What happened, counted</h2>
    <dl class="numbers">
      <div class="good"><dt>Rule enforcing, after the attack began</dt><dd>{f['enforce_s']} s<small>no human involved</small></dd></div>
      <div><dt>Password guesses made by the bot</dt><dd>{f['guesses']}<small>{f['reached']} reached the app, {f['stopped']} were stopped</small></dd></div>
      <div><dt>Real accounts cracked before the rule landed</dt><dd>{f['cracked']}<small>the rule limits the damage, it does not undo it</small></dd></div>
      <div class="good"><dt>A real user logging in while the rule is live</dt><dd>HTTP {f['user_login']}<small>works</small></dd></div>
      <div class="good"><dt>Ordinary visitors blocked by an AEGIS rule</dt><dd>{f['benign_blocked']}<small>of {f['benign_sent']:,} requests</small></dd></div>
      <div><dt>Other alerts AEGIS looked at</dt><dd>{f['other_alerts']}<small>it made {f['other_rules']} rules for them</small></dd></div>
    </dl>
  </section>

  <section class="note">
    <h2>Read this before you believe it</h2>
    <ul>
      <li>It is a small demo shop on one machine, not a production site. The app is BookNook, a deliberately simple target in this repository.</li>
      <li>The gate's watching windows are shortened to {f['shadow_s']} s and {f['canary_s']} s so the demo fits in a minute. The defaults are 30 s and 45 s. Every stage still runs, but a rule is watched for less time before it enforces.</li>
      <li>This is one recording of one run, and the attack was chosen because the standard rules miss it. AEGIS did not cause the {f['cracked']} cracked accounts, but it did not prevent them either: the first {f['reached']} guesses got through.</li>
      <li>The testing behind these claims, and the places where AEGIS still falls short (slow attacks, a load balancer that hides client addresses, a gateway that stops), are in <a href="https://github.com/aaronsunny007/AI-CySec-defence-system/blob/main/docs/SECURITY-REVIEW.md" target="_blank" rel="noopener">the security review</a> and <a href="https://github.com/aaronsunny007/AI-CySec-defence-system/blob/main/docs/REMEASURE-2026-10-31.md" target="_blank" rel="noopener">the re-measurement</a>.</li>
    </ul>
  </section>

  <section>
    <h2>Run it yourself</h2>
    <p>Needs Python 3.10 or newer and the gateway built once (<a href="https://github.com/aaronsunny007/AI-CySec-defence-system/blob/main/docs/INSTALL.md" target="_blank" rel="noopener">install</a>). No accounts, no paid services.</p>
    <pre class="cmd">python demo/run_demo.py</pre>
    <p>To record your own: <code>python demo/record.py demo/aegis-demo.cast -- python demo/run_demo.py</code>, then <code>python demo/build_page.py demo/aegis-demo.cast demo/aegis-demo.html --standalone</code>.</p>
  </section>
</div>
<script type="application/json" id="cast">
{raw.rstrip()}
</script>
<script>{JS}</script>
"""
    if standalone:
        head, rest = page.split("<div class=\"wrap\">", 1)
        return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\n"
                + head + "</head><body>\n<div class=\"wrap\">" + rest + "\n</body></html>\n")
    return page


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("cast", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--standalone", action="store_true", help="wrap in a full HTML document")
    a = ap.parse_args()
    a.out.write_text(build(a.cast, a.standalone), encoding="utf-8")
    print(f"wrote {a.out} ({a.out.stat().st_size:,} bytes)")
