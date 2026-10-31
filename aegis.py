#!/usr/bin/env python3
"""aegis - run the AEGIS defence agent in front of your web app.

    aegis init --target http://127.0.0.1:3000   # once: write aegis.json + secrets
    aegis doctor                                # check everything is in place
    aegis learn                                 # observe only, never block; records your normal traffic
    aegis protect                               # enforce + autonomous rule synthesis, gated on what it learned
    aegis status | aegis stop

Standard library only; everything it starts (Go gateway, Python controller) is open source and local.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "aegis.json"
STATE = ROOT / ".aegis"                      # secrets (0600) - never committed
PIDS = ROOT / "logs" / "aegis.pids"
REQ_LOG = ROOT / "logs" / "gateway" / "requests.jsonl"
CORPUS = ROOT / "data" / "learned" / "corpus.jsonl"
EXE = ".exe" if os.name == "nt" else ""
GATEWAY = ROOT / "bin" / ("gateway" + EXE)
REPLAY = ROOT / "bin" / ("replay" + EXE)
ADMIN = "http://127.0.0.1:8081"

# `protect` refuses to run on less evidence than this: the gate cannot show a rule is safe
# for users it has never seen. There is deliberately no flag to lower these.
MIN_CORPUS_REQUESTS = 2000
MIN_CORPUS_ACTORS = 20

DEFAULTS = {"target": "http://127.0.0.1:3000", "listen": "127.0.0.1:8080",
            "llm": "none", "model": "qwen2.5-coder:7b"}


# --- small helpers -----------------------------------------------------------------

def say(msg: str = "") -> None:
    print(msg, flush=True)


def die(msg: str, code: int = 1) -> "NoReturn":    # noqa: F821
    print("aegis: " + msg, file=sys.stderr)
    sys.exit(code)


ENV_KEYS = {"AEGIS_TARGET": "target", "AEGIS_LISTEN": "listen", "AEGIS_LLM": "llm", "AEGIS_MODEL": "model"}


def load_config() -> dict:
    """aegis.json, overridden by AEGIS_TARGET / AEGIS_LISTEN / AEGIS_LLM / AEGIS_MODEL (containers)."""
    cfg = dict(DEFAULTS)
    if CONFIG.exists():
        cfg.update(json.loads(CONFIG.read_text(encoding="utf-8")))
    elif not any(k in os.environ for k in ENV_KEYS):
        die("no aegis.json - run: aegis init --target http://your-app:port")
    for env, key in ENV_KEYS.items():
        if os.environ.get(env):
            cfg[key] = os.environ[env]
    return cfg


def ensure_secrets() -> dict:
    """Manifest-signing key and admin token, generated once, readable only by this user."""
    STATE.mkdir(mode=0o700, exist_ok=True)
    try:
        STATE.chmod(0o700)
    except OSError:
        pass
    out = {}
    for name in ("AEGIS_MANIFEST_KEY", "AEGIS_ADMIN_TOKEN"):
        p = STATE / (name.lower() + ".txt")
        if not p.exists():
            # created 0600 from the first byte (write_text then chmod leaves a window where it is world-readable)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(secrets.token_hex(32))
        out[name + "_FILE"] = str(p)
    return out


def child_env() -> dict:
    return {**os.environ, **ensure_secrets()}


def port_free(hostport: str) -> bool:
    host, _, port = hostport.rpartition(":")
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex((host or "127.0.0.1", int(port))) != 0


def http_ok(url: str, timeout: float = 2.0) -> bool:
    try:
        urllib.request.urlopen(url, timeout=timeout).close()
        return True
    except urllib.error.HTTPError:
        return True              # the server answered - 404/401 still means "up"
    except Exception:
        return False


def read_pids() -> dict:
    try:
        return json.loads(PIDS.read_text(encoding="utf-8"))
    except Exception:
        return {}


def cmdline_of(pid: int) -> str:
    """The command line of a process, or "" when it cannot be read."""
    try:
        if sys.platform.startswith("linux"):
            return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
        if os.name == "nt":
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  f"(Get-CimInstance Win32_Process -Filter 'ProcessId={int(pid)}').CommandLine"],
                                 capture_output=True, text=True, timeout=20)
            return out.stdout.strip()
        return subprocess.run(["ps", "-p", str(int(pid)), "-o", "command="], capture_output=True, text=True,
                              timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


# What each recorded process must look like. A pid file that is stale (reboot, crash) or edited names a pid
# that may now belong to something else; `aegis stop` must never kill that.
MARKERS = {"gateway": "gateway", "controller": "loop.py"}


def owned(pids: dict, kind: str) -> int | None:
    """The pid recorded for `kind` if it is alive AND still our process, else None."""
    pid = pids.get(kind)
    if not pid or not alive(pid):
        return None
    cmd = cmdline_of(pid)
    return pid if MARKERS[kind] in cmd else None


def alive(pid: int | None) -> bool:
    if not pid:
        return False
    if os.name == "nt":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True)
        return str(pid) in out.stdout
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def private_dir(d: Path) -> None:
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass


def private_file(p: Path) -> Path:
    """Create p (if absent) readable by this user only; logs hold request data."""
    if not p.exists():
        os.close(os.open(p, os.O_WRONLY | os.O_CREAT, 0o600))
    return p


def spawn(cmd: list[str], logname: str, env: dict) -> int:
    private_dir(ROOT / "logs")
    out = open(private_file(ROOT / "logs" / f"{logname}.out.log"), "ab")
    err = open(private_file(ROOT / "logs" / f"{logname}.err.log"), "ab")
    kw = {"creationflags": 0x00000008 | 0x00000200} if os.name == "nt" else {"start_new_session": True}
    try:
        return subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=out, stderr=err, stdin=subprocess.DEVNULL, **kw).pid
    finally:
        out.close()      # the child keeps its own copies
        err.close()


def terminate(pid: int | None) -> None:
    if not alive(pid):
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    for _ in range(50):
        if not alive(pid):
            return
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


# --- the learned corpus --------------------------------------------------------------

def build_corpus() -> tuple[int, int, int]:
    """Snapshot the learn-mode request log (and its rotated predecessor) into the gate's benign corpus,
    dropping any actor the observer itself flags as running a campaign (an attacker present while
    learning must not become 'normal'). Returns (requests, actors, attack_like): attack_like counts kept
    requests that still carry an injection-style payload. They stay in the corpus on purpose -- it is the
    safe direction for a gate (a rule that would block them is rejected, never approved) -- but a high
    count means learning probably overlapped an attack and the operator should look."""
    sys.path.insert(0, str(ROOT / "observer"))
    from actors import Actor, reconstruct   # noqa: E402
    from detector import detect, has_payload  # noqa: E402
    logs = [p for p in (Path(str(REQ_LOG) + ".1"), REQ_LOG) if p.exists()]
    if not logs:
        return 0, 0, 0
    merged: dict[str, Actor] = {}
    for lg in logs:
        for k, a in reconstruct(lg).items():
            merged.setdefault(k, Actor(key=k)).requests.extend(a.requests)
    keep_n = actors_n = attack_like = 0
    private_dir(CORPUS.parent)
    tmp = CORPUS.with_suffix(".tmp")
    private_file(tmp)
    with tmp.open("w", encoding="utf-8") as f:
        for actor in merged.values():
            actor.requests.sort(key=lambda r: r.ts)
            if detect(actor):
                continue
            actors_n += 1
            for r in actor.requests:
                f.write(json.dumps(r.raw, ensure_ascii=False) + "\n")
                keep_n += 1
                attack_like += has_payload(r)
    os.replace(tmp, CORPUS)
    return keep_n, actors_n, attack_like


def log_requests() -> int:
    if not REQ_LOG.exists():
        return 0
    with REQ_LOG.open("rb") as f:
        return sum(1 for _ in f)


# --- commands ------------------------------------------------------------------------

def validate_config(cfg: dict) -> str | None:
    """A problem with the config, or None. Catches typos at `init`, not at 3am."""
    import urllib.parse
    t = urllib.parse.urlsplit(str(cfg.get("target", "")))
    if t.scheme not in ("http", "https") or not t.hostname:
        return f"target must be an http(s) URL such as http://127.0.0.1:3000, got {cfg.get('target')!r}"
    listen = str(cfg.get("listen", ""))
    host, _, port = listen.rpartition(":")
    if not host or not port.isdigit() or not (0 < int(port) < 65536):
        return f"listen must be HOST:PORT such as 127.0.0.1:8080, got {listen!r}"
    if f"{t.hostname}:{t.port or (443 if t.scheme == 'https' else 80)}" == f"{host}:{port}":
        return "target and listen are the same address: AEGIS would proxy to itself"
    if cfg.get("llm") not in ("none", "ollama"):
        return f"llm must be none or ollama, got {cfg.get('llm')!r}"
    return None


def cmd_init(a) -> int:
    cfg = {**DEFAULTS}
    if CONFIG.exists():
        cfg.update(json.loads(CONFIG.read_text(encoding="utf-8")))
    for k in ("target", "listen", "llm", "model"):
        v = getattr(a, k, None)
        if v:
            cfg[k] = v
    problem = validate_config(cfg)
    if problem:
        die(problem)
    CONFIG.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    ensure_secrets()
    say(f"wrote {CONFIG.name}: protecting {cfg['target']} on {cfg['listen']}")
    say("next:  aegis doctor   then   aegis learn")
    return 0


def cmd_doctor(a) -> int:
    cfg = load_config()
    bad = 0

    def check(ok: bool, what: str, fix: str = "") -> None:
        nonlocal bad
        say(("  ok   " if ok else "  FAIL ") + what + ("" if ok else f"\n         -> {fix}"))
        bad += (not ok)

    say("AEGIS doctor")
    check(sys.version_info >= (3, 10), f"Python {sys.version.split()[0]} (need 3.10+)", "install Python 3.10 or newer")
    check(GATEWAY.exists(), f"gateway binary {GATEWAY.relative_to(ROOT)}", "run the installer (install.sh / install.ps1)")
    check(REPLAY.exists(), f"replay tool {REPLAY.relative_to(ROOT)}", "run the installer (install.sh / install.ps1)")
    check(http_ok(cfg["target"]), f"target {cfg['target']} answers", "start your app, or fix `target` in aegis.json")
    running = owned(read_pids(), "gateway") is not None
    if not running:
        check(port_free(cfg["listen"]), f"listen address {cfg['listen']} is free", "pick another with: aegis init --listen HOST:PORT")
        check(port_free("127.0.0.1:8081"), "admin port 127.0.0.1:8081 is free", "stop whatever uses 8081")
    if cfg["llm"] == "ollama":
        check(http_ok("http://127.0.0.1:11434/api/tags"), "Ollama answers on :11434",
              f"install Ollama (free, ollama.com) and run: ollama pull {cfg['model']}  - or: aegis init --llm none")
    n = log_requests()
    say(f"  info learned so far: {n} logged requests (protect needs >= {MIN_CORPUS_REQUESTS} from >= {MIN_CORPUS_ACTORS} distinct visitors)")
    say("ready" if not bad else f"{bad} problem(s) above")
    return 1 if bad else 0


def _start_gateway(cfg: dict, mode: str, env: dict) -> int:
    if not GATEWAY.exists():
        die("bin/gateway is missing - run the installer first")
    if not port_free(cfg["listen"]):
        die(f"{cfg['listen']} is already in use")
    cmd = [str(GATEWAY), "-listen", cfg["listen"], "-backend", cfg["target"], "-mode", mode,
           "-log", str(REQ_LOG.relative_to(ROOT))]
    pid = spawn(cmd, "gateway", env)
    for _ in range(60):
        if http_ok(ADMIN + "/stats"):
            return pid
        if not alive(pid):
            break
        time.sleep(0.5)
    terminate(pid)
    die("gateway did not start - see logs/gateway.err.log")


def _stop_all() -> None:
    p = read_pids()
    for k in ("controller", "gateway"):         # controller first: it talks to the gateway
        pid = owned(p, k)
        if pid:
            terminate(pid)
        elif p.get(k):
            say(f"note: recorded {k} pid {p[k]} is not an AEGIS process any more; leaving it alone")
    PIDS.unlink(missing_ok=True)


def cmd_learn(a) -> int:
    cfg = load_config()
    if owned(read_pids(), "gateway"):
        die("AEGIS is already running (aegis stop first)")
    private_dir(REQ_LOG.parent)
    pid = _start_gateway(cfg, "detect", child_env())
    PIDS.write_text(json.dumps({"gateway": pid, "mode": "learn", "started": time.time()}), encoding="utf-8")
    say(f"LEARN mode: AEGIS is in front of {cfg['target']} on http://{cfg['listen']}  - it never blocks anything.")
    say("Send your normal traffic through that address (real users, your test-suite, a staging copy).")
    say(f"When `aegis status` shows >= {MIN_CORPUS_REQUESTS} requests, run: aegis protect")
    return 0


def cmd_protect(a) -> int:
    cfg = load_config()
    prev = read_pids()
    if prev.get("mode") == "protect" and owned(prev, "gateway"):
        die("already protecting (aegis status)")
    if owned(prev, "gateway"):
        _stop_all()                              # leave learn mode; the request log is kept
    reqs, actors, attack_like = build_corpus()
    if reqs < MIN_CORPUS_REQUESTS or actors < MIN_CORPUS_ACTORS:
        die(f"not enough learned traffic to judge a rule safe: {reqs} requests from {actors} visitors "
            f"(need {MIN_CORPUS_REQUESTS} from {MIN_CORPUS_ACTORS}). Run `aegis learn` longer. "
            "This check has no override - a gate with nothing to compare against would approve anything.")
    env = child_env()
    gw = _start_gateway(cfg, "enforce", env)
    ctl = [sys.executable, "-I", str(ROOT / "controller" / "loop.py"),
           "--benign-corpus", str(CORPUS), "--benign-actors", str(CORPUS)]
    if cfg["llm"] == "ollama":
        ctl += ["--llm", "ollama", "--model", cfg["model"]]
    cp = spawn(ctl, "controller", env)
    PIDS.write_text(json.dumps({"gateway": gw, "controller": cp, "mode": "protect", "started": time.time()}),
                    encoding="utf-8")
    say(f"PROTECT mode: gateway enforcing on http://{cfg['listen']}, controller watching for campaigns.")
    say(f"Gate evidence: {reqs} learned requests from {actors} visitors. New rules go shadow -> canary -> enforce, "
        "and roll back automatically.")
    if reqs and attack_like / reqs > 0.02:
        say(f"WARNING: {attack_like} of {reqs} learned requests ({100 * attack_like / reqs:.1f}%) carry attack-like "
            "payloads. Learning may have overlapped an attack; rules that would block those requests will be "
            "rejected as 'breaks legitimate traffic'. Re-learn on trusted traffic if that is not what you want.")
    say("Watch it with: aegis status     Events: logs/controller/events.jsonl")
    return 0


def cmd_run(a) -> int:
    """Foreground supervisor for containers / systemd: start learn or protect, block until SIGTERM/SIGINT."""
    (cmd_protect if a.mode == "protect" else cmd_learn)(a)
    stop = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.append(1))
    while not stop:
        p = read_pids()
        if not owned(p, "gateway"):
            say("gateway exited - see logs/gateway.err.log")
            _stop_all()
            return 1
        if p.get("controller") and not owned(p, "controller"):
            say("controller exited: traffic still flows and existing rules stay; restart to resume synthesis")
            p.pop("controller")
            PIDS.write_text(json.dumps(p), encoding="utf-8")
        time.sleep(2)
    _stop_all()
    return 0


def cmd_status(a) -> int:
    p = read_pids()
    gw_up, ctl_up = owned(p, "gateway") is not None, owned(p, "controller") is not None
    if not gw_up:
        say("AEGIS is not running.")
        return 0
    say(f"mode: {p.get('mode')}   gateway: up   controller: {'up' if ctl_up else ('-' if p.get('mode') == 'learn' else 'DOWN (traffic still flows; rules stay as they are)')}")
    say(f"requests logged: {log_requests()}")
    try:
        with urllib.request.urlopen(ADMIN + "/stats", timeout=2) as r:
            st = json.load(r)
        say("gateway stats: " + json.dumps(st)[:600])
    except Exception as e:
        say(f"gateway stats unavailable: {e}")
    ev = ROOT / "logs" / "controller" / "events.jsonl"
    if ev.exists():
        lines = ev.read_text(encoding="utf-8", errors="replace").splitlines()[-5:]
        if lines:
            say("last controller events:")
            for ln in lines:
                say("  " + ln[:200])
    return 0


def cmd_stop(a) -> int:
    if not read_pids():
        say("AEGIS is not running.")
        return 0
    _stop_all()
    say("stopped. (Your app is unchanged and reachable directly - AEGIS only proxied it.)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="aegis", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="write aegis.json and generate secrets")
    p.add_argument("--target", help="URL of the app to protect, e.g. http://127.0.0.1:3000")
    p.add_argument("--listen", help="address AEGIS listens on (default 127.0.0.1:8080)")
    p.add_argument("--llm", choices=["none", "ollama"], help="LLM last-resort path (default none = templates only)")
    p.add_argument("--model", help="Ollama model name")
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("run", help="foreground (containers/systemd): learn or protect until stopped")
    p.add_argument("--mode", choices=["learn", "protect"], default="learn")
    p.set_defaults(fn=cmd_run)
    for name, fn, h in (("doctor", cmd_doctor, "check the install and config"),
                        ("learn", cmd_learn, "observe only; record normal traffic"),
                        ("protect", cmd_protect, "enforce + autonomous rule synthesis"),
                        ("status", cmd_status, "what is running and what it has done"),
                        ("stop", cmd_stop, "stop AEGIS (traffic goes straight to your app again)")):
        sub.add_parser(name, help=h).set_defaults(fn=fn)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
