#!/usr/bin/env python3
"""Record a command as an asciicast v2 file (the format asciinema plays) from a real pseudo-terminal.

    python demo/record.py demo/aegis-demo.cast -- python demo/run_demo.py

The bytes in the file are exactly what the program wrote to its terminal, with real timestamps. Stdlib only.
"""

from __future__ import annotations

import codecs
import fcntl
import json
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time


def record(cmd: list[str], out: str, cols: int = 104, rows: int = 34, title: str = "AEGIS in about a minute") -> int:
    master, slave = pty.openpty()
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    env = dict(os.environ, TERM="xterm-256color", PYTHONUNBUFFERED="1", COLUMNS=str(cols), LINES=str(rows))
    t0 = time.time()
    proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True, close_fds=True)
    os.close(slave)
    dec = codecs.getincrementaldecoder("utf-8")("replace")
    events: list[list] = []
    while True:
        r, _, _ = select.select([master], [], [], 0.2)
        if r:
            try:
                data = os.read(master, 8192)
            except OSError:
                break
            if not data:
                break
            text = dec.decode(data)
            if text:
                events.append([round(time.time() - t0, 3), "o", text])
        elif proc.poll() is not None:
            break
    rc = proc.wait()
    header = {"version": 2, "width": cols, "height": rows, "timestamp": int(t0),
              "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"}, "title": title}
    with open(out, "w", encoding="utf-8") as f:
        f.write(json.dumps(header) + "\n")
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"recorded {len(events)} frames, {events[-1][0] if events else 0:.1f}s, exit {rc} -> {out}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    if "--" not in sys.argv or len(sys.argv) < 4:
        sys.exit("usage: record.py OUT.cast -- COMMAND [ARGS...]")
    i = sys.argv.index("--")
    sys.exit(record(sys.argv[i + 1:], sys.argv[1]))
