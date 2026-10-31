"""Did the 2026-10-31 security review change what the observer and rule templates do on real traffic?

Two behaviour-affecting edits were made: the observer's SQLi pattern (bounded quantifiers) and rule template 3
(a function call after quote+and/or). This loads the PRE-review versions straight from git and runs old and new
through the same data, so any difference is visible and explainable:

  1. observer SIGS, per family, on a benign corpus and on attack payloads (+ their mutations)
  2. benign actors the full detector flags (the M1 false-alarm metric), old vs new
  3. template 3 through the real Coraza engine (bin/replay) on the benign corpus and on attack payloads

    python eval/review_compare.py --corpus data/benign_corpus/benign_diverse_detect.jsonl --base c47c8da \
        --out docs/data/review-remeasure/compare.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "observer"))
sys.path.insert(0, str(ROOT / "ir"))
sys.path.insert(0, str(ROOT / "range" / "mutate"))
sys.path.insert(0, str(ROOT / "deliberator"))
import actors as actors_mod                # noqa: E402
import compile as irc                      # noqa: E402
import detector as new_det                 # noqa: E402
import generate as new_gen                 # noqa: E402

REPLAY = ROOT / "bin" / ("replay.exe" if sys.platform == "win32" else "replay")


def git_show(rev: str, path: str) -> str:
    return subprocess.run(["git", "show", f"{rev}:{path}"], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def load_old(rev: str, tmp: Path):
    """The pre-review detector and template generator, loaded from a throw-away copy of the tree."""
    (tmp / "observer").mkdir(parents=True)
    (tmp / "deliberator").mkdir()
    (tmp / "data").mkdir()
    (tmp / "observer" / "detector.py").write_text(git_show(rev, "observer/detector.py"), encoding="utf-8")
    shutil.copy(ROOT / "observer" / "actors.py", tmp / "observer" / "actors.py")
    shutil.copy(ROOT / "data" / "idor_ceilings.json", tmp / "data" / "idor_ceilings.json")
    (tmp / "deliberator" / "generate.py").write_text(git_show(rev, "deliberator/generate.py"), encoding="utf-8")

    def load(name, file):
        spec = importlib.util.spec_from_file_location(name, file)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod
    sys.path.insert(0, str(tmp / "observer"))
    old_det = load("detector_old", tmp / "observer" / "detector.py")
    old_gen = load("generate_old", tmp / "deliberator" / "generate.py")
    sys.path.remove(str(tmp / "observer"))
    return old_det, old_gen


def decoded(rec: dict) -> str:
    uri = rec.get("uri", "") or ""
    path, _, query = uri.partition("?")
    return urllib.parse.unquote_plus(query + " " + (rec.get("body", "") or "")) + " " + urllib.parse.unquote_plus(path)


def attack_payload_requests() -> list[dict]:
    """Attack requests: the repo's payload definitions plus their mutations (encoding, case, comments, ...)."""
    import mutate as mut
    reqs: list[dict] = []
    for f in sorted((ROOT / "data" / "attack_corpus").glob("*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        items = d.get("requests") if isinstance(d, dict) and "requests" in d else None
        if items is None and isinstance(d, dict):
            for fam, lst in d.items():
                if isinstance(lst, list):
                    for p in lst:
                        reqs.append({"family": fam, "method": "GET", "uri": "/search?q=" + urllib.parse.quote(str(p)),
                                     "body": "", "content_type": "", "malicious": True})
        elif items:
            for r in items:
                reqs.append({**r, "family": f.stem, "malicious": True})
    base = [dict(r) for r in reqs]
    try:
        reqs += [dict(m, family=b.get("family")) for b in base for m in mut.mutate_corpus([b])]
    except Exception as e:                                                 # mutation is a bonus, not required
        print("mutation skipped:", e, file=sys.stderr)
    return reqs


def replay_matches(rule: str, requests: list[dict]) -> int:
    with tempfile.TemporaryDirectory() as td:
        rf, cf = Path(td) / "r.conf", Path(td) / "c.jsonl"
        rf.write_text(rule, encoding="utf-8")
        cf.write_text("\n".join(json.dumps({"method": r.get("method", "GET"), "uri": r.get("uri", ""),
                                            "body": r.get("body", ""), "content_type": r.get("content_type", "")})
                                for r in requests), encoding="utf-8")
        out = subprocess.run([str(REPLAY), "-rule", str(rf), "-corpus", str(cf)], capture_output=True, text=True)
    return json.loads(out.stdout.strip().splitlines()[-1])["matched"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--base", default="c47c8da", help="git revision holding the pre-review code")
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args()

    benign = [json.loads(l) for l in a.corpus.open(encoding="utf-8") if l.strip()]
    attacks = attack_payload_requests()
    res: dict = {"corpus": str(a.corpus), "benign_requests": len(benign), "attack_requests": len(attacks), "base": a.base}

    with tempfile.TemporaryDirectory() as td:
        old_det, old_gen = load_old(a.base, Path(td))

        # 1. observer signatures, per family
        fams = {}
        for fam in new_det.SIGS:
            row = {}
            for label, reqs in (("benign", benign), ("attack", attacks)):
                o = [bool(old_det.SIGS[fam].search(decoded(r))) for r in reqs]
                n = [bool(new_det.SIGS[fam].search(new_det.cap(decoded(r)))) for r in reqs]
                row[label] = {"old": sum(o), "new": sum(n), "only_old": sum(x and not y for x, y in zip(o, n)),
                              "only_new": sum(y and not x for x, y in zip(o, n)),
                              "examples_only_old": [reqs[i].get("uri", "")[:110] for i, (x, y) in enumerate(zip(o, n)) if x and not y][:3],
                              "examples_only_new": [reqs[i].get("uri", "")[:110] for i, (x, y) in enumerate(zip(o, n)) if y and not x][:3]}
            fams[fam] = row
        res["observer_signatures"] = fams

        # 2. benign actors the whole detector flags
        path = a.corpus
        acts = actors_mod.reconstruct(path)
        big = [x for x in acts.values() if len(x.requests) >= 3]
        old_flag = {x.key for x in big if old_det.detect(x)}
        new_flag = {x.key for x in big if new_det.detect(x)}
        res["benign_actors_flagged"] = {"actors_judged": len(big), "old": len(old_flag), "new": len(new_flag),
                                        "only_new": sorted(new_flag - old_flag)[:10], "only_old": sorted(old_flag - new_flag)[:10]}

        # 3. template 3 through the real engine
        dossier = {"attack_class": "sqli", "endpoints": ["/rest/products/search"], "techniques": ["sqli"], "actor": "x", "n_requests": 5}
        t3 = {}
        for label, gen in (("old", old_gen), ("new", new_gen)):
            cand = next(c for c in gen.candidates_for("sqli", dossier) if c["id"] == "aegis-sqli-3")
            unscoped = {k: v for k, v in cand.items() if k != "scope"}
            rule = irc.compile_rule(unscoped, deny=True)
            sql_attacks = [r for r in attacks if "sql" in str(r.get("family", "")).lower() or r.get("family") in (None, "sqli")]
            t3[label] = {"benign_matched": replay_matches(rule, benign), "benign_total": len(benign),
                         "sqli_attack_matched": replay_matches(rule, sql_attacks), "sqli_attack_total": len(sql_attacks),
                         "all_attack_matched": replay_matches(rule, attacks), "all_attack_total": len(attacks)}
        res["template_3"] = t3

    print(json.dumps(res, indent=2))
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(res, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
