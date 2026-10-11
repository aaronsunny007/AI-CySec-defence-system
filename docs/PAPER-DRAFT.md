# AEGIS: Gating Autonomous Web-Application Defence on Measured Harm

*Draft v0.1 — 2026-10-11. Every number below is taken from a results file in this
repository (linked in section 9) and was produced by a script in `eval/`. Citations
use the numbering of the PRD bibliography and **must be verified against the originals
before submission** (PRD section 0).*

## Abstract

An autonomous defender is deployable not when its detection is accurate but when the
mitigations it invents can be shown, automatically and before enforcement, not to harm
the application it protects. We build AEGIS, an open, emulated range (OWASP Juice Shop
behind a Go/Coraza gateway, a 443,507-request benign corpus from 10,379 real browser
journeys, and eight scripted attack campaigns) and a six-stage validation gate for
synthesised web-application rules. Against attackers that spoof a browser user-agent,
untuned OWASP CRS contains 2 of 8 campaigns, lets the attacker meet their objective in 3
of 8, and wrongly blocks 4.0% of benign requests while breaking 5.0% of legitimate user
journeys. A gate that replays each candidate against the full benign corpus promoted a
SQLi rule at 0.0045% false positives and a traversal rule at 0.0000%, rejected the weaker
candidates, and cut the legitimate traffic an adversary could force the defender to block
from 0.62% (an ungated "block any apostrophe" rule) to 0.008%. A live shadow and canary
stage with automatic rollback rejected an overfit rule in shadow and rolled back a
fault-injected one in 0.02 s, though only after it had blocked 4 legitimate requests. A
last-resort local-LLM path produced no promotable rule in our trials; the gate absorbed
every candidate, including one that would have blocked 17% of benign traffic. We also
report five measurement errors we made and corrected, one of which (attack tools that
announce themselves) inflated a WAF baseline by a factor of two.

## 1. Introduction

Autonomous cyber defence has been demonstrated at scale for source-code patching
(DARPA AIxCC [9][10]) and studied extensively in simulation (CAGE/CybORG [13]), yet a
2025 systematic review finds every environment in the literature is a simulation, with
no open emulated or real-world gym, and names the lack of realistic environments as the
first barrier to deployment [7]. Commercial autonomous responders are held back less by
detection quality than by trust in their actions [17][18]. We target the web-application
layer, where real traffic, real payloads and a real enforcement point exist, and make the
*proof of non-harm* the centre of the system rather than an afterthought.

**Contributions (each scoped to what we measured):**
1. An open, reproducible range with a 443,507-request benign corpus that deliberately
   includes weird-but-legitimate input (SQL words in free text, HTML in reviews, unicode
   names, long inputs, mobile and slow clients).
2. A six-stage gate whose offline stages replay candidates through the *real* Coraza engine,
   and whose live stages (shadow, canary with automatic rollback) run on a hot-reloadable
   gateway with per-rule modes.
3. A measurement of how much legitimate traffic an adversary can force the defender to
   block, with and without the gate (section 5.8).
4. Negative and corrective results: a local-LLM synthesiser that did not produce a
   promotable rule, a rate limit that throttles rather than prevents, and the
   methodology errors in section 6.

**Non-goals.** No offensive action; no source-code patching; one application; no claim
about unrecognised single requests (campaigns only).

## 2. Related work
See PRD section 2 for the annotated review; the positioning is: AICA [1] and MAPE-K [5]
as architecture; AIxCC [9] for the lesson that engineering reliability beats algorithmic
novelty (our budgets, fail-open and hot-reload stress test follow from it); CAGE [13] for
the idea of penalising the defender for harming legitimate ("green") users, which we
measure with real user journeys rather than simulated ones; C-MADF [26] as the closest
gated-execution design (gating on a computed score rather than empirical replay); Cloudflare's
inline ML [16] for the latency budget.

## 3. System

Five planes on two timescales. **Enforcement** (microseconds, inline): a Go reverse proxy
embedding Coraza 3.8.1 and OWASP CRS 4.25, plus AEGIS rules with per-rule modes
`off | shadow | canary(x%) | enforce`, hot-reloaded from a manifest by atomic swap of an
immutable rule set. **Observation**: actor reconstruction and a behavioural campaign
detector. **Deliberation**: template synthesis, with a local LLM only as last resort.
**Validation gate**. **Memory**: SQLite, with reuse / generalise / fresh paths.

*Invariants enforced in code:* fail open (a failed reload keeps the old rules); the LLM is
unprivileged — it sees a fixed-vocabulary feature summary, never raw traffic, and emits
only typed Rule IR, which a validating compiler turns into a SecRule; no rule reaches
`enforce` without passing every stage; hard budgets (new rules per hour, LLM calls per
hour, tokens, candidates).

*Gate stages.* (1) replay against the benign corpus, reject above 0.01% FP; (2) replay
the observed campaign, require full block; (3) live regression A/B against CRS-only;
(4) mutation test — encodings, casing, comments, whitespace, and for traversal path
encodings — requiring >= 80% of mutants blocked; (5) shadow on live traffic, with
suspected false positives judged by the behavioural detector and live match counts
required to equal the replay engine's prediction; (6) canary with rollback on suspected-FP
blocks, 5xx regression or p99 regression.

## 4. Experimental setup
Target OWASP Juice Shop 20.2.0; Go 1.27.2; Coraza 3.8.1; CRS 4.25, paranoia 1, untuned.
One Windows laptop (15.8 GB RAM, 4 GB GPU), no cloud. Benign traffic: Playwright, 11
journey types, random personas. Attacks: eight campaigns (SQLi, XSS, path traversal,
command injection, SSRF, user enumeration, IDOR/BOLA, credential stuffing), each a
progressing recon-to-exploit sequence from one actor, plus four *novel* campaigns the
templates do not cover (SSTI, NoSQL operators, XXE, JNDI). Attackers send a spoofed
browser user-agent (section 6). Ground truth for evaluation is a range-only label set by
the range's own clients; no detector, gate or rule reads it.

## 5. Results

### 5.1 Baseline: OWASP CRS alone (`docs/BASELINE.md`)
| | spoofed-browser attackers (headline) | announced-scanner attackers |
|---|---|---|
| Campaigns contained | **2 / 8** | 4 / 8 |
| Malicious requests blocked | **30 / 64 (46.9%)** | 35 / 64 (54.7%) |
| Attacker objective met | **3 / 8 (38%)** | 3 / 8 (38%) |
| Harmless recon blocked | 1 / 19 | 9 / 19 |

CRS misses entirely the three classes that look normal per request — credential stuffing,
IDOR/BOLA, user enumeration (0 blocked; the attacker succeeds in all three). On benign
traffic: **4.011%** of 443,507 requests would be blocked (0.277% excluding the socket.io
push channel; budget 0.01%), **5.0%** of 300 live journeys broken (15), WAF p99 **14.2 ms**
(budget 1 ms).

### 5.2 Campaign detection (`docs/M1-RESULTS.md`)
16 of 16 attack actors detected and 16 of 16 *correctly attributed* (p50 6.1 s, p90 12.0 s,
all within 30 s) — including the three classes CRS cannot see. One of 160 benign actors
was false-flagged (a too-loose SQLi signature); narrowing it cut benign request matches
from 0.0755% to 0.0059%. Slow-and-low pacing evades: 20 s-spaced enumeration was not
detected at all and 15 s-spaced stuffing was caught only as the wrong technique.

### 5.3 Offline gate on signature rules
SQLi: of three candidates the gate rejected the broad `detectSQLi` rule (62% of the
campaign, 0.0083% FP) and the endpoint-scoped one (12%), and promoted a comment-tolerant
regex: **100% of the campaign (24/24), 87% of 138 mutants, 0.0045% FP** (20 of 443,507).
Path traversal: promoted at **100% of the campaign, 100% of 84 path-encoding mutants, 0
FP**; a stricter candidate was rejected at 80% coverage.

### 5.4 Rate limits (`docs/M2-RESULTS.md`)
The gate chose `>5 logins / 60 s` (0/122 benign actors rate-limited, 2/2 stuffing actors
rate-limited) over `>10 / 60 s` (too loose). In a live A/B with the rule hot-loaded in
0.53 s: requests blocked 0/12 -> 5/12, but valid credentials found only **3 -> 1**. The
rate limit **throttles; it does not prevent**, and it is keyed on the actor identifier, so
rotating that identifier defeats it.

### 5.5 Live stages (`docs/M2-LIVE-STAGES.md`)
| | outcome |
|---|---|
| Good rule | shadow: 2,460 requests, 0/2,440 suspected FPs, **live matches 16 = replay-predicted 16**; canary 60 s at 25%: no regression -> promoted |
| Overfit rule (any `'`) through the pipeline | rejected at shadow: 16/2,447 suspected FPs |
| Overfit rule fault-injected straight into canary | rolled back after **53.8 s**; rollback call **0.02 s**; **4 legitimate requests blocked** of 2,301 first |

The 53.8 s and the 4 blocked requests are the honest cost of canarying a rule that matches
~0.6% of benign traffic on 25% of actors.

### 5.6 Hot reload
48 live manifest reloads under 8 keep-alive client threads: 1,382 requests, **0 failed**;
reload p50 506 ms; a corrupt manifest (a rule smuggling `allow`) was refused and the
previous rules kept enforcing.

### 5.7 Memory and the arms race (`docs/M3-RESULTS.md`, `docs/M4-RESULTS.md`)
Across five shifting moves from empty memory, all five were mitigated; first exposures
took 19-52 s (dominated by the 443k-request replay), a SQLi variant was generalised in
142 ms and an exact repeat reused in 3.2 ms (~490x faster). This replays recorded
campaigns in a fixed order; it is *not* an adaptive attacker.

### 5.8 Induced self-DoS (`docs/M4-RESULTS.md`)
Adversarial payloads were blended into the strings real users send. The most legitimate
traffic any candidate could force the defender to block was **0.6151%** without the gate
(a "block any apostrophe" rule) and **0.0083%** with it (~74x). The naive rules are ones
we wrote to represent an overfitting responder, not a competing system. Rate limits are
per-actor, so one actor cannot push another over a limit.

### 5.9 Last-resort LLM (`docs/M3-RESULTS.md`)
Local Mistral 7B (Q4_K_M) on a novel SSTI campaign, three calls: 15 candidates, **0
promoted**. Failures were wrong tool for the class, under-coverage (best candidate 6/12 of
the campaign) and over-matching (one candidate matched **17.16%** of benign traffic). Calls
cost ~75-86 s and ~1.2k tokens each. *[Model-size and repair-loop ablation: pending; see
`docs/M3-RESULTS.md` when complete.]*

## 6. Methodology errors we made, and what they taught
These are reported because each would have flattered the system, or hidden a weakness,
had it gone uncaught.
1. **Self-announcing attackers inflated the WAF baseline.** Our attack tools sent
   `sqlmap`/`Nuclei` user-agents; CRS rule 913100 blocks *any* request from them, so the
   first baseline ("4/8 contained, 55% blocked") partly measured "CRS read the name tag".
   Spoofed attackers: 2/8, 47%. Caught because harmless recon requests were being blocked.
2. **A mis-scripted attack understated attacker success.** The IDOR campaign logged in as
   an account it never registered, so its objective could never be met; attacker success
   was reported as 25% when it was 38%.
3. **A mislabelled request distorted a gate result.** A plain file read was labelled
   "path traversal", demanding a block no traversal rule should deliver.
4. **A zero false-positive result was luck.** 0/160 benign actors flagged did not survive a
   fresh episode; the signature matched prose and socket.io session ids.
5. **We overclaimed on rate limiting** ("stops credential stuffing") until a live A/B showed
   the attacker still found a valid credential.
6. **Engineering found by stress, not inspection:** AEGIS rules loaded after CRS never saw
   CRS-blocked requests (shadow counts would under-count); a Windows rename race broke
   manifest swaps; a model-written value with a newline could have started a second
   directive (closed in the compiler, tested adversarially).

## 7. Threats to validity and limitations
One application, eight attack classes we wrote, one laptop, single runs for most
experiments; percentages over 8 campaigns move in 12.5-point steps. Actors are separated by
a per-client cookie standing in for source IPs, so IP rotation is unhandled. The behavioural
detector's thresholds are hand-set and evadable by pacing. Shadow and canary use the
behavioural detector as the false-positive oracle, so a wrongly flagged benign actor would
hide its false positives. Canary traffic is replayed corpus requests, 60 req/s, windows of
45-60 s. The admin API is unauthenticated (loopback) and the manifest is unsigned. The
canary monitor handles one canary rule at a time. The benign corpus predates actor
separation. Induced self-DoS was measured against rules we wrote, not against a live
adaptive attacker; an attacker adapting to AEGIS's rules is untested.

## 8. Future work
Adaptive adversary (pacing under thresholds, identifier rotation); held-out attack
variants; a repair loop and larger/code-specialised models for the LLM path; DVWA for
cross-application generalisation; signed manifests; a campaign stream to measure the
fraction of campaigns reaching the LLM.

## 9. Reproducibility
Repository: https://github.com/aaronsunny007/AI-CySec-defence-system (MIT). Everything runs
natively on Windows, no Docker/WSL. Commands are in `README.md`; results in
`docs/BASELINE.md`, `M1-RESULTS.md`, `M2-RESULTS.md`, `M2-LIVE-STAGES.md`, `M3-RESULTS.md`,
`M4-RESULTS.md`; decisions in `docs/DECISIONS.md`. The benign corpus (~260 MB) is regenerated
by `range/benign/generate.py`. Tests: `python -m unittest discover -s tests` (18) and
`go test ./...` in `gateway/`. Versions: Go 1.27.2, Coraza 3.8.1, CRS 4.25, Juice Shop
20.2.0, Ollama 0.40.2, Mistral 7B Q4_K_M.
