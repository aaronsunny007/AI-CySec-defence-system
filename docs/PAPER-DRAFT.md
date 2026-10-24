# AEGIS: Gating Autonomous Web-Application Defence on Measured Harm

*Draft v0.4 — 2026-10-24 (v0.4 re-measures everything on a 20,262-distinct-request gate corpus with diverse benign sessions, adds lessons 16-19 and an updated ML baseline). Earlier: v0.3 — 2026-10-15. (v0.2, 2026-10-12, added the autonomous closed loop, the adaptive attacker, rule-store hardening, a second target app and a citation check; v0.3 re-measures them with replicates and real-speed attackers and adds an ML-WAF baseline. Four citation discrepancies are listed in `docs/CITATION-CHECK.md`.) Every number below is taken from a results file in this
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
last-resort local-LLM path produced no promotable rule in any of 16 trials (two 7B
models, one-shot and with a feedback repair loop, four novel campaigns); the gate
absorbed all 124 candidates, including one that would have blocked 17% of benign traffic
and two that blocked a whole campaign but were stopped by the mutation stage for
memorising the payload. Wired into one autonomous loop (detect, synthesise, gate, shadow,
canary, enforce, with a signed rule store), AEGIS put a rule in force 59-82 s on average after a
campaign began, in 24 of 24 class-runs over five replicates on Juice Shop and three on a second small
app, with 3 of 138,611 benign requests blocked on Juice Shop (all one generated string) and 0 of
151,995 on the second app. Against a real-speed adaptive attacker that re-encodes payloads and rotates
identity, requests reaching the app fell from 380 to 11 of 400 (SQLi) and 323 to 40 (command
injection); credential stuffing was slowed (400 to 267 guesses reaching the app) but not prevented, and
a short attack that finishes inside the ~1-1.5 minute loop latency is not mitigated. We also report
nineteen measurement and engineering errors we made and corrected, among them attack tools that announce
themselves (inflating a WAF baseline twofold), a `localhost` delay that slowed our own attackers
tenfold, and a benign corpus whose 443,507 rows hold only about 4,100 distinct request shapes.

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
campaigns in a fixed order; it is *not* an adaptive attacker (see 5.11 for one).

### 5.8 Induced self-DoS (`docs/M4-RESULTS.md`)
Adversarial payloads were blended into the strings real users send. The most legitimate
traffic any candidate could force the defender to block was **0.6151%** without the gate
(a "block any apostrophe" rule) and **0.0083%** with it (~74x). The naive rules are ones
we wrote to represent an overfitting responder, not a competing system. Rate limits are
per-actor, so one actor cannot push another over a limit.

### 5.9 Last-resort LLM (`docs/M3-RESULTS.md`)
The model sees only a fixed-vocabulary feature summary and emits only Rule IR (section 3).
We ran Mistral 7B (general) and Qwen2.5-Coder 7B (code-specialised), each one-shot and with a
3-round repair loop that returns the gate's verdict as stage names, numbers and
token-class names (never traffic text), on four campaigns the templates do not cover:
SSTI, NoSQL operators, XXE, JNDI. Fresh memory per run; one sample per cell.

| Model | one-shot | repair x3 |
|---|---|---|
| Mistral 7B | 0 / 4 promoted | 0 / 4 promoted |
| Qwen2.5-Coder 7B | 0 / 4 promoted | 0 / 4 promoted |

**0 of 16 cells promoted a rule.** Of the 124 candidates that reached the gate, 92 (74%)
were safe but ineffective (passed the benign budget, matched too little of the campaign), 26
(21%) matched legitimate traffic (one candidate: **17.16%** of it), 4 failed to load in the
engine, and 2 blocked an entire campaign at an acceptable false-positive rate but failed the
mutation stage because they memorised the payload. In a hand-inspected round the model
re-proposed its own failed regex rather than using the feedback; repair roughly tripled
model time and tokens for no change in outcome. Calls cost ~75-125 s and ~1k-1.5k tokens
each on a laptop GPU.

*Reading this correctly.* The safety property held for every candidate; the capability
question is answered "no" only for these two same-size models given this input. Four
campaigns, one sample each, and a deliberately starved input (the model never sees
payloads) mean this does not show that LLMs cannot synthesise such rules. A larger or API
model was not tested; the next experiments we would run are letting the model choose from a
vetted library of token-class patterns instead of writing regexes, then a larger model.

### 5.10 The whole loop, with nobody in it (`docs/E2E-RESULTS.md`)
A separate controller process tails the gateway log and, with no human action, detects a
campaign, synthesises or recalls a rule, passes it through the gate (offline stages, then 20 s
shadow and 30 s canary at 25% with rollback armed) and enforces it. The rule store was HMAC-signed
and the admin API token-guarded throughout. Real browser journeys plus replayed corpus traffic ran
the whole time; the attacker is a persistent script that takes a fresh identity every few seconds
and connects at real speed. Five replicate range boots on Juice Shop, three on a second app:

| class | app | enforced | detected after onset | **rule enforcing after onset** (mean, 95% CI) |
|---|---|---|---|---|
| command injection (CRS stops 8/12) | Juice Shop | 5/5 | 1.8 s | **58.8 s** (57.4-60.2) |
| credential stuffing (CRS stops 0) | Juice Shop | 5/5 | 17.5 s | **74.1 s** (73.2-74.9) |
| SQLi | Juice Shop | 5/5 | 12.5 s | **81.6 s** (60.7-102.5) |
| SQLi / command injection / stuffing | BookNook | 3/3 each | 1.0-1.4 s | **59.2 / 59.5 / 61.3 s** |

Benign requests blocked by an AEGIS rule: **3 of 138,611** (0.002%; all the same generated string
`may cool mango don't ' and ' --`, blocked by the SQLi rule) on Juice Shop and **0 of 151,995** on
BookNook. This is with a gate corpus of 20,262 distinct benign requests (including generated
awkward-but-legitimate sessions) and background load of the original traffic mix plus diverse sessions.
Memory made the synthesis step orders of magnitude faster on a repeat (e.g. 63 s to 3 ms
for SQLi) but **did not make end-to-end enforcement meaningfully faster**: a reused rule still passes
shadow and canary (~57 s), and one live pipeline runs at a time, so campaigns queue. The loop needed
several rounds of live debugging that offline experiments had not exposed (section 6, items 7-14, 17, 19).

### 5.11 An adaptive attacker (`docs/M4-RESULTS.md`)
A red agent that sees only HTTP status codes re-encodes payloads, rotates identity, slows down and
learns the rate-limit quota; budget 400 requests, one run per cell, same seed in both arms.

| goal | requests reaching the app: CRS only | closed loop | identities used (closed) | valid logins harvested (CRS only / closed) |
|---|---|---|---|---|
| SQLi | 380 / 400 | **11 / 400** | 66 | n/a (never met in either arm) |
| command injection | 323 / 400 | **40 / 400** | 58 | n/a (no sink) |
| credential stuffing | 400 / 400 | 267 / 400 | 35 | **2 / 1** |

The observer flagged every identity in the stuffing run (35/35), 65 of 66 in SQLi and 48 of 58 in
command injection; the first AEGIS block came at request 98, 32 and 49 of 400. SQLi and command
injection are largely stopped (97% and 88% of requests did not reach the app). Stuffing is slowed, not
stopped: the attacker still found one valid login before the rule landed, a per-identity rate limit
only throttles, and an attack short enough to finish before the ~1-1.5 minute loop latency is
unmitigated in both arms. An earlier, slower-client version of this experiment reported the opposite
for stuffing (section 6, item 13), and a first closed-loop batch of these runs mitigated nothing in
command injection because of a flawed canary check (item 19); those runs are superseded. Benign
requests blocked by an AEGIS rule across the three closed-loop runs: **0 of 225,558**.

### 5.12 A second target app (`docs/E2E-RESULTS.md`)
BookNook is a small deliberately vulnerable stdlib-Python app with different paths, parameter names
and a simulated command sink, with its own 30,011-request benign corpus. Nothing was retuned for it,
but the first run failed on SQLi: the detector hard-coded Juice Shop's login URL, and the SQLi
template flagged a benign review `'quoted' and "double"` (0.60% of that corpus). After fixing both
(generic login detection; a real comparison required after `and`/`or`), all three classes were
mitigated in 3/3 replicates. This is a self-built second app: it shows the pipeline is not
hard-wired to one app's URLs, not that it generalises to real ones (DVWA was not run: it needs
PHP/MySQL downloads).

### 5.13 A static ML-WAF baseline (`docs/ML-BASELINE.md`)
A hashed n-gram logistic regression trained once offline on benign requests (20,262 distinct) plus
generated attack variants, thresholded to our 0.01% false-positive budget (measured 0.012% of raw rows
on the test split). It detects 0% / 0% of the real SQLi / XSS campaign requests, 80% / 0% / 80% of
traversal / command-injection / SSRF, 0% of four families it never saw, and **0% of the three
behavioural campaigns** (each request looks normal). The baseline is crude (generated training
data, one configuration) and must not be read as a claim that AEGIS beats a good ML-WAF; it
illustrates the structural gap that per-request models cannot see campaign-level attacks, and that a
diverse benign corpus makes a fixed false-positive budget much stricter on them.

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

7. **A template that could never match, invisible until it ran live (2026-10-12).** All three
   command-injection templates blocked 0% of `; cat /etc/passwd`: ModSecurity's `cmdLine`
   transform deletes `;` before the regex runs. Offline experiments never gated command
   injection on captured evidence. The first end-to-end run found it; the gate rejected all
   three (correct) and nothing was enforced until the templates were fixed.
8. **A percentage false-positive budget cannot say "never this user".** `aegis-sqli-3` met the
   0.01% budget (0.0045%, 20 of 443,507) and still blocked, 14 times in a 576k-request live run,
   one real user's password `7ggq|;]3,p'#` (a quote followed by `#`). All 20 corpus matches were
   that one user. Fixed in the rule (0 of 443,507 afterwards) and by a new gate stage that
   replays a file of known-harmful-to-block benign requests with zero tolerance.
9. **The live false-positive judge was blind to identity rotation.** It counted matches on
   observer-unflagged actors as false positives; an attacker's two-request second identity is
   never flagged, so a correct rule was rejected in shadow. Matches on actors with fewer than
   three requests are now reported as *indeterminate* (and capped), not as false positives.
10. **The canary's error-rate comparison false-alarmed.** Two groups of different actors,
    clustered traffic, checked every two seconds: an unmodified rate rule was rolled back at
    z=3.0 (9.1% vs 4.6% 5xx). It now needs significance and is retried once; suspected-FP
    rollbacks stay final.
11. **Operational errors were treated as verdicts, and an attacker could starve the budget.** A
    404 from the admin API blacklisted a rule; every rotated attacker identity consumed the
    campaigns-per-hour budget. Both fixed.
12. **A laptop suspend produced a plausible-looking failed run** (65 minutes with no requests in
    the gateway log). The harness now reports log gaps.

13. **Our own attackers were ten times slower than configured.** The attack and benign clients
    connected to `localhost`, which on this Windows machine costs ~2 s per new connection (IPv6
    refused, then fallback). Attackers ran at ~0.4 req/s, which made every "requests that got through"
    count a lower bound and, with a slow attacker, even flipped the stuffing conclusion. Found only
    because a replay driver that used `127.0.0.1` ran faster. Clients now use `127.0.0.1` with a
    browser Host header.
14. **Three more live-loop bugs that only real-speed attackers exposed.** The shadow stage counted
    requests that arrived before the new rule had loaded, so a correct rule failed its
    live-versus-replay agreement check; the "rule bypassed" test counted an attacker's pre-enforcement
    history; and a single campaigns-per-hour budget was exhausted by ~190 false alarms on synthetic
    users, so a real SQLi campaign was never handled in one replicate (budget is now per technique).
15. **The benign corpus is far less diverse than its row count.** 443,507 rows, but 62,162 distinct
    `(method, URI, body)` triples, 58k of them unique `/socket.io` polls; excluding those, only
    4,101 distinct requests, with the top 100 making up 83% of rows. Every false-positive rate in
    this paper is measured on those request shapes. (Found while building the ML baseline.)
16. **A more diverse benign corpus broke the templates, as it should.** We generated persistent
    sessions with awkward-but-legitimate input (passwords with quotes and pipes, SQL words in
    reviews, addresses, unicode, long text) and combined them with the original corpus into a gate
    corpus of 20,262 *distinct* requests (a separate 33k-distinct stress corpus is kept apart,
    because part of it is word-salad that a generator, not a user, would write). Measured on it,
    the first-draft templates matched 0.2-0.3% of benign requests (SQLi-1, cmdi-2) and traversal,
    command-injection and SQLi templates had to be rewritten (real traversal sequences, command
    word lists, a comment branch, double URL-decoding). Rules that survive both corpora are the
    ones the gate now admits; the audit is in `docs/data/fp_audit.txt`.
17. **Making the cooldown smarter flooded the controller.** Keying the cooldown on payload
    fingerprints stopped a false alarm from locking out a real campaign, but meant every
    look-alike false alarm ran the whole gate again. With a login/registration-heavy replay as
    background load, 450-600 false triggers per run starved the real campaigns: SQLi was enforced in
    0 of 5 runs and stuffing in 1 of 5. Three fixes together: gate replay results are cached by
    (rule text, corpus identity), campaigns are handled strongest-evidence-first, and the background
    load is the original traffic mix plus diverse sessions rather than a replay of the
    input-heavy corpus. The 3-replicate verification afterwards: 9/9 class-runs enforced, 0 of
    59,869 benign requests blocked, 43-56 false triggers per run (105-126 in later runs).
18. **Throttles on a controller are part of the attack surface.** Budgets that were right for a
    quiet system (60 campaigns/hour) were exhausted by false alarms alone; they are now a CPU safety
    valve (600/hour, 200 per technique), not the throttle. Prioritising by evidence is what keeps
    the real attack from waiting.
19. **The canary's latency check measured the app's long-polls.** It compared p99 latency between the
    canary and control slices from the gateway's counters. Juice Shop holds `/socket.io` polling
    requests open for about 25 s by design, so whichever slice contained a few of them "regressed" by
    3-4x. In the adaptive runs five canaries in a row rolled back rules that had blocked nothing, and
    command injection was never mitigated in one run; the replicate runs had 196 s outliers for the
    same reason. It was only visible once the background load contained enough browser clients.
    The check now computes p99 from the request log with long-poll requests excluded, with a unit
    test. A related harness lesson: a laptop suspend of ~15 h hid inside one adaptive run, caught only
    because the harness reports log gaps; that run was repeated.

## 7. Threats to validity and limitations
One main application (plus one small self-built second app), eight attack classes we wrote, one
laptop, five or three replicates for the end-to-end timings and single runs for the adaptive attacker; percentages over 8 campaigns move in 12.5-point steps. Actors are separated by
a per-client cookie standing in for source IPs, so IP rotation is unhandled (the adaptive attacker in 5.11 exploits exactly this). The behavioural
detector's thresholds are hand-set and evadable by pacing. Shadow and canary use the
behavioural detector as the false-positive oracle, so a wrongly flagged benign actor would
hide its false positives. Canary traffic is replayed corpus requests, 60 req/s, windows of
45-60 s. Signing the manifest and authenticating the admin API are implemented and were on in the final
measurements (docs/HARDENING.md). The controller runs one live
pipeline at a time (~57 s each), so campaigns queue. The benign corpus predates actor
separation; the gate corpus is 20,262 distinct requests, partly generated by us, so "no false positives"
means on those shapes (3 of 138,611 live benign requests were still blocked, all one generated string). The adaptive attacker (5.11) is one simple ladder, one seed, one run per cell.

## 8. Future work
A stronger adaptive adversary (probing rule boundaries; pacing under thresholds from the start); actor linkage beyond a cookie (IP/ASN/TLS fingerprint on a real deployment); held-out attack
variants; for the LLM path, a vetted-pattern-library interface (the model chooses token
classes, we compile the regex) and then larger/API models; DVWA (needs PHP/MySQL downloads) in addition to the BookNook second app (5.12); a campaign stream to measure the
fraction of campaigns reaching the LLM.

## 9. Reproducibility
Repository: https://github.com/aaronsunny007/AI-CySec-defence-system (MIT). Everything runs
natively on Windows, no Docker/WSL. Commands are in `README.md`; results in
`docs/BASELINE.md`, `M1-RESULTS.md`, `M2-RESULTS.md`, `M2-LIVE-STAGES.md`, `M3-RESULTS.md`,
`M4-RESULTS.md`, `E2E-RESULTS.md`, `HARDENING.md`, `CITATION-CHECK.md`; decisions in `docs/DECISIONS.md`. The benign corpus (~260 MB) is regenerated
by `range/benign/generate.py`. Tests: `python -m unittest discover -s tests` (68) and
`go test ./...` in `gateway/`. Versions: Go 1.27.2, Coraza 3.8.1, CRS 4.25, Juice Shop
20.2.0, Ollama 0.40.2, Mistral 7B Q4_K_M.
