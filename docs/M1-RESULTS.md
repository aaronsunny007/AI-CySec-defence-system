# M1 — Campaign detection (re-measured 2026-10-11)

Heuristic detector, no ML (`observer/detector.py`), per CLAUDE.md M1 ("heuristics
and clustering first"). Re-measured with `eval/m1_episode.py` after finding that the
first evaluation was flawed (below). **This replaces the original M1 write-up.**

## What was wrong with the first evaluation
1. **Ground truth was the attack tool's user-agent** — attacker-controlled, and the
   very string CRS blocks on (rule 913100). The detector never read the UA, so the
   detection *logic* was unaffected, but the labels were not independent. Ground
   truth is now a range-only `gt_label` set by the range's own clients; attackers
   send a spoofed browser UA.
2. **0/160 benign false flags was luck of the draw.** Re-measured, one benign actor
   *was* flagged (below). The detector's SQLi signature was too loose.
3. **It only asked "was a campaign detected?"**, not "did it name the right attack?".
   Correct attribution is now measured.
4. **The evasion margin was asserted, never measured.** It is now (phase 2).

## Phase 1 — standard campaigns (benign journeys + all 8 campaigns x2, detect mode)

| Campaign | actors | detected | correctly attributed | time-to-detect (s) |
|---|---|---|---|---|
| command_injection | 2 | 2 | 2 | 11.1, 2.1 |
| credential_stuffing | 2 | 2 | 2 | 12.0, 10.6 |
| idor_bola | 2 | 2 | 2 | 9.3, 6.5 |
| path_traversal | 2 | 2 | 2 | 2.4, 2.1 |
| sqli | 2 | 2 | 2 | 4.2, 6.1 |
| ssrf | 2 | 2 | 2 | 0.0, 0.0 |
| user_enumeration | 2 | 2 | 2 | 22.5, 6.6 |
| xss | 2 | 2 | 2 | 2.8, 2.1 |
| **total** | **16** | **16 (100%)** | **16 (100%)** | p50 **6.1 s**, p90 **12.0 s**, within 30 s: **100%** |

Three of these (credential stuffing, IDOR, user enumeration) are the classes CRS
cannot see per request (BASELINE: 0 of their requests blocked, attacker succeeds in
all three).

**False positives on benign actors: 1 of 160 (0.62%) — not the 0/160 first reported.**
The flagged actor was a legitimate user whose 4 requests matched the SQLi signature.
Root cause: the signature treated a bare `--` and a bare `1=1` as SQL. It fired on
ordinary prose ("Arrived late -- but worth it", "Tastes like 1=1 perfect apples")
**and on socket.io session ids, which contain `--`**.

### Fix and re-measurement
Comment markers now count only after a quote or parenthesis; the bare tautology is
dropped (`' OR ...` already covers every attack payload).

| | benign requests matching the SQLi signature (all 443,507) | attack payloads matched (8) |
|---|---|---|
| before | 335 (0.0755%) | 7 / 8 |
| after | **26 (0.0059%)** | **8 / 8** |

Re-scoring the same episode log: 0 of 161 benign actors flagged. **Caveat:** that
episode is the one in which the problem was found, so "0/161" is not held-out
evidence; the corpus-level request match rate is the better number. The remaining
26 matches are strong passwords that happen to contain `'#`. The xss (18) and
traversal (30) signatures also fire on benign requests (reviews containing a literal
`<script>` or `../../`, deliberately in the benign set); a detection needs >= 2 such
requests from one actor, which is what keeps those from becoming campaign flags, but
a user who posts two such reviews would be flagged.

## Phase 2 — slow-and-low evasion (the margin, measured)
The rate-shaped campaigns re-run under the detector's thresholds (stuffing 15 s
between attempts, enumeration 20 s between probes).

| Campaign | what the detector said |
|---|---|
| credential_stuffing (15 s/attempt, 12 requests over 158 s) | flagged, but as **user_enumeration** ("4 distinct accounts probed") — **0 correct attributions**. It evaded its own rule (>= 6 logins/60 s) and the AEGIS rate limit (>5/60 s) |
| user_enumeration (20 s/probe, 8 requests over 115 s) | **nothing detected** (3 probes per 60 s < the threshold of 4) |

**One run each, so this shows the margin exists, not how large it is.** Windowed
thresholds are hand-set (`T` in the detector); an attacker who paces under them is
not slowed. This is the evasion M4's adaptive adversary should exploit and the
defence should be re-tested against.

## Detectors (behavioural; none reads the user-agent or the actor key)
- **injection** (sqli/xss/traversal/cmdi/ssrf): >= 2 requests matching a payload-family signature.
- **credential_stuffing**: >= 6 `POST /rest/user/login` within 60 s.
- **user_enumeration**: >= 4 distinct accounts probed within 60 s.
- **idor_bola**: >= 4 distinct numeric ids walked on one endpoint (not time-windowed).
- **scan**: >= 25 distinct endpoints **and** >= 30% 4xx.

## Limitations
1. **Our own eight campaigns, one run each, one app.** 100% partly reflects that one
   detector was written per attack class that we also wrote. Needs held-out variants.
2. **Hand-set thresholds**, evadable by pacing (phase 2). Never tuned on held-out data.
3. **Actors are separated by a per-client cookie** (`aegis_vid`) standing in for
   distinct source IPs (docs/DECISIONS.md). IP rotation / fingerprint reconstruction
   is not implemented, so an attacker who rotates the identifier is a new actor.
4. **Signature false-match rates** are measured per request on the benign corpus
   (which predates the cookie), not per actor.
5. The detector has no signature for novel classes (SSTI, XXE, NoSQL operators, JNDI)
   and would not flag them; those campaigns are only reachable by the LLM path when a
   dossier is supplied some other way.
