# Static ML-WAF baseline (spec baseline 3)

Script `eval/ml_baseline.py`, output `docs/data/ml_baseline.txt` / `.json` (re-run 2026-10-24 on the
combined 20,262-distinct-request benign corpus). A hashed character-n-gram logistic regression (numpy
only), trained once offline on benign requests from our corpus plus a *generated* attack set (800
variants per class from a small grammar: SQLi, XSS, command injection, traversal, SSRF), with the
threshold set on a separate benign validation split so that at most **0.01 % of raw benign rows** are
flagged (AEGIS's budget). On the test split it flagged **0.0120 %** of raw rows (0.01 % of distinct
requests), i.e. the budget is slightly exceeded out of sample.

| what is tested | detected at that threshold |
|---|---|
| held-out generated variants: SQLi / XSS / cmdi / traversal / SSRF | 29 % / 72 % / 64 % / 91 % / 73 % |
| the REAL campaign requests our scripts send: SQLi / XSS / traversal / cmdi / SSRF | **0 %** / **0 %** / 80 % / **0 %** / 80 % |
| ...their mutants (SQLi / XSS / traversal / cmdi / SSRF) | 0 % / 0 % / 100 % / 0 % / 60 % |
| four families never trained: SSTI / NoSQL / XXE / JNDI | 0 % / 0 % / 0 % / 0 % |
| behavioural campaigns, per request: stuffing / IDOR / enumeration | **0 % / 0 % / 0 %** |

At a looser threshold (0.1 % FP) the real command-injection requests rise to 8 %, XXE to 67 % and IDOR to
42 %, still nothing on stuffing or enumeration. Compared with the earlier run on a 4.1k-request benign
side, a diverse benign corpus makes the same budget much stricter: real command injection fell from 50 %
to 0 % and the unseen families from 0-67 % to 0 %.

**Reading it honestly.** This is a crude baseline: the training attacks come from my own generator
(a public labelled corpus such as CSIC-2010 would need a download), one configuration, no tuning,
and the benign side is 20,262 distinct request shapes (the earlier run had only 4.1k; `E2E-RESULTS.md`). It detected 0 % of the
real SQLi and XSS campaign requests even though it handled held-out generated variants of those
classes, which says more about my generator than about ML-WAFs in general. What it does show is the
structural point: a per-request classifier trained before the attack cannot see the behavioural
campaigns at all (every request is individually normal) and partly misses unseen families, whereas
AEGIS learns a rule from the campaign itself, at the cost of the 1-1.5 minutes the first exposure takes.
It is not a claim that AEGIS beats a good ML-WAF. A stronger baseline remains to be built.
