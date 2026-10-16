# Static ML-WAF baseline (spec baseline 3)

Script `eval/ml_baseline.py`, output `docs/data/ml_baseline.txt` / `.json`. A hashed character-n-gram
logistic regression (numpy only), trained once offline on benign requests from our corpus plus a
*generated* attack set (800 variants per class from a small grammar: SQLi, XSS, command injection,
traversal, SSRF), with the threshold set on a separate benign validation split so that at most
**0.01 % of raw benign rows** are flagged (AEGIS's budget). Test false positives at that threshold:
**0.0059 %** of raw rows (0.06 % of the 1,707 distinct test requests).

| what is tested | detected at that threshold |
|---|---|
| held-out generated variants: SQLi / XSS / cmdi / traversal / SSRF | 68 % / 86 % / 85 % / 99 % / 88 % |
| the REAL campaign requests our scripts send: SQLi / XSS / traversal / cmdi / SSRF | **0 %** / **0 %** / 80 % / 50 % / 100 % |
| ...their mutants (SQLi / XSS / traversal / cmdi / SSRF) | 0 % / 0 % / 100 % / 50 % / 93 % |
| four families never trained: SSTI / NoSQL / XXE / JNDI | 33 % / 0 % / 67 % / 50 % |
| behavioural campaigns, per request: stuffing / IDOR / enumeration | **0 % / 0 % / 0 %** |

**Reading it honestly.** This is a crude baseline: the training attacks come from my own generator
(a public labelled corpus such as CSIC-2010 would need a download), one configuration, no tuning,
and the benign side has only 4.1k distinct request shapes (`E2E-RESULTS.md`). It detected 0 % of the
real SQLi and XSS campaign requests even though it handled held-out generated variants of those
classes, which says more about my generator than about ML-WAFs in general. What it does show is the
structural point: a per-request classifier trained before the attack cannot see the behavioural
campaigns at all (every request is individually normal) and partly misses unseen families, whereas
AEGIS learns a rule from the campaign itself, at the cost of the 60-160 s the first exposure takes.
It is not a claim that AEGIS beats a good ML-WAF. A stronger baseline remains to be built.
