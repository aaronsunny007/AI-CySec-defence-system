# Static ML-WAF baselines (spec baseline 3)

Two baselines. **v2 (below) is the one to cite**; v1 (further down) was trained on attacks from my own
generator and is kept for the record.

## v2: trained on real public attack data (2026-10-27)

Script `eval/ml_baseline2.py`, output `docs/data/ml_baseline2.txt` / `.json`. Training data:

* the public **HttpParamsDataset** (github.com/Morzeux/HttpParamsDataset, 31,067 labelled parameter values:
  19,304 benign from CSIC-2010; 10,852 SQLi from sqlmap, 532 XSS from XSSYA/FuzzDB, 89 command injection and
  290 path traversal from Vega/FuzzDB), wrapped as ordinary requests, 60% for training and 40% held out;
* the benign requests of **all four of our corpora** (Juice Shop, diverse sessions, BookNook, DVWA; 7,549
  / 7,257 / 10,321 distinct requests in train / validation / test, hash-split);
* models: character TF-IDF (2-5-grams) + logistic regression, gradient-boosted trees over engineered
  payload features (sklearn HistGradientBoosting), and the max of the two. The threshold of each is set on
  the validation benign requests so at most **0.01 % of raw benign rows** are flagged (AEGIS's own budget).

Measured benign false positives at that threshold on the test split: 0.0029 % (TF-IDF+LR), 0 % (GBDT).

| what is tested (n = requests) | TF-IDF + LR | GBDT | max of both |
|---|---|---|---|
| held-out public dataset: SQLi / XSS / path traversal / command injection | 100 / 99 / 100 / 79 % | 100 / 93 / 86 / 44 % | 100 / 96 / 95 / 56 % |
| REAL campaign requests our scripts send: SQLi (n=16) | **37.5 %** | 0 % | 0 % |
| ...XSS (n=12) / path traversal (n=10) / SSRF (n=10) | 100 / 80 / 100 % | 50 / 0 / 0 % | 50 / 80 / 0 % |
| ...command injection (n=24) | **0 %** (33 % at 0.1 % FP) | 8 % | 8 % |
| their mutants: SQLi / XSS / traversal / cmdi / SSRF | 35 / 88 / 100 / 0 / 100 % | 0 / 50 / 0 / 9 / 0 % | 0 / 50 / 93 / 9 / 0 % |
| four families never trained: SSTI / NoSQL / XXE / JNDI | 0 / 0 / 83 / 0 % | 17 / 0 / 8 / 33 % | 17 / 0 / 8 / 33 % |
| behavioural campaigns, per request: stuffing / IDOR / enumeration | **0 / 0 / 0 %** | 0 / 0 / 0 % | 0 / 0 / 0 % |

**Reading it honestly.**

* Training on real public data makes the baseline much better than v1 on classic single-request
  payloads: TF-IDF + LR catches XSS, SSRF and path traversal in our campaigns at the 0.01 % budget (100 %,
  100 %, 80 %), where AEGIS needs a first exposure plus about a minute to learn a rule. A per-request
  ML-WAF has a real advantage on payloads like these.
* It is still weak where it matters for our claims: **0 % of command injection** (the public set has only 89
  such values and they look different from our shell-chaining requests), **37.5 % of SQLi** (the public
  SQLi values are sqlmap's, which differ from hand-written login bypasses), 0 % of three of the four
  unseen families, and **0 % of every behavioural campaign** (credential stuffing, IDOR, enumeration: each
  request is individually normal, so no per-request model can see them).
* The campaign sets are small (10-30 requests per class), the models are untuned, and the dataset is
  parameter values, not full requests. Treat the percentages as rough. This is a fair "CRS + a static
  classifier" comparison for the claims about behavioural campaigns and unseen families; it is not a claim
  that AEGIS beats a tuned commercial ML-WAF on classic payloads.
* The max-of-both ensemble is worse than TF-IDF + LR alone, because the GBDT's threshold at the 0.01 %
  budget is much stricter.

## v1: generated training attacks (2026-10-24)


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
