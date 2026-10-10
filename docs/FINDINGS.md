# Early findings (pre-baseline)

Observations from development runs. **These are not the baseline.** The
baseline (`docs/BASELINE.md`) needs the ≥100k-request benign corpus, the
attack campaigns, and paired detect/enforce runs from the eval harness.
Recorded here so nothing is lost, and so the baseline can confirm or refute them.

## 2026-10-10 (FULL CORPUS) — CRS 4.25 (Coraza 3.8.1), PL1, threshold 5, untuned, vs Juice Shop 20.2.0

**Corpus:** 443,507 benign requests from 10,379 Playwright journeys, 3 h, detect mode.
Saved: `data/benign_corpus/benign_20261010_crs41_pl1_detect.jsonl` (261 MB).
Journey success (detect mode, nothing blocked): 90.2%; failures were Juice Shop
app errors (932, the apostrophe/SQLi bug) and script flakiness (85), **0 by defence**.

### False-positive rate (the number that matters)

| Measure | FP rate | vs 0.01% budget |
|---|---|---|
| All benign requests | **4.011%** (17,791 / 443,507) | 400× over |
| Excluding socket.io push channel | **0.277%** (1,229) | 28× over |

Dominant sources (untuned CRS):

| Count | Path | Rule | Cause |
|---|---|---|---|
| 16,553 | `/socket.io/` | 920420 | push-channel polling sends `text/plain`; not in CRS default allowed content types |
| ~950 | `/api/*`, `/rest/*` | 911100 | app REST API uses `PUT`; CRS default allows only GET/HEAD/POST/OPTIONS |
| 128 | `/assets/...` unicode-art filename | 933180 | PHP variable-function heuristic |
| ~90 | `/rest/user/login`, reviews | 942100/942350 | libinjection flags strong passwords / review text with SQL-ish tokens |

### Latency (laptop, 4 concurrent browsers, cold-ish)
p50 **2.68 ms**, p95 **9.5 ms**, p99 **14.2 ms**, max 80 ms. Budget: p99 ≤ 1 ms added.
Untuned CRS at PL1 already blows the inline budget by ~14× on this hardware.
(Not yet a controlled single-threaded benchmark — measure that before quoting.)

### Takeaways for the baseline
- "CRS untuned" FP rate is **4.0%** raw / **0.28%** without the socket.io noise — both
  far above budget. A competent operator's day-one tuning (allow `PUT`, allow the
  socket.io content type, standard exclusions) is the fair "CRS tuned" comparison.
- The socket.io result is real but is one misconfigured content-type rule, not 16k
  distinct problems — report both numbers so it isn't mistaken for either.

---

## 2026-10-10 (earlier dev run) — same config, ~10k requests

CRS would have blocked **401 / 10,077 benign requests = 3.98%**. Spec budget: 0.01%.
Superseded by the full-corpus numbers above; kept for continuity.

| Count | Request | Rule | Cause |
|---|---|---|---|
| 373 | `POST /socket.io/` | 920420 (+942190 ×7) | socket.io polling sends `text/plain`, not in CRS's default allowed content types |
| 19 | `PUT /api/BasketItems/*`, `PUT /rest/products/*/reviews` | 911100 | CRS default allows only GET/HEAD/POST/OPTIONS; the app's REST API uses PUT |
| 9 | `POST /rest/user/login`, `POST /api/Users/` | 932280 | strong passwords containing `{a,b}` look like bash brace expansion |
| 2 | product image with unicode-art filename | 933180 | PHP variable-function heuristic |

### Journeys broken with CRS enforcing (80 journeys)

- 71/80 journeys succeeded.
- **3 confirmed broken by CRS:** product reviews rejected with 403 (`PUT` → 911100).
- 6 failed by timeout with no foreground request blocked — unattributed until paired runs exist.
- Background `/socket.io/` polling was blocked in essentially every journey (live notifications broken), without failing the journey.

### Latency
WAF evaluation per request: p50 ≈ 2.7 ms, p99 ≈ 16 ms (laptop, 4 concurrent browsers).
Spec budget: p99 ≤ 1 ms added. Not yet measured under controlled load.

### Misses
`; cat /etc/passwd` in a query parameter: not detected (score 0).

### App behaviour that is NOT a defence failure
Juice Shop's login and search are deliberately SQL-injectable, so **any apostrophe**
(`o'neill@…` emails, `O'Brien hummus` searches) makes the app return 500.
Real users with apostrophes in their email cannot log in. The journey generator
attributes these as `cause: app`, not `defence`.

### Implication for the baseline
"CRS alone" has two honest variants and the baseline should report both:
1. **CRS untuned** (out of the box) — what the numbers above describe.
2. **CRS tuned for the app** — allow `PUT`/`DELETE`, allow socket.io's content
   type, the standard exclusions a competent operator would add on day one.
Reporting only (1) would make AEGIS look good against a straw man.
