### Juice Shop (signed, fast clients): 5 replicate runs

| class | enforced | detect (s) | time to enforce (s) | synthesis (s) | attacker reached app, before / after |
|---|---|---|---|---|---|
| command_injection | 5/5 | 4.0 (95% CI 1.3-6.7; range 1.0-7.1; n=5) | 84.5 (95% CI 72.4-96.5; range 74.1-99.4; n=5) | 16.3 (95% CI 8.3-24.4; range 7.4-24.2; n=5) | 49.8 / 10.6 |
| credential_stuffing | 5/5 | 39.0 (95% CI 34.6-43.4; range 33.6-42.2; n=5) | 96.6 (95% CI 91.3-101.8; range 89.7-100.9; n=5) | 0.0 (95% CI -0.0-0.1; range 0.0-0.1; n=5) | 64.6 / 20.8 |
| sqli | 5/5 | 15.6 (95% CI 9.1-22.2; range 9.4-19.9; n=5) | 137.1 (95% CI 120.3-153.9; range 125.3-158.8; n=5) | 63.0 (95% CI 43.6-82.4; range 48.9-89.8; n=5) | 34.8 / 10.4 |

benign requests 94640, blocked by an AEGIS rule: 0; live-stage rejections: 0; false triggers per run: [13, 3, 14, 5, 22]; log gaps: [[], [], [], [], []]

{
 "n_runs": 5,
