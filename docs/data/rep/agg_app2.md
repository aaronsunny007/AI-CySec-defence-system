### BookNook (second app): 3 replicate runs

| class | enforced | detect (s) | time to enforce (s) | synthesis (s) | attacker reached app, before / after |
|---|---|---|---|---|---|
| sqli | 3/3 | 1.1 (95% CI -0.2-2.3; range 0.6-1.6; n=3) | 62.9 (95% CI 57.7-68.0; range 60.6-64.7; n=3) | 4.3 (95% CI 0.2-8.4; range 3.3-6.2; n=3) | 10.7 / 6.7 |
| command_injection | 3/3 | 1.3 (95% CI 0.6-2.0; range 1.0-1.5; n=3) | 64.0 (95% CI 59.9-68.1; range 62.4-65.7; n=3) | 2.3 (95% CI 0.1-4.4; range 1.3-3.0; n=3) | 31.3 / 7 |
| credential_stuffing | 3/3 | 1.5 (95% CI 1.2-1.8; range 1.4-1.6; n=3) | 64.1 (95% CI 62.2-66.0; range 63.2-64.6; n=3) | 0.0 (95% CI -0.0-0.1; range 0.0-0.1; n=3) | 120.3 / 48 |

benign requests 145454, blocked by an AEGIS rule: 0; live-stage rejections: 3; false triggers per run: [41, 48, 44]; log gaps: [[], [], []]

{
 "n_runs": 3,
