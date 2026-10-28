### Juice Shop, diverse gate corpus: 5 replicate runs

| class | enforced | detect (s) | time to enforce (s) | synthesis (s) | attacker reached app, before / after |
|---|---|---|---|---|---|
| command_injection | 5/5 | 1.5 (95% CI 0.9-2.1; range 0.7-1.9; n=5) | 85.6 (95% CI 8.7-162.4; range 56.8-196.3; n=5) | 0.1 (95% CI 0.1-0.1; range 0.1-0.1; n=5) | 71.2 / 15.6 |
| credential_stuffing | 5/5 | 13.9 (95% CI 5.4-22.3; range 1.9-18.0; n=5) | 70.4 (95% CI 62.2-78.5; range 58.8-74.5; n=5) | 0.0 (95% CI 0.0-0.0; range 0.0-0.0; n=5) | 85.4 / 35.6 |
| sqli | 5/5 | 11.8 (95% CI -0.3-23.9; range 1.1-21.4; n=5) | 72.2 (95% CI 61.5-82.9; range 62.5-81.0; n=5) | 2.1 (95% CI 1.9-2.4; range 1.9-2.4; n=5) | 22.6 / 11.4 |

benign requests 122929, blocked by an AEGIS rule: 1; live-stage rejections: 2; false triggers per run: [43, 43, 56, 126, 105]; log gaps: [[], [], [], [], []]

{
 "n_runs": 5,
 "classes": {
  "command_injection": {
   "enforced": "5/5",
   "time_to_enforce_s": {
    "n": 5,
    "mean": 85.6,
    "min": 56.8,
    "max": 196.3,
    "sd": 61.9,
    "ci95": [
     8.7,
     162.4
    ]
   },
   "time_to_detect_s": {
    "n": 5,
    "mean": 1.5,
    "min": 0.7,
    "max": 1.9,
    "sd": 0.5,
    "ci95": [
     0.9,
     2.1
    ]
   },
   "synthesis_s": {
    "n": 5,
    "mean": 0.1,
    "min": 0.1,
    "max": 0.1,
    "sd": 0.0,
    "ci95": [
     0.1,
     0.1
    ]
   },
   "attacker_requests_reaching_app_before": {
    "n": 5,
    "mean": 71.2,
    "min": 44,
    "max": 164,
    "sd": 51.9,
    "ci95": [
     6.7,
     135.7
    ]
   },
   "attacker_requests_reaching_app_after": {
    "n": 5,
    "mean": 15.6,
    "min": 12,
    "max": 24,
    "sd": 4.8,
    "ci95": [
     9.7,
     21.5
    ]
   },
   "attacker_requests_blocked_by_aegis_after": {
    "n": 5,
    "mean": 63.2,
    "min": 36,
    "max": 70,
    "sd": 15.2,
    "ci95": [
     44.3,
     82.1
    ]
   },
   "valid_login_runs_before": {
    "n": 5,
    "mean": 0,
    "min": 0,
    "max": 0,
    "sd": 0.0,
    "ci95": [
     0.0,
     0.0
    ]
   },
   "valid_login_runs_after": {
    "n": 5,
    "mean": 0,
    "min": 0,
    "max": 0,
    "sd": 0.0,
    "ci95": [
     0.0,
     0.0
    ]
   }
  },
  "credential_stuffing": {
   "enforced": "5/5",
   "time_to_enforce_s": {
    "n": 5,
    "mean": 70.4,
    "min": 58.8,
    "max": 74.5,
    "sd": 6.6,
    "ci95": [
     62.2,
     78.5
    ]
   },
   "time_to_detect_s": {
    "n": 5,
    "mean": 13.9,
    "min": 1.9,
    "max": 18.0,
    "sd": 6.8,
    "ci95": [
     5.4,
     22.3
    ]
   },
   "synthesis_s": {
    "n": 5,
    "mean": 0.0,
    "min": 0.0,
    "max": 0.0,
    "sd": 0.0,
    "ci95": [
     0.0,
     0.0
    ]
   },
   "attacker_requests_reaching_app_before": {
    "n": 5,
    "mean": 85.4,
    "min": 72,
    "max": 108,
    "sd": 15.8,
    "ci95": [
     65.7,
     105.1
    ]
   },
   "attacker_requests_reaching_app_after": {
    "n": 5,
    "mean": 35.6,
    "min": 31,
    "max": 42,
    "sd": 4.0,
    "ci95": [
     30.7,
     40.5
    ]
   },
   "attacker_requests_blocked_by_aegis_after": {
    "n": 5,
    "mean": 29.2,
    "min": 25,
    "max": 35,
    "sd": 4.4,
    "ci95": [
     23.8,
     34.6
    ]
   },
   "valid_login_runs_before": {
    "n": 5,
    "mean": 6.8,
    "min": 5,
    "max": 9,
    "sd": 1.6,
    "ci95": [
     4.8,
     8.8
    ]
   },
   "valid_login_runs_after": {
    "n": 5,
    "mean": 5.2,
    "min": 5,
    "max": 6,
    "sd": 0.4,
    "ci95": [
     4.6,
     5.8
    ]
   }
  },
  "sqli": {
   "enforced": "5/5",
   "time_to_enforce_s": {
    "n": 5,
    "mean": 72.2,
    "min": 62.5,
    "max": 81.0,
    "sd": 8.6,
    "ci95": [
     61.5,
     82.9
    ]
   },
   "time_to_detect_s": {
    "n": 5,
    "mean": 11.8,
    "min": 1.1,
    "max": 21.4,
    "sd": 9.8,
    "ci95": [
     -0.3,
     23.9
    ]
   },
   "synthesis_s": {
    "n": 5,
    "mean": 2.1,
    "min": 1.9,
    "max": 2.4,
    "sd": 0.2,
    "ci95": [
     1.9,
     2.4
    ]
   },
   "attacker_requests_reaching_app_before": {
    "n": 5,
    "mean": 22.6,
    "min": 19,
    "max": 26,
    "sd": 3.0,
    "ci95": [
     18.9,
     26.3
    ]
   },
   "attacker_requests_reaching_app_after": {
    "n": 5,
    "mean": 11.4,
    "min": 10,
    "max": 12,
    "sd": 0.9,
    "ci95": [
     10.3,
     12.5
    ]
   },
   "attacker_requests_blocked_by_aegis_after": {
    "n": 5,
    "mean": 47.2,
    "min": 44,
    "max": 48,
    "sd": 1.8,
    "ci95": [
     45.0,
     49.4
    ]
   },
   "valid_login_runs_before": {
    "n": 5,
    "mean": 0,
    "min": 0,
    "max": 0,
    "sd": 0.0,
    "ci95": [
     0.0,
     0.0
    ]
   },
   "valid_login_runs_after": {
    "n": 5,
    "mean": 0,
    "min": 0,
    "max": 0,
    "sd": 0.0,
    "ci95": [
     0.0,
     0.0
    ]
   }
  }
 },
 "benign_requests_total": 122929,
 "benign_blocked_by_aegis_total": 1,
 "false_triggers_per_run": [
  43,
  43,
  56,
  126,
  105
 ],
 "rejected_live_total": 2,
 "log_gaps": [
  [],
  [],
  [],
  [],
  []
 ]
}
