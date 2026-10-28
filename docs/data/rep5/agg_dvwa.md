### DVWA (third app), final code: 3 replicate runs

| class | enforced | detect (s) | time to enforce (s) | synthesis (s) | attacker reached app, before / after |
|---|---|---|---|---|---|
| sqli | 3/3 | 1.0 (95% CI 0.9-1.2; range 1.0-1.1; n=3) | 57.4 (95% CI 56.6-58.1; range 57.1-57.7; n=3) | 0.6 (95% CI 0.6-0.7; range 0.6-0.6; n=3) | 27 / 18 |
| command_injection | 3/3 | 1.9 (95% CI 1.2-2.7; range 1.6-2.1; n=3) | 69.1 (95% CI 26.6-111.5; range 59.0-88.8; n=3) | 0.6 (95% CI 0.6-0.7; range 0.6-0.6; n=3) | 54.3 / 25.3 |
| credential_stuffing | 3/3 | 2.9 (95% CI 2.1-3.7; range 2.7-3.3; n=3) | 59.5 (95% CI 56.6-62.4; range 58.5-60.8; n=3) | 0.0 (95% CI 0.0-0.0; range 0.0-0.0; n=3) | 241.3 / 121.3 |

benign requests 40828, blocked by an AEGIS rule: 0; live-stage rejections: 4; false triggers per run: [2, 2, 2]; log gaps: [[], [], []]

{
 "n_runs": 3,
 "classes": {
  "sqli": {
   "enforced": "3/3",
   "time_to_enforce_s": {
    "n": 3,
    "mean": 57.4,
    "min": 57.1,
    "max": 57.7,
    "sd": 0.3,
    "ci95": [
     56.6,
     58.1
    ]
   },
   "time_to_detect_s": {
    "n": 3,
    "mean": 1.0,
    "min": 1.0,
    "max": 1.1,
    "sd": 0.1,
    "ci95": [
     0.9,
     1.2
    ]
   },
   "synthesis_s": {
    "n": 3,
    "mean": 0.6,
    "min": 0.6,
    "max": 0.6,
    "sd": 0.0,
    "ci95": [
     0.6,
     0.7
    ]
   },
   "attacker_requests_reaching_app_before": {
    "n": 3,
    "mean": 27,
    "min": 27,
    "max": 27,
    "sd": 0.0,
    "ci95": [
     27.0,
     27.0
    ]
   },
   "attacker_requests_reaching_app_after": {
    "n": 3,
    "mean": 18,
    "min": 18,
    "max": 18,
    "sd": 0.0,
    "ci95": [
     18.0,
     18.0
    ]
   },
   "attacker_requests_blocked_by_aegis_after": {
    "n": 3,
    "mean": 56.3,
    "min": 56,
    "max": 57,
    "sd": 0.6,
    "ci95": [
     54.9,
     57.8
    ]
   },
   "valid_login_runs_before": {
    "n": 3,
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
    "n": 3,
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
  "command_injection": {
   "enforced": "3/3",
   "time_to_enforce_s": {
    "n": 3,
    "mean": 69.1,
    "min": 59.0,
    "max": 88.8,
    "sd": 17.1,
    "ci95": [
     26.6,
     111.5
    ]
   },
   "time_to_detect_s": {
    "n": 3,
    "mean": 1.9,
    "min": 1.6,
    "max": 2.1,
    "sd": 0.3,
    "ci95": [
     1.2,
     2.7
    ]
   },
   "synthesis_s": {
    "n": 3,
    "mean": 0.6,
    "min": 0.6,
    "max": 0.6,
    "sd": 0.0,
    "ci95": [
     0.6,
     0.7
    ]
   },
   "attacker_requests_reaching_app_before": {
    "n": 3,
    "mean": 54.3,
    "min": 46,
    "max": 71,
    "sd": 14.4,
    "ci95": [
     18.5,
     90.2
    ]
   },
   "attacker_requests_reaching_app_after": {
    "n": 3,
    "mean": 25.3,
    "min": 25,
    "max": 26,
    "sd": 0.6,
    "ci95": [
     23.9,
     26.8
    ]
   },
   "attacker_requests_blocked_by_aegis_after": {
    "n": 3,
    "mean": 28.7,
    "min": 26,
    "max": 30,
    "sd": 2.3,
    "ci95": [
     22.9,
     34.4
    ]
   },
   "valid_login_runs_before": {
    "n": 3,
    "mean": 9,
    "min": 8,
    "max": 11,
    "sd": 1.7,
    "ci95": [
     4.7,
     13.3
    ]
   },
   "valid_login_runs_after": {
    "n": 3,
    "mean": 5,
    "min": 5,
    "max": 5,
    "sd": 0.0,
    "ci95": [
     5.0,
     5.0
    ]
   }
  },
  "credential_stuffing": {
   "enforced": "3/3",
   "time_to_enforce_s": {
    "n": 3,
    "mean": 59.5,
    "min": 58.5,
    "max": 60.8,
    "sd": 1.2,
    "ci95": [
     56.6,
     62.4
    ]
   },
   "time_to_detect_s": {
    "n": 3,
    "mean": 2.9,
    "min": 2.7,
    "max": 3.3,
    "sd": 0.3,
    "ci95": [
     2.1,
     3.7
    ]
   },
   "synthesis_s": {
    "n": 3,
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
    "n": 3,
    "mean": 241.3,
    "min": 234,
    "max": 252,
    "sd": 9.5,
    "ci95": [
     217.9,
     264.8
    ]
   },
   "attacker_requests_reaching_app_after": {
    "n": 3,
    "mean": 121.3,
    "min": 110,
    "max": 132,
    "sd": 11.0,
    "ci95": [
     94.0,
     148.7
    ]
   },
   "attacker_requests_blocked_by_aegis_after": {
    "n": 3,
    "mean": 39.7,
    "min": 35,
    "max": 42,
    "sd": 4.0,
    "ci95": [
     29.6,
     49.7
    ]
   },
   "valid_login_runs_before": {
    "n": 3,
    "mean": 7,
    "min": 7,
    "max": 7,
    "sd": 0.0,
    "ci95": [
     7.0,
     7.0
    ]
   },
   "valid_login_runs_after": {
    "n": 3,
    "mean": 5.3,
    "min": 5,
    "max": 6,
    "sd": 0.6,
    "ci95": [
     3.9,
     6.8
    ]
   }
  }
 },
 "benign_requests_total": 40828,
 "benign_blocked_by_aegis_total": 0,
 "false_triggers_per_run": [
  2,
  2,
  2
 ],
 "rejected_live_total": 4,
 "log_gaps": [
  [],
  [],
  []
 ]
}
