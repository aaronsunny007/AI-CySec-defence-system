### BookNook, diverse gate corpus: 3 replicate runs

| class | enforced | detect (s) | time to enforce (s) | synthesis (s) | attacker reached app, before / after |
|---|---|---|---|---|---|
| sqli | 3/3 | 1.1 (95% CI -0.2-2.4; range 0.5-1.4; n=3) | 59.2 (95% CI 58.1-60.3; range 58.7-59.5; n=3) | 0.7 (95% CI 0.6-0.7; range 0.6-0.7; n=3) | 10 / 7 |
| command_injection | 3/3 | 1.0 (95% CI 0.1-1.9; range 0.6-1.2; n=3) | 59.5 (95% CI 55.8-63.2; range 57.9-60.8; n=3) | 0.6 (95% CI 0.5-0.6; range 0.6-0.6; n=3) | 29.7 / 7.3 |
| credential_stuffing | 3/3 | 1.4 (95% CI 0.2-2.5; range 0.9-1.8; n=3) | 61.3 (95% CI 58.9-63.7; range 60.7-62.4; n=3) | 0.0 (95% CI 0.0-0.0; range 0.0-0.0; n=3) | 120 / 42 |

benign requests 151995, blocked by an AEGIS rule: 0; live-stage rejections: 3; false triggers per run: [41, 41, 44]; log gaps: [[], [], []]

{
 "n_runs": 3,
 "classes": {
  "sqli": {
   "enforced": "3/3",
   "time_to_enforce_s": {
    "n": 3,
    "mean": 59.2,
    "min": 58.7,
    "max": 59.5,
    "sd": 0.4,
    "ci95": [
     58.1,
     60.3
    ]
   },
   "time_to_detect_s": {
    "n": 3,
    "mean": 1.1,
    "min": 0.5,
    "max": 1.4,
    "sd": 0.5,
    "ci95": [
     -0.2,
     2.4
    ]
   },
   "synthesis_s": {
    "n": 3,
    "mean": 0.7,
    "min": 0.6,
    "max": 0.7,
    "sd": 0.0,
    "ci95": [
     0.6,
     0.7
    ]
   },
   "attacker_requests_reaching_app_before": {
    "n": 3,
    "mean": 10,
    "min": 10,
    "max": 10,
    "sd": 0.0,
    "ci95": [
     10.0,
     10.0
    ]
   },
   "attacker_requests_reaching_app_after": {
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
   "attacker_requests_blocked_by_aegis_after": {
    "n": 3,
    "mean": 56,
    "min": 56,
    "max": 56,
    "sd": 0.0,
    "ci95": [
     56.0,
     56.0
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
    "mean": 59.5,
    "min": 57.9,
    "max": 60.8,
    "sd": 1.5,
    "ci95": [
     55.8,
     63.2
    ]
   },
   "time_to_detect_s": {
    "n": 3,
    "mean": 1.0,
    "min": 0.6,
    "max": 1.2,
    "sd": 0.3,
    "ci95": [
     0.1,
     1.9
    ]
   },
   "synthesis_s": {
    "n": 3,
    "mean": 0.6,
    "min": 0.6,
    "max": 0.6,
    "sd": 0.0,
    "ci95": [
     0.5,
     0.6
    ]
   },
   "attacker_requests_reaching_app_before": {
    "n": 3,
    "mean": 29.7,
    "min": 29,
    "max": 31,
    "sd": 1.2,
    "ci95": [
     26.8,
     32.5
    ]
   },
   "attacker_requests_reaching_app_after": {
    "n": 3,
    "mean": 7.3,
    "min": 7,
    "max": 8,
    "sd": 0.6,
    "ci95": [
     5.9,
     8.8
    ]
   },
   "attacker_requests_blocked_by_aegis_after": {
    "n": 3,
    "mean": 36.7,
    "min": 35,
    "max": 40,
    "sd": 2.9,
    "ci95": [
     29.5,
     43.8
    ]
   },
   "valid_login_runs_before": {
    "n": 3,
    "mean": 9.3,
    "min": 9,
    "max": 10,
    "sd": 0.6,
    "ci95": [
     7.9,
     10.8
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
  "credential_stuffing": {
   "enforced": "3/3",
   "time_to_enforce_s": {
    "n": 3,
    "mean": 61.3,
    "min": 60.7,
    "max": 62.4,
    "sd": 1.0,
    "ci95": [
     58.9,
     63.7
    ]
   },
   "time_to_detect_s": {
    "n": 3,
    "mean": 1.4,
    "min": 0.9,
    "max": 1.8,
    "sd": 0.5,
    "ci95": [
     0.2,
     2.5
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
    "mean": 120,
    "min": 112,
    "max": 126,
    "sd": 7.2,
    "ci95": [
     102.1,
     137.9
    ]
   },
   "attacker_requests_reaching_app_after": {
    "n": 3,
    "mean": 42,
    "min": 42,
    "max": 42,
    "sd": 0.0,
    "ci95": [
     42.0,
     42.0
    ]
   },
   "attacker_requests_blocked_by_aegis_after": {
    "n": 3,
    "mean": 35.3,
    "min": 35,
    "max": 36,
    "sd": 0.6,
    "ci95": [
     33.9,
     36.8
    ]
   },
   "valid_login_runs_before": {
    "n": 3,
    "mean": 11.3,
    "min": 11,
    "max": 12,
    "sd": 0.6,
    "ci95": [
     9.9,
     12.8
    ]
   },
   "valid_login_runs_after": {
    "n": 3,
    "mean": 7,
    "min": 7,
    "max": 7,
    "sd": 0.0,
    "ci95": [
     7.0,
     7.0
    ]
   }
  }
 },
 "benign_requests_total": 151995,
 "benign_blocked_by_aegis_total": 0,
 "false_triggers_per_run": [
  41,
  41,
  44
 ],
 "rejected_live_total": 3,
 "log_gaps": [
  [],
  [],
  []
 ]
}
