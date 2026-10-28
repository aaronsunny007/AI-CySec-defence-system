### BookNook, final code: 3 replicate runs

| class | enforced | detect (s) | time to enforce (s) | synthesis (s) | attacker reached app, before / after |
|---|---|---|---|---|---|
| sqli | 3/3 | 1.1 (95% CI 0.4-1.8; range 0.9-1.4; n=3) | 58.2 (95% CI 56.5-59.9; range 57.8-59.0; n=3) | 0.6 (95% CI 0.6-0.6; range 0.6-0.6; n=3) | 10 / 7 |
| command_injection | 3/3 | 1.0 (95% CI 0.8-1.1; range 0.9-1.0; n=3) | 59.5 (95% CI 57.4-61.6; range 58.6-60.3; n=3) | 0.6 (95% CI 0.3-1.0; range 0.6-0.8; n=3) | 31 / 7.3 |
| credential_stuffing | 3/3 | 1.5 (95% CI 1.0-2.0; range 1.3-1.7; n=3) | 60.5 (95% CI 55.8-65.2; range 59.0-62.6; n=3) | 0.0 (95% CI 0.0-0.0; range 0.0-0.0; n=3) | 116.3 / 46.3 |

benign requests 155444, blocked by an AEGIS rule: 0; live-stage rejections: 3; false triggers per run: [44, 44, 44]; log gaps: [[], [], []]

{
 "n_runs": 3,
 "classes": {
  "sqli": {
   "enforced": "3/3",
   "time_to_enforce_s": {
    "n": 3,
    "mean": 58.2,
    "min": 57.8,
    "max": 59.0,
    "sd": 0.7,
    "ci95": [
     56.5,
     59.9
    ]
   },
   "time_to_detect_s": {
    "n": 3,
    "mean": 1.1,
    "min": 0.9,
    "max": 1.4,
    "sd": 0.3,
    "ci95": [
     0.4,
     1.8
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
     0.6
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
    "min": 58.6,
    "max": 60.3,
    "sd": 0.9,
    "ci95": [
     57.4,
     61.6
    ]
   },
   "time_to_detect_s": {
    "n": 3,
    "mean": 1.0,
    "min": 0.9,
    "max": 1.0,
    "sd": 0.1,
    "ci95": [
     0.8,
     1.1
    ]
   },
   "synthesis_s": {
    "n": 3,
    "mean": 0.6,
    "min": 0.6,
    "max": 0.8,
    "sd": 0.1,
    "ci95": [
     0.3,
     1.0
    ]
   },
   "attacker_requests_reaching_app_before": {
    "n": 3,
    "mean": 31,
    "min": 29,
    "max": 33,
    "sd": 2.0,
    "ci95": [
     26.0,
     36.0
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
    "mean": 10,
    "min": 9,
    "max": 11,
    "sd": 1.0,
    "ci95": [
     7.5,
     12.5
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
    "mean": 60.5,
    "min": 59.0,
    "max": 62.6,
    "sd": 1.9,
    "ci95": [
     55.8,
     65.2
    ]
   },
   "time_to_detect_s": {
    "n": 3,
    "mean": 1.5,
    "min": 1.3,
    "max": 1.7,
    "sd": 0.2,
    "ci95": [
     1.0,
     2.0
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
    "mean": 116.3,
    "min": 111,
    "max": 122,
    "sd": 5.5,
    "ci95": [
     102.7,
     130.0
    ]
   },
   "attacker_requests_reaching_app_after": {
    "n": 3,
    "mean": 46.3,
    "min": 43,
    "max": 48,
    "sd": 2.9,
    "ci95": [
     39.2,
     53.5
    ]
   },
   "attacker_requests_blocked_by_aegis_after": {
    "n": 3,
    "mean": 40,
    "min": 40,
    "max": 40,
    "sd": 0.0,
    "ci95": [
     40.0,
     40.0
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
    "mean": 7.7,
    "min": 7,
    "max": 8,
    "sd": 0.6,
    "ci95": [
     6.2,
     9.1
    ]
   }
  }
 },
 "benign_requests_total": 155444,
 "benign_blocked_by_aegis_total": 0,
 "false_triggers_per_run": [
  44,
  44,
  44
 ],
 "rejected_live_total": 3,
 "log_gaps": [
  [],
  [],
  []
 ]
}
