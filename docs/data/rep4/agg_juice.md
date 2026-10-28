### Juice Shop, final code: 5 replicate runs

| class | enforced | detect (s) | time to enforce (s) | synthesis (s) | attacker reached app, before / after |
|---|---|---|---|---|---|
| command_injection | 5/5 | 1.4 (95% CI 0.9-1.9; range 0.7-1.8; n=5) | 58.2 (95% CI 57.4-58.9; range 57.6-59.2; n=5) | 0.1 (95% CI 0.1-0.1; range 0.1-0.1; n=5) | 51.6 / 14 |
| credential_stuffing | 5/5 | 17.2 (95% CI 15.9-18.5; range 15.7-18.6; n=5) | 74.0 (95% CI 72.2-75.8; range 71.7-75.4; n=5) | 0.0 (95% CI 0.0-0.0; range 0.0-0.0; n=5) | 114 / 41.4 |
| sqli | 5/5 | 20.0 (95% CI 17.3-22.7; range 17.6-22.2; n=5) | 79.9 (95% CI 76.3-83.4; range 77.2-84.2; n=5) | 2.2 (95% CI 1.8-2.7; range 1.9-2.8; n=5) | 25.6 / 13.2 |

benign requests 151726, blocked by an AEGIS rule: 0; live-stage rejections: 0; false triggers per run: [133, 136, 129, 131, 100]; log gaps: [[], [], [], [], []]

{
 "n_runs": 5,
 "classes": {
  "command_injection": {
   "enforced": "5/5",
   "time_to_enforce_s": {
    "n": 5,
    "mean": 58.2,
    "min": 57.6,
    "max": 59.2,
    "sd": 0.6,
    "ci95": [
     57.4,
     58.9
    ]
   },
   "time_to_detect_s": {
    "n": 5,
    "mean": 1.4,
    "min": 0.7,
    "max": 1.8,
    "sd": 0.4,
    "ci95": [
     0.9,
     1.9
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
    "mean": 51.6,
    "min": 48,
    "max": 54,
    "sd": 2.2,
    "ci95": [
     48.9,
     54.3
    ]
   },
   "attacker_requests_reaching_app_after": {
    "n": 5,
    "mean": 14,
    "min": 14,
    "max": 14,
    "sd": 0.0,
    "ci95": [
     14.0,
     14.0
    ]
   },
   "attacker_requests_blocked_by_aegis_after": {
    "n": 5,
    "mean": 71.2,
    "min": 70,
    "max": 76,
    "sd": 2.7,
    "ci95": [
     67.9,
     74.5
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
    "mean": 74.0,
    "min": 71.7,
    "max": 75.4,
    "sd": 1.5,
    "ci95": [
     72.2,
     75.8
    ]
   },
   "time_to_detect_s": {
    "n": 5,
    "mean": 17.2,
    "min": 15.7,
    "max": 18.6,
    "sd": 1.1,
    "ci95": [
     15.9,
     18.5
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
    "mean": 114,
    "min": 101,
    "max": 122,
    "sd": 8.1,
    "ci95": [
     104.0,
     124.0
    ]
   },
   "attacker_requests_reaching_app_after": {
    "n": 5,
    "mean": 41.4,
    "min": 38,
    "max": 47,
    "sd": 3.7,
    "ci95": [
     36.8,
     46.0
    ]
   },
   "attacker_requests_blocked_by_aegis_after": {
    "n": 5,
    "mean": 32.2,
    "min": 30,
    "max": 37,
    "sd": 2.9,
    "ci95": [
     28.6,
     35.8
    ]
   },
   "valid_login_runs_before": {
    "n": 5,
    "mean": 9.6,
    "min": 9,
    "max": 10,
    "sd": 0.5,
    "ci95": [
     8.9,
     10.3
    ]
   },
   "valid_login_runs_after": {
    "n": 5,
    "mean": 5.8,
    "min": 5,
    "max": 7,
    "sd": 0.8,
    "ci95": [
     4.8,
     6.8
    ]
   }
  },
  "sqli": {
   "enforced": "5/5",
   "time_to_enforce_s": {
    "n": 5,
    "mean": 79.9,
    "min": 77.2,
    "max": 84.2,
    "sd": 2.9,
    "ci95": [
     76.3,
     83.4
    ]
   },
   "time_to_detect_s": {
    "n": 5,
    "mean": 20.0,
    "min": 17.6,
    "max": 22.2,
    "sd": 2.2,
    "ci95": [
     17.3,
     22.7
    ]
   },
   "synthesis_s": {
    "n": 5,
    "mean": 2.2,
    "min": 1.9,
    "max": 2.8,
    "sd": 0.4,
    "ci95": [
     1.8,
     2.7
    ]
   },
   "attacker_requests_reaching_app_before": {
    "n": 5,
    "mean": 25.6,
    "min": 24,
    "max": 28,
    "sd": 1.7,
    "ci95": [
     23.5,
     27.7
    ]
   },
   "attacker_requests_reaching_app_after": {
    "n": 5,
    "mean": 13.2,
    "min": 12,
    "max": 14,
    "sd": 1.1,
    "ci95": [
     11.8,
     14.6
    ]
   },
   "attacker_requests_blocked_by_aegis_after": {
    "n": 5,
    "mean": 53.2,
    "min": 48,
    "max": 56,
    "sd": 3.9,
    "ci95": [
     48.4,
     58.0
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
 "benign_requests_total": 151726,
 "benign_blocked_by_aegis_total": 0,
 "false_triggers_per_run": [
  133,
  136,
  129,
  131,
  100
 ],
 "rejected_live_total": 0,
 "log_gaps": [
  [],
  [],
  [],
  [],
  []
 ]
}
