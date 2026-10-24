### Juice Shop, diverse gate corpus, long-poll-safe canary: 5 replicate runs

| class | enforced | detect (s) | time to enforce (s) | synthesis (s) | attacker reached app, before / after |
|---|---|---|---|---|---|
| command_injection | 5/5 | 1.8 (95% CI 1.0-2.6; range 1.0-2.8; n=5) | 58.8 (95% CI 57.4-60.2; range 58.1-60.8; n=5) | 0.1 (95% CI 0.1-0.1; range 0.1-0.1; n=5) | 53.2 / 14 |
| credential_stuffing | 5/5 | 17.5 (95% CI 17.1-17.9; range 16.9-17.7; n=5) | 74.1 (95% CI 73.2-74.9; range 73.4-75.0; n=5) | 0.0 (95% CI 0.0-0.0; range 0.0-0.0; n=5) | 105.4 / 40.8 |
| sqli | 5/5 | 12.5 (95% CI -0.2-25.2; range 1.1-22.3; n=5) | 81.6 (95% CI 60.7-102.5; range 61.0-107.7; n=5) | 2.1 (95% CI 2.0-2.2; range 1.9-2.1; n=5) | 26 / 12.4 |

benign requests 138611, blocked by an AEGIS rule: 3; live-stage rejections: 2; false triggers per run: [114, 105, 105, 107, 111]; log gaps: [[], [], [], [], []]

{
 "n_runs": 5,
 "classes": {
  "command_injection": {
   "enforced": "5/5",
   "time_to_enforce_s": {
    "n": 5,
    "mean": 58.8,
    "min": 58.1,
    "max": 60.8,
    "sd": 1.1,
    "ci95": [
     57.4,
     60.2
    ]
   },
   "time_to_detect_s": {
    "n": 5,
    "mean": 1.8,
    "min": 1.0,
    "max": 2.8,
    "sd": 0.6,
    "ci95": [
     1.0,
     2.6
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
    "mean": 53.2,
    "min": 52,
    "max": 56,
    "sd": 1.8,
    "ci95": [
     51.0,
     55.4
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
    "mean": 70,
    "min": 70,
    "max": 70,
    "sd": 0.0,
    "ci95": [
     70.0,
     70.0
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
    "mean": 74.1,
    "min": 73.4,
    "max": 75.0,
    "sd": 0.7,
    "ci95": [
     73.2,
     74.9
    ]
   },
   "time_to_detect_s": {
    "n": 5,
    "mean": 17.5,
    "min": 16.9,
    "max": 17.7,
    "sd": 0.3,
    "ci95": [
     17.1,
     17.9
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
    "mean": 105.4,
    "min": 91,
    "max": 115,
    "sd": 9.2,
    "ci95": [
     94.0,
     116.8
    ]
   },
   "attacker_requests_reaching_app_after": {
    "n": 5,
    "mean": 40.8,
    "min": 37,
    "max": 47,
    "sd": 4.0,
    "ci95": [
     35.9,
     45.7
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
    "mean": 9,
    "min": 8,
    "max": 10,
    "sd": 0.7,
    "ci95": [
     8.1,
     9.9
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
    "mean": 81.6,
    "min": 61.0,
    "max": 107.7,
    "sd": 16.8,
    "ci95": [
     60.7,
     102.5
    ]
   },
   "time_to_detect_s": {
    "n": 5,
    "mean": 12.5,
    "min": 1.1,
    "max": 22.3,
    "sd": 10.3,
    "ci95": [
     -0.2,
     25.2
    ]
   },
   "synthesis_s": {
    "n": 5,
    "mean": 2.1,
    "min": 1.9,
    "max": 2.1,
    "sd": 0.1,
    "ci95": [
     2.0,
     2.2
    ]
   },
   "attacker_requests_reaching_app_before": {
    "n": 5,
    "mean": 26,
    "min": 20,
    "max": 34,
    "sd": 5.1,
    "ci95": [
     19.7,
     32.3
    ]
   },
   "attacker_requests_reaching_app_after": {
    "n": 5,
    "mean": 12.4,
    "min": 12,
    "max": 14,
    "sd": 0.9,
    "ci95": [
     11.3,
     13.5
    ]
   },
   "attacker_requests_blocked_by_aegis_after": {
    "n": 5,
    "mean": 49.8,
    "min": 48,
    "max": 56,
    "sd": 3.5,
    "ci95": [
     45.5,
     54.1
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
 "benign_requests_total": 138611,
 "benign_blocked_by_aegis_total": 3,
 "false_triggers_per_run": [
  114,
  105,
  105,
  107,
  111
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
