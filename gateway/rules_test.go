package main

import "testing"

func TestValidateSecRule(t *testing.T) {
	good := `SecRule ARGS "@rx foo" "id:100001,phase:2,pass,log,msg:'AEGIS sqli rule aegis-x-1',tag:'aegis',tag:'aegis-rule:aegis-x-1',t:none"`
	cases := []struct {
		name string
		text string
		ok   bool
	}{
		{"valid pass rule", good, true},
		{"valid chained rule", good + "\n    SecRule REQUEST_URI \"@beginsWith /rest\" \"t:none\"", true},
		{"deny action", `SecRule ARGS "@rx foo" "id:1,phase:2,deny,status:403"`, false},
		{"allow injected as 2nd line", good + "\nSecRule ARGS \"@unconditionalMatch\" \"id:2,phase:1,allow\"", false},
		{"ctl switches rules off", `SecRule ARGS "@rx foo" "id:3,phase:1,pass,ctl:ruleEngine=Off"`, false},
		{"skip action", `SecRule ARGS "@rx foo" "id:4,phase:1,pass,skipAfter:END"`, false},
		{"non-SecRule directive", "SecRuleRemoveById 949110", false},
		{"Include directive", "Include /etc/passwd", false},
		{"engine directive", "SecRuleEngine Off", false},
		{"empty", "  \n ", false},
		{"regex mentioning exec/proxy/allow is fine", `SecRule ARGS "@rx (exec|proxy|allow|skip)" "id:5,phase:2,pass,log,msg:'AEGIS cmdi rule aegis-c-1',t:none"`, true},
		{"extra quoted argument", `SecRule ARGS "@rx a" "id:6,pass" "id:7,allow"`, false},
	}
	for _, c := range cases {
		err := validateSecRule("t", c.text)
		if (err == nil) != c.ok {
			t.Errorf("%s: ok=%v but err=%v", c.name, c.ok, err)
		}
	}
}

func TestBuildRuleSetRejectsBadManifests(t *testing.T) {
	bad := []Manifest{
		{Rules: []ManifestRule{{ID: "a", Type: "sec", Mode: "nonsense", SecRule: "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass\""}}},
		{Rules: []ManifestRule{{ID: "a", Type: "rate", Mode: "enforce", Count: 0, WindowS: 60, EndpointPrefix: "/x"}}},
		{Rules: []ManifestRule{{ID: "a", Type: "sec", Mode: "canary", CanaryPct: 0, SecRule: "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass\""}}},
		{Rules: []ManifestRule{
			{ID: "dup", Type: "rate", Mode: "enforce", Count: 1, WindowS: 1, EndpointPrefix: "/x"},
			{ID: "dup", Type: "rate", Mode: "enforce", Count: 1, WindowS: 1, EndpointPrefix: "/x"}}},
	}
	for i, m := range bad {
		if _, err := buildRuleSet(m, ""); err == nil {
			t.Errorf("bad manifest %d was accepted", i)
		}
	}
}

func TestActNow(t *testing.T) {
	if actNow("shadow", 0, 5, true) {
		t.Error("shadow must never act")
	}
	if !actNow("enforce", 0, 99, true) {
		t.Error("enforce must act")
	}
	if actNow("enforce", 0, 0, false) {
		t.Error("detect mode must never act")
	}
	if !actNow("canary", 25, 24, true) || actNow("canary", 25, 25, true) {
		t.Error("canary boundary wrong: bucket < pct acts")
	}
}

func TestRateLimiterWindow(t *testing.T) {
	rl := newRateLimiter()
	rules := []ManifestRule{{ID: "r", Type: "rate", Mode: "enforce", EndpointPrefix: "/login", Methods: []string{"POST"}, Count: 3, WindowS: 60}}
	for i := 1; i <= 3; i++ {
		if len(rl.check(rules, "a", "POST", "/login")) != 0 {
			t.Fatalf("request %d should be within the limit", i)
		}
	}
	if len(rl.check(rules, "a", "POST", "/login")) != 1 {
		t.Error("4th request must exceed")
	}
	if len(rl.check(rules, "b", "POST", "/login")) != 0 {
		t.Error("a different actor must have its own window")
	}
	if len(rl.check(rules, "a", "GET", "/login")) != 0 {
		t.Error("out-of-scope method must not count")
	}
}
