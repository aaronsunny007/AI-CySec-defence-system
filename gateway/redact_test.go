package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactText(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"json password", `{"email":"a@b.c","password":"Sup3rS3cret!"}`, `{"email":"a@b.c","password":"[redacted]"}`},
		{"json spaced + nested", `{"user": {"Password" : "hunter2"}, "ok": 1}`, `{"user": {"Password" : "[redacted]"}, "ok": 1}`},
		{"json escaped quote", `{"password":"a\"b"}`, `{"password":"[redacted]"}`},
		{"json token", `{"access_token":"abc.def"}`, `{"access_token":"[redacted]"}`},
		{"form body", `email=a%40b.c&password=hunter2&x=1`, `email=a%40b.c&password=[redacted]&x=1`},
		{"query token", `/rest/x?token=abc123&q=hat`, `/rest/x?token=[redacted]&q=hat`},
		{"xml", `<login><password>p@ss</password></login>`, `<login><password>[redacted]</password></login>`},
		{"non-secret untouched", `{"email":"a@b.c","q":"shoes"}`, `{"email":"a@b.c","q":"shoes"}`},
		{"key named passenger is not a secret", `{"passenger":"Bob"}`, `{"passenger":"Bob"}`},
		// An attacker's payload in a secret-named field is NOT a secret: the observer must still see it.
		{"sqli in password kept", `{"email":"a","password":"' OR 1=1--"}`, `{"email":"a","password":"' OR 1=1--"}`},
		{"url-encoded sqli kept", `password=%27%20OR%201%3D1--`, `password=%27%20OR%201%3D1--`},
		{"xss in token kept", `{"token":"<script>alert(1)</script>"}`, `{"token":"<script>alert(1)</script>"}`},
		{"empty", ``, ``},
	}
	for _, c := range cases {
		if got := redactText(c.in); got != c.want {
			t.Errorf("%s:\n  in   %s\n  got  %s\n  want %s", c.name, c.in, got, c.want)
		}
	}
}

func TestRedactKeepsKeyPresenceForLoginDetection(t *testing.T) {
	out := redactText(`{"email":"victim@example.com","password":"Sup3rS3cret!"}`)
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("redacted body is no longer valid JSON: %v", err)
	}
	if v, ok := m["password"].(string); !ok || v == "" || strings.Contains(out, "Sup3rS3cret") {
		t.Errorf("password key must remain (as a string) with the value gone: %s", out)
	}
}

func TestInjectionLike(t *testing.T) {
	for _, s := range []string{"' OR 1=1--", "1 UNION SELECT a FROM b", "../../etc/passwd", "<script>x</script>",
		"; cat /etc/passwd", "http://169.254.169.254/latest"} {
		if !injectionLike(s) {
			t.Errorf("%q should look like a payload", s)
		}
	}
	for _, s := range []string{"Sup3rS3cret!", "correct horse battery staple", "p@ssw0rd#2024", "O'Brien"} {
		if injectionLike(s) {
			t.Errorf("%q must not look like a payload", s)
		}
	}
}
