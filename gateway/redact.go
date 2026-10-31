package main

// Secret redaction for the request log.
//
// The log is long-lived (and `aegis learn` copies it into the gate's benign corpus), but real
// login bodies carry passwords and many apps put tokens in query strings. Values of secret-looking
// fields are replaced with "[redacted]" BEFORE a record is written. The KEY stays, so the observer
// still sees "a login POST with a password and an email" (is_login_attempt) and campaign detection
// is unchanged.
//
// One exception, deliberately: a value that looks like an injection payload is kept. An attacker's
// `' OR 1=1--` in the password field is not a secret, and the observer needs it to see the campaign.
// "Looks like a payload" uses the same signatures as observer/detector.py SIGS; the strings below are
// copied from there and tests/test_redaction_parity.py fails if they drift apart.

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

const redacted = "[redacted]"

// injectionSigs mirrors observer/detector.py SIGS (case-insensitive).
var injectionSigs = map[string]string{
	"sqli":      `('|%27)[\s)]{0,100}(or|and)\s|union\s+select|('|%27|\))\s*(--|#)|\bselect\b.{1,300}\bfrom\b|sqlite_master`,
	"xss":       `<script|onerror\s*=|onload\s*=|<svg|<iframe|javascript:`,
	"traversal": `\.\./|\.\.%2f|%2e%2e|/etc/passwd|\.\.\\|%00|%2500`,
	"cmdi":      `;\s*(cat|id|whoami|ls|ping)\b|\|\s*(whoami|id|cat)\b|\$\(|` + "`.*`" + `|&&\s*(ping|cat)`,
	"ssrf":      `(https?|file|gopher)://(127\.0\.0\.1|localhost|169\.254\.169\.254|\[::1\]|0\.0\.0\.0)`,
}

var injectionRE []*regexp.Regexp

// secretKey names the fields whose values are never logged.
const secretKey = `pass(?:word|wd|phrase)?|pwd|secret|(?:access|refresh|id|auth|api|csrf|xsrf|session)?[_-]?token|` +
	`api[_-]?key|authorization|credentials?|card(?:[_-]?(?:number|no))?|cvv|cvc|ssn|otp|private[_-]?key|` +
	`client[_-]?secret|session(?:[_-]?id)?`

var (
	jsonSecretRE = regexp.MustCompile(`("(?i:` + secretKey + `)"\s*:\s*)"((?:[^"\\]|\\.)*)"`)
	formSecretRE = regexp.MustCompile(`((?:^|[&?;])(?i:` + secretKey + `)=)([^&#\s]*)`)
	xmlSecretRE  = regexp.MustCompile(`(<(?i:` + secretKey + `)>)([^<]*)(</)`)
)

func init() {
	for _, p := range injectionSigs {
		injectionRE = append(injectionRE, regexp.MustCompile(`(?i)`+p))
	}
}

// injectionLike reports whether s (raw or percent-encoded) matches an attack signature.
func injectionLike(s string) bool {
	cands := []string{s}
	if d, err := url.QueryUnescape(s); err == nil && d != s {
		cands = append(cands, d)
	}
	for _, c := range cands {
		for _, re := range injectionRE {
			if re.MatchString(c) {
				return true
			}
		}
	}
	return false
}

// replaceSub rewrites each match of re using fn over its submatches (index 0 = whole match).
func replaceSub(re *regexp.Regexp, s string, fn func(sub []string) string) string {
	idx := re.FindAllStringSubmatchIndex(s, -1)
	if idx == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, loc := range idx {
		b.WriteString(s[last:loc[0]])
		sub := make([]string, len(loc)/2)
		for i := range sub {
			if loc[2*i] >= 0 {
				sub[i] = s[loc[2*i]:loc[2*i+1]]
			}
		}
		b.WriteString(fn(sub))
		last = loc[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// redactText removes secret values from a JSON, form/query or XML fragment.
func redactText(s string) string {
	if s == "" {
		return s
	}
	s = replaceSub(jsonSecretRE, s, func(sub []string) string {
		val := sub[2]
		var un string
		if json.Unmarshal([]byte(`"`+val+`"`), &un) != nil {
			un = val
		}
		if injectionLike(un) || injectionLike(val) {
			return sub[0]
		}
		return sub[1] + `"` + redacted + `"`
	})
	s = replaceSub(formSecretRE, s, func(sub []string) string {
		if injectionLike(sub[2]) {
			return sub[0]
		}
		return sub[1] + redacted
	})
	s = replaceSub(xmlSecretRE, s, func(sub []string) string {
		if injectionLike(sub[2]) {
			return sub[0]
		}
		return sub[1] + redacted + sub[3]
	})
	return s
}
