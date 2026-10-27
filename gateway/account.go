package main

import (
	"encoding/json"
	"net/url"
	"strings"
)

// accountOf extracts the account a request is about (the login/registration e-mail) from a
// JSON or form body, lower-cased and length-capped. It exists so a rate rule can key on the TARGET of a
// credential-stuffing attack rather than on the attacker's (rotatable) identity. Anything that
// is not a small JSON object with a string "email"/"username" yields "".
func accountOf(body []byte) string {
	if len(body) == 0 || len(body) > 4096 {
		return ""
	}
	m := map[string]any{}
	if t := strings.TrimLeft(string(body), " \t\r\n"); strings.HasPrefix(t, "{") {
		if json.Unmarshal(body, &m) != nil {
			return ""
		}
	} else if !strings.Contains(t, "\n") && strings.Contains(t, "=") {
		// an HTML form post (urlencoded), e.g. DVWA's login
		q, err := url.ParseQuery(t)
		if err != nil {
			return ""
		}
		for k, v := range q {
			if len(v) > 0 {
				m[strings.ToLower(k)] = v[0]
			}
		}
	} else {
		return ""
	}
	for _, k := range []string{"email", "username", "user"} {
		if v, ok := m[k].(string); ok && v != "" {
			v = strings.ToLower(strings.TrimSpace(v))
			if len(v) > 120 {
				v = v[:120]
			}
			return v
		}
	}
	return ""
}
