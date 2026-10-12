package main

import (
	"encoding/json"
	"strings"
)

// accountOf extracts the account a request is about (the login/registration e-mail) from a
// JSON body, lower-cased and length-capped. It exists so a rate rule can key on the TARGET of a
// credential-stuffing attack rather than on the attacker's (rotatable) identity. Anything that
// is not a small JSON object with a string "email"/"username" yields "".
func accountOf(body []byte) string {
	if len(body) == 0 || len(body) > 4096 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
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
