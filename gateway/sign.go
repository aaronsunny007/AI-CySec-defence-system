package main

// Rule-store hardening: a signed manifest and an authenticated admin API.
//
// The manifest is the gateway's whole rule set; whoever can write it can switch the
// defence off or install a rule that blocks real users. With a key configured the
// file is an envelope {"payload": "<manifest JSON text>", "sig": "<hex HMAC-SHA256>"}
// and the gateway REFUSES anything else (unsigned, wrongly signed, or older than the
// rules already loaded) and keeps serving with its previous rules.
//
// What this covers: tampering with the manifest on disk by a process that does not
// hold the key; replaying an older (validly signed) manifest; unauthenticated calls
// to the mutating admin endpoints from other local processes.
// What it does NOT cover: theft of the key (anything that can read the key can sign),
// a compromised gateway or controller process, a root/admin attacker on the host, or
// confidentiality of the manifest (it is signed, not encrypted). See docs/HARDENING.md.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
)

type envelope struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

func signPayload(key []byte, payload string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// decodeManifest turns the raw file bytes into manifest JSON. With a key, the bytes must
// be a correctly signed envelope. Without a key, both plain and enveloped files are
// accepted (unsigned mode, as before).
func decodeManifest(raw []byte, key []byte) ([]byte, error) {
	var env envelope
	isEnv := json.Unmarshal(raw, &env) == nil && env.Payload != "" && env.Sig != ""
	if len(key) == 0 {
		if isEnv {
			return []byte(env.Payload), nil
		}
		return raw, nil
	}
	if !isEnv {
		return nil, errors.New("manifest is not signed but a signing key is configured")
	}
	want := signPayload(key, env.Payload)
	if subtle.ConstantTimeCompare([]byte(want), []byte(strings.ToLower(env.Sig))) != 1 {
		return nil, errors.New("manifest signature does not verify")
	}
	return []byte(env.Payload), nil
}

func encodeManifest(m Manifest, key []byte) ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil || len(key) == 0 {
		return b, err
	}
	payload := string(b)
	return json.MarshalIndent(envelope{Payload: payload, Sig: signPayload(key, payload)}, "", "  ")
}

// secretFrom reads a secret from env var NAME, or from the file named by NAME_FILE.
// Neither value is ever logged.
func secretFrom(name string) []byte {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return []byte(v)
	}
	if p := os.Getenv(name + "_FILE"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			return []byte(strings.TrimSpace(string(b)))
		}
	}
	return nil
}

// requireToken guards a mutating admin handler. With no token configured it is a no-op
// (loopback-only, as before); with one, a missing or wrong bearer token is a 401.
func requireToken(token []byte, next http.HandlerFunc) http.HandlerFunc {
	if len(token) == 0 {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		got := strings.TrimPrefix(h, "Bearer ")
		if !strings.HasPrefix(h, "Bearer ") || subtle.ConstantTimeCompare([]byte(got), token) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
