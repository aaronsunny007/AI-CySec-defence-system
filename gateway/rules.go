package main

// Dynamic rule store for the AEGIS gateway: manifest, per-rule modes, hot
// reload, counters, per-slice stats, and a loopback admin API.
//
// Design:
//   - AEGIS SecRules are compiled with `pass` (never deny). The gateway decides
//     per rule whether a match is acted on, from the rule's MODE:
//         off      not loaded
//         shadow   match is counted, never blocks
//         canary   blocks only actors whose bucket < canary_pct, others shadow
//         enforce  blocks
//   - Rules live in a manifest (JSON). A watcher polls it; on change a NEW
//     ruleSet is built in the background and swapped in atomically. In-flight
//     requests keep the old set, so a reload drops no connection (FR-E2).
//   - A failed reload keeps the old set (fail safe). Counters and rate-limit
//     windows survive reloads.
//   - Rollback = set mode off; the admin call reloads immediately, so rollback
//     is bounded by build time, well under 5 s (FR-E5).
//   - The admin API listens on loopback only. With AEGIS_MANIFEST_KEY set the manifest
//     must be HMAC-signed and AEGIS_ADMIN_TOKEN guards the mutating endpoints (sign.go).

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
)

var validModes = map[string]bool{"off": true, "shadow": true, "canary": true, "enforce": true}

// ManifestRule is one rule entry. Type "sec" carries a compiled SecRule text;
// type "rate" carries a stateful per-actor rate limit.
type ManifestRule struct {
	ID             string   `json:"id"`
	Type           string   `json:"type"`
	Mode           string   `json:"mode"`
	CanaryPct      int      `json:"canary_pct"`
	AttackClass    string   `json:"attack_class,omitempty"`
	SecRule        string   `json:"secrule,omitempty"`
	EndpointPrefix string   `json:"endpoint_prefix,omitempty"`
	Methods        []string `json:"methods,omitempty"`
	Count          int      `json:"count,omitempty"`
	WindowS        int      `json:"window_s,omitempty"`
	// Key: what a rate rule counts per. "" / "actor" = the visitor identity (default);
	// "account" = the account named in the request body (defeats identity rotation for
	// credential stuffing; does not help against one password sprayed over many accounts).
	Key string `json:"key,omitempty"`
}

type Manifest struct {
	Version int            `json:"version"`
	Rules   []ManifestRule `json:"rules"`
}

// ruleSet is an immutable snapshot swapped in atomically.
type ruleSet struct {
	waf       coraza.WAF
	sec       map[string]ManifestRule
	rate      []ManifestRule
	rateByID  map[string]ManifestRule
	version   int
	maxCanary int // highest canary_pct among loaded rules; defines the canary slice
}

func (rr ManifestRule) matches(method, path string) bool {
	if !strings.HasPrefix(path, rr.EndpointPrefix) {
		return false
	}
	if len(rr.Methods) == 0 {
		return true
	}
	for _, m := range rr.Methods {
		if m == method {
			return true
		}
	}
	return false
}

// allowedActions are the ONLY actions an AEGIS sec rule may carry. The gateway,
// not the rule text, decides whether a match blocks, so a rule may only match
// and log. This is an allowlist (not a blocklist) and is checked against the
// parsed ACTIONS argument only, so a legitimate regex containing words like
// "exec" or "proxy" is not rejected. It is defence in depth behind
// ir/compile.py: a manifest written by anything other than the trusted compiler
// still cannot smuggle in `allow` (whitelisting an attacker), `ctl:` / `skip`
// (switching other rules off), or `deny`.
var allowedActions = map[string]bool{
	"id": true, "phase": true, "pass": true, "log": true, "msg": true,
	"tag": true, "t": true, "chain": true,
}

// splitActions splits an actions argument on commas that are outside single
// quotes (msg and tag values are single-quoted).
func splitActions(a string) []string {
	var out []string
	var cur strings.Builder
	inq := false
	for _, r := range a {
		switch {
		case r == '\'':
			inq = !inq
			cur.WriteRune(r)
		case r == ',' && !inq:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, cur.String())
}

// validateSecRule is a structural guard for the rule store: every line must be
// `SecRule <vars> "<operator>" "<actions>"` with exactly two double-quoted
// arguments (the compiler forbids quotes in values), and every action must be
// on the allowlist.
func validateSecRule(id, text string) error {
	if strings.TrimSpace(text) == "" {
		return fmt.Errorf("rule %s: empty secrule", id)
	}
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if !strings.HasPrefix(ln, "SecRule ") {
			return fmt.Errorf("rule %s: only SecRule lines allowed, got %.40q", id, ln)
		}
		parts := strings.Split(ln, "\"")
		if len(parts) != 5 || strings.TrimSpace(parts[4]) != "" {
			return fmt.Errorf("rule %s: a SecRule line must have exactly an operator and an actions argument", id)
		}
		for _, tok := range splitActions(parts[3]) {
			name := strings.ToLower(strings.TrimSpace(tok))
			if i := strings.IndexByte(name, ':'); i >= 0 {
				name = name[:i]
			}
			if !allowedActions[name] {
				return fmt.Errorf("rule %s: action %q is not allowed (sec rules may only pass; "+
					"the gateway decides the mode)", id, strings.TrimSpace(tok))
			}
		}
	}
	return nil
}

func buildRuleSet(m Manifest, staticInclude string) (*ruleSet, error) {
	rs := &ruleSet{sec: map[string]ManifestRule{}, rateByID: map[string]ManifestRule{}, version: m.Version}
	var aegis strings.Builder
	seen := map[string]bool{}
	for _, r := range m.Rules {
		if r.ID == "" || seen[r.ID] {
			return nil, fmt.Errorf("rule id missing or duplicated: %q", r.ID)
		}
		seen[r.ID] = true
		if !validModes[r.Mode] {
			return nil, fmt.Errorf("rule %s: bad mode %q", r.ID, r.Mode)
		}
		if r.Mode == "off" {
			continue
		}
		if r.Mode == "canary" && (r.CanaryPct < 1 || r.CanaryPct > 100) {
			return nil, fmt.Errorf("rule %s: canary_pct must be 1-100", r.ID)
		}
		if r.Mode == "canary" && r.CanaryPct > rs.maxCanary {
			rs.maxCanary = r.CanaryPct
		}
		switch r.Type {
		case "sec":
			if err := validateSecRule(r.ID, r.SecRule); err != nil {
				return nil, err
			}
			aegis.WriteString(strings.TrimSpace(r.SecRule) + "\n")
			rs.sec[r.ID] = r
		case "rate":
			if r.Count < 1 || r.WindowS < 1 || r.EndpointPrefix == "" {
				return nil, fmt.Errorf("rule %s: bad rate spec", r.ID)
			}
			if r.Key != "" && r.Key != "actor" && r.Key != "account" {
				return nil, fmt.Errorf("rule %s: bad rate key %q", r.ID, r.Key)
			}
			rs.rate = append(rs.rate, r)
			rs.rateByID[r.ID] = r
		default:
			return nil, fmt.Errorf("rule %s: bad type %q", r.ID, r.Type)
		}
	}
	waf, err := newWAF(staticInclude + "\n" + aegis.String())
	if err != nil {
		return nil, fmt.Errorf("compile rules: %w", err)
	}
	rs.waf = waf
	return rs, nil
}

// --- counters -----------------------------------------------------------------

type ruleCounters struct {
	Matches atomic.Int64 // every match, any mode
	Blocks  atomic.Int64 // matches that were acted on
	Shadow  atomic.Int64 // matches that were NOT acted on (shadow / canary-out)
}

func (g *gateway) counter(id string) *ruleCounters {
	g.cmu.RLock()
	c := g.cnt[id]
	g.cmu.RUnlock()
	if c != nil {
		return c
	}
	g.cmu.Lock()
	defer g.cmu.Unlock()
	if c = g.cnt[id]; c == nil {
		c = &ruleCounters{}
		g.cnt[id] = c
	}
	return c
}

// bucketOf maps an actor to a stable 0-99 bucket for canary membership: an
// actor is consistently in or out of the canary, not flapping per request.
func bucketOf(session string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(session))
	return int(h.Sum32() % 100)
}

// actNow decides whether a match under this rule's mode is enforced.
func actNow(mode string, pct, bucket int, globalEnforce bool) bool {
	if !globalEnforce {
		return false
	}
	switch mode {
	case "enforce":
		return true
	case "canary":
		return bucket < pct
	}
	return false
}

func (g *gateway) bump(id string, act bool) {
	c := g.counter(id)
	c.Matches.Add(1)
	if act {
		c.Blocks.Add(1)
	} else {
		c.Shadow.Add(1)
	}
}

// --- per-slice stats (control vs canary) --------------------------------------

type sliceStats struct {
	mu         sync.Mutex
	n          int64
	aegisBlock int64
	status5xx  int64
	lat        []int64
	idx        int
	full       bool
}

const latRing = 4096

func newSlice() *sliceStats { return &sliceStats{lat: make([]int64, latRing)} }

func (s *sliceStats) add(aegisBlocked bool, status int, appServed bool, totalUS int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	if aegisBlocked {
		s.aegisBlock++
	}
	if appServed && status >= 500 {
		s.status5xx++
	}
	s.lat[s.idx] = totalUS
	s.idx = (s.idx + 1) % latRing
	if s.idx == 0 {
		s.full = true
	}
}

func (s *sliceStats) snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.idx
	if s.full {
		n = latRing
	}
	vals := append([]int64(nil), s.lat[:n]...)
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	pct := func(p float64) int64 {
		if len(vals) == 0 {
			return 0
		}
		i := int(float64(len(vals)) * p)
		if i >= len(vals) {
			i = len(vals) - 1
		}
		return vals[i]
	}
	return map[string]any{
		"n": s.n, "aegis_blocked": s.aegisBlock, "status_5xx": s.status5xx,
		"p50_us": pct(0.50), "p99_us": pct(0.99),
	}
}

// --- rate limiter (state survives reloads) -------------------------------------

type rateLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newRateLimiter() *rateLimiter { return &rateLimiter{hits: map[string][]time.Time{}} }

// check records this request against every matching rate rule and returns the
// ids of rules whose window is exceeded: the (count+1)-th and later in-scope
// request within the trailing window_s. Same logic as gate/ratelimit.py.
func (rl *rateLimiter) check(rules []ManifestRule, actor, account, method, path string) []string {
	if rl == nil || len(rules) == 0 {
		return nil
	}
	now := time.Now()
	var exceeded []string
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for _, rr := range rules {
		if !rr.matches(method, path) {
			continue
		}
		subject := actor
		if rr.Key == "account" {
			if account == "" {
				continue // nothing to key on: this request is not about an account
			}
			subject = "acct:" + account
		}
		key := subject + "\x00" + rr.ID
		win := append(rl.hits[key], now)
		cutoff := now.Add(-time.Duration(rr.WindowS) * time.Second)
		j := 0
		for ; j < len(win); j++ {
			if win[j].After(cutoff) {
				break
			}
		}
		win = win[j:]
		rl.hits[key] = win
		if len(win) > rr.Count {
			exceeded = append(exceeded, rr.ID)
		}
	}
	return exceeded
}

// prune drops idle actors so the table cannot grow without bound.
func (rl *rateLimiter) prune(maxIdle time.Duration) {
	cutoff := time.Now().Add(-maxIdle)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for k, w := range rl.hits {
		if len(w) == 0 || w[len(w)-1].Before(cutoff) {
			delete(rl.hits, k)
		}
	}
}

// --- manifest IO, reload, watcher ---------------------------------------------

func readManifest(path string, key []byte) (Manifest, error) {
	var m Manifest
	raw, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	b, err := decodeManifest(raw, key)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	return m, nil
}

func writeManifest(path string, m Manifest, key []byte) error {
	b, err := encodeManifest(m, key)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	// On Windows a rename onto a file another process has open fails; retry
	// briefly (the other side is only ever a short read).
	var err2 error
	for i := 0; i < 200; i++ {
		if err2 = os.Rename(tmp, path); err2 == nil {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return err2
}

// reload builds a new ruleSet from the manifest and swaps it in. On any error
// the previous ruleSet stays active.
func (g *gateway) reload() error {
	g.reloadMu.Lock()
	defer g.reloadMu.Unlock()
	t0 := time.Now()
	m, err := readManifest(g.manifestPath, g.manifestKey)
	if err != nil {
		return err
	}
	// Replay protection (signed mode): never go back to an older manifest, even a
	// validly signed one.
	if len(g.manifestKey) > 0 {
		if cur := g.rs.Load(); cur != nil && m.Version < cur.version {
			return fmt.Errorf("manifest v%d is older than the loaded v%d (replay refused)", m.Version, cur.version)
		}
	}
	rs, err := buildRuleSet(m, g.staticInclude)
	if err != nil {
		return err
	}
	g.rs.Store(rs)
	log.Printf("reloaded manifest v%d: %d sec, %d rate rules in %v",
		m.Version, len(rs.sec), len(rs.rate), time.Since(t0).Round(time.Millisecond))
	return nil
}

func (g *gateway) watchManifest(every time.Duration) {
	var lastMod time.Time
	var lastSize int64 = -1
	for {
		time.Sleep(every)
		func() {
			defer func() {
				if p := recover(); p != nil {
					log.Printf("watcher panic (ignored): %v", p)
				}
			}()
			st, err := os.Stat(g.manifestPath)
			if err != nil {
				return
			}
			if st.ModTime().Equal(lastMod) && st.Size() == lastSize {
				return
			}
			lastMod, lastSize = st.ModTime(), st.Size()
			if err := g.reload(); err != nil {
				log.Printf("reload FAILED, keeping previous rules: %v", err)
			}
		}()
	}
}

// --- admin API (loopback only) --------------------------------------------------

func (g *gateway) adminMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		rs := g.rs.Load()
		rules := map[string]any{}
		add := func(id, typ, mode string, pct int) {
			c := g.counter(id)
			rules[id] = map[string]any{"type": typ, "mode": mode, "canary_pct": pct,
				"matches": c.Matches.Load(), "blocks": c.Blocks.Load(), "shadow": c.Shadow.Load()}
		}
		for _, r := range rs.sec {
			add(r.ID, "sec", r.Mode, r.CanaryPct)
		}
		for _, r := range rs.rate {
			add(r.ID, "rate", r.Mode, r.CanaryPct)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": rs.version, "canary_slice_pct": rs.maxCanary, "rules": rules,
			"slices":      map[string]any{"control": g.slices[0].snapshot(), "canary": g.slices[1].snapshot()},
			"log_dropped": g.dropped.Load(),
		})
	})

	setMode := func(w http.ResponseWriter, r *http.Request, id, mode string, pct int) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if !validModes[mode] {
			http.Error(w, "bad mode", http.StatusBadRequest)
			return
		}
		g.reloadMu.Lock()
		m, err := readManifest(g.manifestPath, g.manifestKey)
		if err != nil {
			g.reloadMu.Unlock()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		found := false
		for i := range m.Rules {
			if m.Rules[i].ID == id {
				m.Rules[i].Mode, m.Rules[i].CanaryPct, found = mode, pct, true
			}
		}
		if !found {
			g.reloadMu.Unlock()
			http.Error(w, "unknown rule", http.StatusNotFound)
			return
		}
		m.Version++
		err = writeManifest(g.manifestPath, m, g.manifestKey)
		g.reloadMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := g.reload(); err != nil {
			http.Error(w, "reload failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "%s -> %s\n", id, mode)
	}
	mux.HandleFunc("/mode", requireToken(g.adminToken, func(w http.ResponseWriter, r *http.Request) {
		pct := 0
		fmt.Sscanf(r.URL.Query().Get("pct"), "%d", &pct)
		setMode(w, r, r.URL.Query().Get("id"), r.URL.Query().Get("mode"), pct)
	}))
	mux.HandleFunc("/rollback", requireToken(g.adminToken, func(w http.ResponseWriter, r *http.Request) {
		setMode(w, r, r.URL.Query().Get("id"), "off", 0)
	}))
	return mux
}
