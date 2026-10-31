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
	"regexp"
	"sort"
	"strconv"
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
// quotes (msg and tag values are single-quoted). It is only safe to use after
// checkActions has refused backslashes and unbalanced quotes: with no escape
// character there is exactly one way to read the quoting, so this splitter and
// Coraza's agree. (They did not when backslash-escaped quotes were allowed:
// `msg:\'x,allow,tag:\'y` read as ONE msg action here and as three actions in
// Coraza, which smuggled `allow`/`deny`/`ctl` past this check.)
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

// allowedOperators are the only operators an AEGIS sec rule may use: the ones ir/compile.py emits.
// The rest of Coraza's set includes network lookups (@rbl) and external programs (@inspectFile),
// which have no place in the request path (invariant 8).
var allowedOperators = map[string]bool{
	"@rx": true, "@contains": true, "@streq": true, "@detectsqli": true, "@detectxss": true,
	"@gt": true, "@ge": true, "@beginswith": true, "@pm": true,
}

var allowedTransforms = map[string]bool{
	"none": true, "lowercase": true, "urldecodeuni": true, "removecomments": true,
	"compresswhitespace": true, "removewhitespace": true, "htmlentitydecode": true,
	"cmdline": true, "normalizepath": true, "length": true,
}

var (
	secVarsRE = regexp.MustCompile(`^[A-Z][A-Z_]*(\|[A-Z][A-Z_]*)*$`)
	quotedRE  = regexp.MustCompile(`^'[^'\\]*'$`)
	numericRE = regexp.MustCompile(`^[0-9]+$`)
	minRuleID = 100000 // ir/compile.py numeric_id range; CRS and Coraza use the rest
	maxRuleID = 199999
)

// checkActions enforces a closed grammar on the actions argument: no escape characters, balanced
// quotes, and only allowlisted `name` or `name:value` actions whose values have the expected shape.
func checkActions(id, actions string) error {
	if strings.Contains(actions, "\\") {
		return fmt.Errorf("rule %s: backslash is not allowed in the actions argument", id)
	}
	if strings.Count(actions, "'")%2 != 0 {
		return fmt.Errorf("rule %s: unbalanced quote in the actions argument", id)
	}
	for _, tok := range splitActions(actions) {
		tok = strings.TrimSpace(tok)
		name, val, hasVal := strings.Cut(tok, ":")
		lname := strings.ToLower(name)
		if !allowedActions[lname] {
			return fmt.Errorf("rule %s: action %q is not allowed (sec rules may only pass; "+
				"the gateway decides the mode)", id, tok)
		}
		switch lname {
		case "msg", "tag":
			if !hasVal || !quotedRE.MatchString(val) {
				return fmt.Errorf("rule %s: %s must be a single-quoted string, got %q", id, lname, tok)
			}
		case "id":
			n, err := strconv.Atoi(val)
			if !hasVal || !numericRE.MatchString(val) || err != nil || n < minRuleID || n > maxRuleID {
				return fmt.Errorf("rule %s: id must be %d-%d, got %q", id, minRuleID, maxRuleID, tok)
			}
		case "phase":
			if !hasVal || len(val) != 1 || val[0] < '1' || val[0] > '5' {
				return fmt.Errorf("rule %s: bad phase %q", id, tok)
			}
		case "t":
			if !hasVal || !allowedTransforms[strings.ToLower(val)] {
				return fmt.Errorf("rule %s: transformation %q is not allowed", id, tok)
			}
		default: // pass, log, chain take no value
			if hasVal {
				return fmt.Errorf("rule %s: action %q takes no value", id, tok)
			}
		}
	}
	return nil
}

// validateSecRule is a structural guard for the rule store: every line must be
// `SecRule <VARS> "<operator> <arg>" "<actions>"` with exactly two double-quoted arguments (the
// compiler forbids quotes in values), an allowlisted operator, and a closed actions grammar.
func validateSecRule(id, text string) error {
	if strings.TrimSpace(text) == "" {
		return fmt.Errorf("rule %s: empty secrule", id)
	}
	for _, r := range text {
		if (r < 0x20 && r != '\n' && r != '\t' && r != '\r') || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 {
			return fmt.Errorf("rule %s: control or line-separator character %U in rule text", id, r)
		}
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
		if len(parts) != 5 || strings.TrimSpace(parts[4]) != "" || strings.TrimSpace(parts[2]) != "" {
			return fmt.Errorf("rule %s: a SecRule line must have exactly an operator and an actions argument", id)
		}
		if !secVarsRE.MatchString(strings.TrimSpace(strings.TrimPrefix(parts[0], "SecRule "))) {
			return fmt.Errorf("rule %s: bad variable list %.40q", id, parts[0])
		}
		op, _, _ := strings.Cut(strings.TrimSpace(parts[1]), " ")
		if !allowedOperators[strings.ToLower(op)] {
			return fmt.Errorf("rule %s: operator %q is not allowed", id, op)
		}
		if err := checkActions(id, parts[3]); err != nil {
			return err
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

// The high-water mark remembers the newest manifest version this gateway has loaded, in
// <manifest>.hw, so that replay protection survives a restart. Without it a validly signed OLDER
// manifest put on disk before a restart was accepted and silently dropped every newer rule.
// Format: {"v":N,"sig":"<hex HMAC of 'aegis-hw:N'>"} (sig empty in unsigned mode).
func hwPath(manifest string) string { return manifest + ".hw" }

func readHW(manifest string, key []byte) int {
	raw, err := os.ReadFile(hwPath(manifest))
	if err != nil {
		return 0
	}
	var h struct {
		V   int    `json:"v"`
		Sig string `json:"sig"`
	}
	if json.Unmarshal(raw, &h) != nil || h.V < 0 {
		return 0
	}
	if len(key) > 0 && signPayload(key, "aegis-hw:"+strconv.Itoa(h.V)) != strings.ToLower(h.Sig) {
		log.Printf("WARNING: %s has an invalid signature; ignoring it", hwPath(manifest))
		return 0
	}
	return h.V
}

func writeHW(manifest string, v int, key []byte) error {
	sig := ""
	if len(key) > 0 {
		sig = signPayload(key, "aegis-hw:"+strconv.Itoa(v))
	}
	b, _ := json.Marshal(map[string]any{"v": v, "sig": sig})
	tmp := hwPath(manifest) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, hwPath(manifest))
}

// <manifest>.good is a copy of the last manifest that loaded successfully. At startup a manifest that
// is corrupt, unsigned, wrongly signed or older than the high-water mark is replaced by it (still
// verified and checked against the mark), so tampering or a half-written file costs nothing rather than
// leaving the gateway without its rules.
func goodPath(manifest string) string { return manifest + ".good" }

func copyFileAtomic(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// restoreLastGood puts the last-good manifest back in place and loads it.
func (g *gateway) restoreLastGood() error {
	if _, err := readManifest(goodPath(g.manifestPath), g.manifestKey); err != nil {
		return fmt.Errorf("no usable last-good manifest: %w", err)
	}
	if err := copyFileAtomic(goodPath(g.manifestPath), g.manifestPath); err != nil {
		return err
	}
	return g.reload()
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
	// Replay protection (signed mode): never go back to an older manifest, even a validly
	// signed one -- older than what is loaded now, or than anything this gateway ever loaded.
	if len(g.manifestKey) > 0 {
		floor := g.hw
		if cur := g.rs.Load(); cur != nil && cur.version > floor {
			floor = cur.version
		}
		if m.Version < floor {
			return fmt.Errorf("manifest v%d is older than v%d already seen (replay refused)", m.Version, floor)
		}
	}
	rs, err := buildRuleSet(m, g.staticInclude)
	if err != nil {
		return err
	}
	g.rs.Store(rs)
	if err := copyFileAtomic(g.manifestPath, goodPath(g.manifestPath)); err != nil {
		log.Printf("could not save the last-good manifest: %v", err)
	}
	if m.Version > g.hw {
		g.hw = m.Version
		if err := writeHW(g.manifestPath, g.hw, g.manifestKey); err != nil {
			log.Printf("could not persist the manifest high-water mark: %v", err)
		}
	}
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
		if mode == "canary" && (pct < 1 || pct > 100) {
			// Writing this and failing at reload would leave an invalid manifest on disk.
			http.Error(w, "canary needs pct=1..100", http.StatusBadRequest)
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
