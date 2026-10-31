// Command gateway is the AEGIS enforcement plane: a reverse proxy that runs
// every request through OWASP Coraza + the OWASP Core Rule Set, plus any AEGIS
// rules in its (hot-reloadable) manifest, before forwarding to the protected app.
//
// Invariants (see CLAUDE.md section 2):
//   - Fail open. Any error or panic inside the WAF path forwards the request
//     unmodified and is logged with fail_open=true. A failed rule reload keeps
//     the previous rules.
//   - No network calls, no LLM, nothing unbounded in the request path.
//   - Every request is logged, benign or not, one JSON object per line, in the
//     same v1 schema that observer/normalise.py produces.
//
// Request-phase inspection only (phases 1-2). Response inspection is left out
// to protect the latency budget; revisit if outbound data-leak rules are needed.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"
)

const schemaVersion = 1

// defaultMaxBody caps how much request body we buffer and inspect (flag -max-body). A body larger
// than this cannot be inspected in full; what happens then is the -oversize policy: "reject" (the
// default, 413) or "pass" (forward uninspected beyond the cap, flagged in the log). It must not be
// silent: padding a body past the cap used to carry a SQLi payload straight through.
const defaultMaxBody = 1 << 20 // 1 MiB

// defaultLogBodyMax caps how much of a body is written to the request log (the WAF still sees all of
// what -max-body allows). Keeps one huge POST from filling the disk.
const defaultLogBodyMax = 64 << 10

var scoreRE = regexp.MustCompile(`Total Score:\s*(\d+)`)

// Record is one request in the AEGIS v1 request schema.
type Record struct {
	V             int    `json:"v"`
	TS            string `json:"ts"`
	ID            string `json:"id"`
	ClientIP      string `json:"client_ip"`
	ClientPort    int    `json:"client_port"`
	Method        string `json:"method"`
	URI           string `json:"uri"`
	HTTPVersion   string `json:"http_version"`
	Host          string `json:"host"`
	UserAgent     string `json:"user_agent"`
	ContentType   string `json:"content_type"`
	CookiePresent bool   `json:"cookie_present"`
	AuthPresent   bool   `json:"auth_present"`
	// Session: short, non-reversible fingerprint of the caller's identity
	// (visitor nonce / bearer token / session cookie, else client IP). Lets the
	// observer reconstruct one actor across requests without logging secrets.
	// NOT a detection signal on its own -- actors are grouped by it, then judged
	// on behaviour.
	Session string `json:"session"`
	// Ident says where Session came from: "vid" (range-only visitor cookie), "auth" (Authorization
	// header), "cookie" (an app session cookie) or "ip". Everything but "ip" is chosen by the caller, so
	// an attacker can mint a fresh one per request; the observer uses this to know which actors it can
	// trust to be one client.
	Ident        string   `json:"ident,omitempty"`
	Oversize     bool     `json:"oversize,omitempty"` // body exceeded -max-body
	Body         string   `json:"body"`
	BodyLen      int      `json:"body_len"`
	Status       int      `json:"status"`
	Blocked      bool     `json:"blocked"`
	AnomalyScore int      `json:"anomaly_score"`
	RuleIDs      []string `json:"rule_ids"`
	AttackTags   []string `json:"attack_tags"`
	// Gateway-only fields.
	WAFMicros   int64  `json:"waf_us"`
	TotalMicros int64  `json:"total_us"`
	FailOpen    bool   `json:"fail_open"`
	FailReason  string `json:"fail_reason,omitempty"`
	Mode        string `json:"mode"`
	RateRule    string `json:"rate_rule,omitempty"`
	// AegisMatches lists AEGIS rules that matched this request as
	// "id|mode|blocked" or "id|mode|shadow" (what the rule's mode did).
	AegisMatches []string `json:"aegis_matches,omitempty"`
	Canary       bool     `json:"canary"`
	RulesVersion int      `json:"rules_version"`
	// GTLabel is RANGE-ONLY ground truth ("benign" or "attack:<campaign>"),
	// read from the visitor cookie the range's own clients set. It exists so
	// evaluation does not have to key on the user-agent (which an attacker
	// controls and CRS itself matches on). No detector, gate or rule may read
	// it; it is empty for any real traffic.
	GTLabel string `json:"gt_label,omitempty"`
}

// gtLabel derives the range-only ground-truth label from the aegis_vid cookie.
func gtLabel(r *http.Request) string {
	c, err := r.Cookie("aegis_vid") // caller only invokes this in -range mode
	if err != nil {
		return ""
	}
	switch {
	case strings.HasPrefix(c.Value, "atk-"):
		v := strings.TrimPrefix(c.Value, "atk-")
		if i := strings.LastIndex(v, "-"); i > 0 {
			v = v[:i]
		}
		return "attack:" + v
	case strings.HasPrefix(c.Value, "benign"), strings.HasPrefix(c.Value, "witness"),
		strings.HasPrefix(c.Value, "stress"):
		return "benign"
	}
	return ""
}

type gateway struct {
	proxy   *httputil.ReverseProxy
	logs    chan Record
	enforce bool
	rl      *rateLimiter
	dropped atomic.Int64

	rangeMode  bool   // honour the lab-only aegis_vid cookie (visitor identity + ground truth)
	maxBody    int64  // largest body inspected in full
	oversize   string // "reject" | "pass"
	logBodyMax int    // bytes of body written to the log

	rs            atomic.Pointer[ruleSet]
	manifestPath  string
	hw            int    // highest manifest version ever loaded (persisted in <manifest>.hw)
	manifestKey   []byte // HMAC key for the signed manifest; nil = unsigned mode
	adminToken    []byte // bearer token for mutating admin endpoints; nil = none required
	staticInclude string
	reloadMu      sync.Mutex

	cmu    sync.RWMutex
	cnt    map[string]*ruleCounters
	slices [2]*sliceStats // 0 = control, 1 = canary
}

// Directive order matters. Coraza stops evaluating a transaction once CRS's
// blocking rule (949110, phase 2) interrupts it, so any AEGIS rule loaded AFTER
// CRS would never see a request CRS already blocks -- shadow counts would
// silently under-count and AEGIS matches could not be attributed. AEGIS rules
// therefore load BEFORE CRS. They only `pass`, so they never interrupt.
const wafHead = `
Include @coraza.conf-recommended
SecRuleEngine On
SecResponseBodyAccess Off
`

const wafCRS = `
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
`

func newWAF(extra string) (coraza.WAF, error) {
	return coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(wafHead + extra + "\n" + wafCRS).
		WithRootFS(mergefs.Merge(coreruleset.FS, mergefsio.OSFS)))
}

// sessionID derives a stable, non-reversible actor fingerprint. aegis_vid (the
// range's per-client nonce, standing in for distinct source IPs; see
// docs/DECISIONS.md) wins, then bearer token, then Juice Shop cookies, then the
// client IP. The raw value is hashed so no token or cookie reaches the log.
func sessionID(r *http.Request, ip string, rangeMode bool) (id, ident string) {
	raw := ""
	if c, err := r.Cookie("aegis_vid"); rangeMode && err == nil && c.Value != "" {
		raw, ident = "v:"+c.Value, "vid" // lab only: in production this cookie is attacker-chosen like any other
	} else if a := r.Header.Get("Authorization"); a != "" {
		raw, ident = "b:"+a, "auth"
	} else if c, err := r.Cookie("token"); err == nil && c.Value != "" {
		raw, ident = "t:"+c.Value, "cookie"
	} else if c, err := r.Cookie("continueCode"); err == nil && c.Value != "" {
		raw, ident = "c:"+c.Value, "cookie"
	} else if c, err := r.Cookie("connect.sid"); err == nil && c.Value != "" {
		raw, ident = "s:"+c.Value, "cookie"
	}
	if raw == "" {
		return "ip:" + ip, "ip"
	}
	sum := sha256.Sum256([]byte(raw))
	return "h:" + hex.EncodeToString(sum[:8]), ident
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// statusWriter records the status code sent to the client.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// inspect runs the request through Coraza. It returns the interruption (nil
// means allow) and the AEGIS rule ids that matched, and fills the WAF fields of
// rec. A panic inside Coraza is converted into an error so the caller fails open.
func (g *gateway) inspect(waf coraza.WAF, r *http.Request, body []byte, rec *Record) (it *types.Interruption, aegisIDs []string, err error) {
	defer func() {
		if p := recover(); p != nil {
			it, aegisIDs, err = nil, nil, fmt.Errorf("panic: %v", p)
		}
	}()

	tx := waf.NewTransactionWithID(rec.ID)
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	srvHost, srvPortStr, _ := net.SplitHostPort(r.Context().Value(http.LocalAddrContextKey).(net.Addr).String())
	srvPort, _ := strconv.Atoi(srvPortStr)
	tx.ProcessConnection(rec.ClientIP, rec.ClientPort, srvHost, srvPort)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(strings.Split(r.Host, ":")[0])
	}

	it = tx.ProcessRequestHeaders()
	if it == nil && tx.IsRequestBodyAccessible() && len(body) > 0 {
		if it, _, err = tx.WriteRequestBody(body); err != nil {
			return nil, nil, err
		}
	}
	if it == nil {
		if it, err = tx.ProcessRequestBody(); err != nil {
			return nil, nil, err
		}
	}

	tags := map[string]bool{}
	ids := map[string]bool{}
	aegis := map[string]bool{}
	for _, mr := range tx.MatchedRules() {
		for _, t := range mr.Rule().Tags() {
			if strings.HasPrefix(t, "aegis-rule:") {
				aegis[strings.TrimPrefix(t, "aegis-rule:")] = true
			}
		}
		if m := scoreRE.FindStringSubmatch(mr.Message() + " " + mr.Data()); m != nil {
			if s, _ := strconv.Atoi(m[1]); s > rec.AnomalyScore {
				rec.AnomalyScore = s
			}
		}
		// CRS flow-control rules (paranoia-level skips, ctl rules) have no msg.
		if !isDetectionRule(mr.Rule().ID()) || mr.Message() == "" {
			continue
		}
		id := strconv.Itoa(mr.Rule().ID())
		ids[id] = true
		for _, t := range mr.Rule().Tags() {
			if strings.HasPrefix(t, "attack-") {
				tags[t] = true
			}
		}
	}
	rec.RuleIDs = sortedKeys(ids)
	rec.AttackTags = sortedKeys(tags)
	return it, sortedKeys(aegis), nil
}

// isDetectionRule reports whether a matched rule is an actual detection.
// CRS 900xxx-910xxx are setup/initialisation rules that "match" on every
// request, 949xxx/959xxx/980xxx are score evaluation and reporting, and
// Coraza's 200001 just switches on the JSON/XML body parser. 200002+ (body
// parse failures) and CRS 911xxx-948xxx are real detections.
func isDetectionRule(id int) bool {
	return (id >= 911000 && id < 949000) || (id >= 200002 && id < 200100)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ip, portStr, _ := net.SplitHostPort(r.RemoteAddr)
	port, _ := strconv.Atoi(portStr)
	rs := g.rs.Load() // one immutable snapshot for the whole request
	rec := Record{
		V:             schemaVersion,
		TS:            start.UTC().Format(time.RFC3339Nano),
		ID:            newID(),
		ClientIP:      ip,
		ClientPort:    port,
		Method:        r.Method,
		URI:           r.URL.RequestURI(),
		HTTPVersion:   r.Proto,
		Host:          r.Host,
		UserAgent:     r.UserAgent(),
		ContentType:   r.Header.Get("Content-Type"),
		CookiePresent: r.Header.Get("Cookie") != "",
		AuthPresent:   r.Header.Get("Authorization") != "",
		RuleIDs:       []string{},
		AttackTags:    []string{},
		Mode:          map[bool]string{true: "enforce", false: "detect"}[g.enforce],
		RulesVersion:  rs.version,
	}
	rec.Session, rec.Ident = sessionID(r, ip, g.rangeMode)
	if g.rangeMode {
		rec.GTLabel = gtLabel(r)
	}
	bucket := bucketOf(rec.Session)
	rec.Canary = rs.maxCanary > 0 && bucket < rs.maxCanary

	// Buffer up to maxBody (+1, to notice an overflow) for inspection; stitch the rest back on for the app.
	var body []byte
	oversize := false
	if r.Body != nil {
		var err error
		full, err := io.ReadAll(io.LimitReader(r.Body, g.maxBody+1))
		if err != nil {
			rec.FailOpen, rec.FailReason = true, "body read: "+err.Error()
		}
		body = full
		if int64(len(full)) > g.maxBody {
			body, oversize = full[:g.maxBody], true
		}
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(full), r.Body), r.Body}
	}
	if r.ContentLength > g.maxBody {
		oversize = true
	}
	rec.Oversize = oversize
	logged := body
	if len(logged) > g.logBodyMax {
		logged = logged[:g.logBodyMax]
	}
	rec.Body = redactText(string(logged))
	rec.URI = redactText(rec.URI)
	rec.BodyLen = len(body)
	if r.ContentLength > int64(len(body)) {
		rec.BodyLen = int(r.ContentLength)
	}
	rejectOversize := oversize && g.oversize == "reject"

	blockedBy, blockStatus := "", 0
	apply := func(id string, cfg ManifestRule) {
		act := actNow(cfg.Mode, cfg.CanaryPct, bucket, g.enforce)
		g.bump(id, act)
		outcome := "shadow"
		if act {
			outcome = "blocked"
			if blockedBy == "" {
				blockedBy = id
			}
		}
		rec.AegisMatches = append(rec.AegisMatches, id+"|"+cfg.Mode+"|"+outcome)
	}

	// Rate limits (stateful, per actor). A panic here must not take the app
	// down: guard and fail open.
	func() {
		defer func() { _ = recover() }()
		for _, id := range g.rl.check(rs.rate, rec.Session, accountOf(body), r.Method, r.URL.Path) {
			if rec.RateRule == "" {
				rec.RateRule = id
			}
			apply(id, rs.rateByID[id])
			if blockedBy == id {
				blockStatus = http.StatusTooManyRequests
			}
		}
	}()

	var it *types.Interruption
	if !rec.FailOpen && !rejectOversize {
		wafStart := time.Now()
		var err error
		var aegisIDs []string
		it, aegisIDs, err = g.inspect(rs.waf, r, body, &rec)
		rec.WAFMicros = time.Since(wafStart).Microseconds()
		if err != nil {
			it = nil
			rec.FailOpen, rec.FailReason = true, err.Error()
		} else {
			for _, id := range aegisIDs {
				if cfg, ok := rs.sec[id]; ok {
					apply(id, cfg)
					if blockedBy == id && blockStatus == 0 {
						blockStatus = http.StatusForbidden
					}
				}
			}
		}
	}

	sw := &statusWriter{ResponseWriter: w}
	aegisBlocked := blockedBy != ""
	served := false
	switch {
	case rejectOversize:
		rec.Blocked = true
		sw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		sw.WriteHeader(http.StatusRequestEntityTooLarge)
		fmt.Fprintf(sw, "Request body larger than the %d bytes AEGIS can inspect (ref %s)\n", g.maxBody, rec.ID)
	case aegisBlocked:
		rec.Blocked = true
		sw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		sw.WriteHeader(blockStatus)
		fmt.Fprintf(sw, "Request blocked by AEGIS rule %s (ref %s)\n", blockedBy, rec.ID)
	case it != nil && g.enforce:
		status := it.Status
		if status == 0 {
			status = http.StatusForbidden
		}
		rec.Blocked = true
		sw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		sw.WriteHeader(status)
		fmt.Fprintf(sw, "Request blocked by AEGIS (ref %s)\n", rec.ID)
	default:
		served = true
		g.proxy.ServeHTTP(sw, r)
	}

	rec.Status = sw.status
	rec.TotalMicros = time.Since(start).Microseconds()
	slice := g.slices[0]
	if rec.Canary {
		slice = g.slices[1]
	}
	slice.add(aegisBlocked, rec.Status, served, rec.TotalMicros)
	select {
	case g.logs <- rec:
	default:
		g.dropped.Add(1) // never block the request path on logging
	}
}

// writeLogs appends records to path, mode 0600 in a 0700 directory (it holds request data). When the
// file passes maxBytes it is renamed to path+".1" (replacing the previous one) and a fresh file is
// started, so the log cannot fill the disk.
func writeLogs(path string, in <-chan Record, maxBytes int64) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		log.Fatalf("log dir: %v", err)
	}
	open := func() (*os.File, *bufio.Writer, *json.Encoder) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Fatalf("open log: %v", err)
		}
		bw := bufio.NewWriterSize(f, 64<<10)
		enc := json.NewEncoder(bw)
		enc.SetEscapeHTML(false)
		return f, bw, enc
	}
	f, bw, enc := open()
	tick := time.NewTicker(500 * time.Millisecond)
	for {
		select {
		case rec := <-in:
			if err := enc.Encode(rec); err != nil {
				log.Printf("log write: %v", err)
			}
		case <-tick.C:
			_ = bw.Flush()
			if maxBytes > 0 {
				if st, err := f.Stat(); err == nil && st.Size() > maxBytes {
					_ = f.Close()
					if err := os.Rename(path, path+".1"); err != nil {
						log.Printf("log rotate: %v", err)
					}
					f, bw, enc = open()
				}
			}
		}
	}
}

// legacyRateRules loads the older static rate-rule file (compile_rate output)
// as enforce-mode rate rules.
func legacyRateRules(path string) ([]ManifestRule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []ManifestRule
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, err
	}
	for i := range rules {
		rules[i].Type, rules[i].Mode = "rate", "enforce"
	}
	return rules, nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "address to listen on")
	admin := flag.String("admin", "127.0.0.1:8081", "loopback admin API address (stats, mode, rollback); empty disables")
	backend := flag.String("backend", "http://127.0.0.1:3000", "protected app URL")
	logPath := flag.String("log", "logs/gateway/requests.jsonl", "request log (JSONL, appended)")
	mode := flag.String("mode", "enforce", "enforce = block on verdict; detect = log verdict, never block")
	rules := flag.String("rules", "", "optional static SecRule file included after CRS (deny-style, always enforced)")
	rateRulesPath := flag.String("raterules", "", "optional static JSON of rate rules (all enforce)")
	manifest := flag.String("manifest", "rules/active/manifest.json", "hot-reloadable AEGIS rule manifest (created empty if missing)")
	rangeMode := flag.Bool("range", false, "LAB ONLY: trust the aegis_vid cookie as visitor identity and ground-truth label. Never in production: an attacker can set it freely")
	maxBodyFlag := flag.Int64("max-body", defaultMaxBody, "largest request body (bytes) inspected in full")
	oversize := flag.String("oversize", "reject", "bodies over -max-body: reject (413) | pass (forward, only the first -max-body bytes inspected)")
	logBodyMax := flag.Int("log-body-max", defaultLogBodyMax, "bytes of request body written to the log")
	logMaxMB := flag.Int64("log-max-mb", 1024, "rotate the request log to <log>.1 above this size in MiB; 0 = never")
	flag.Parse()

	if *mode != "enforce" && *mode != "detect" {
		log.Fatalf("-mode must be enforce or detect")
	}
	if *oversize != "reject" && *oversize != "pass" {
		log.Fatalf("-oversize must be reject or pass")
	}
	if *maxBodyFlag < 1 || *logBodyMax < 0 {
		log.Fatalf("-max-body must be positive and -log-body-max non-negative")
	}
	target, err := url.Parse(*backend)
	if err != nil {
		log.Fatalf("bad -backend: %v", err)
	}

	g := &gateway{
		logs: make(chan Record, 8192), enforce: *mode == "enforce",
		rl: newRateLimiter(), manifestPath: *manifest,
		manifestKey: secretFrom("AEGIS_MANIFEST_KEY"), adminToken: secretFrom("AEGIS_ADMIN_TOKEN"),
		cnt: map[string]*ruleCounters{}, slices: [2]*sliceStats{newSlice(), newSlice()},
		rangeMode: *rangeMode, maxBody: *maxBodyFlag, oversize: *oversize, logBodyMax: *logBodyMax,
	}
	if *admin != "" && !isLoopbackAddr(*admin) && len(g.adminToken) == 0 {
		log.Fatalf("-admin %s is not a loopback address and AEGIS_ADMIN_TOKEN is not set: refusing to expose the rule-store API unauthenticated", *admin)
	}
	if *rangeMode {
		log.Printf("WARNING: -range is on: the aegis_vid cookie is trusted as identity. Lab use only.")
	}
	if *rules != "" {
		g.staticInclude = "Include " + filepath.ToSlash(*rules)
	}

	// Manifest: create empty if missing, merge any legacy static rate rules.
	if err := os.MkdirAll(filepath.Dir(*manifest), 0o755); err != nil {
		log.Fatalf("manifest dir: %v", err)
	}
	if _, err := os.Stat(*manifest); os.IsNotExist(err) {
		_ = os.Remove(hwPath(*manifest)) // a deliberate reset (manifest removed) also resets the replay mark
		_ = os.Remove(goodPath(*manifest))
		if err := writeManifest(*manifest, Manifest{Version: 1}, g.manifestKey); err != nil {
			log.Fatalf("create manifest: %v", err)
		}
	}
	if *rateRulesPath != "" {
		legacy, err := legacyRateRules(*rateRulesPath)
		if err != nil {
			log.Fatalf("load rate rules: %v", err)
		}
		m, err := readManifest(*manifest, g.manifestKey)
		if err != nil {
			log.Fatalf("read manifest: %v", err)
		}
		have := map[string]bool{}
		for _, r := range m.Rules {
			have[r.ID] = true
		}
		for _, r := range legacy {
			if !have[r.ID] {
				m.Rules = append(m.Rules, r)
			}
		}
		m.Version++
		if err := writeManifest(*manifest, m, g.manifestKey); err != nil {
			log.Fatalf("write manifest: %v", err)
		}
	}
	log.Printf("rule store: signed manifest %v, admin token %v",
		len(g.manifestKey) > 0, len(g.adminToken) > 0)
	g.hw = readHW(*manifest, g.manifestKey)
	if err := g.reload(); err != nil {
		// Do NOT refuse to start: that takes the protected app down because of a bad or tampered rule
		// file (invariant 1, fail open). First try the last manifest that loaded cleanly; failing that
		// start with Coraza + CRS only. Say so loudly either way and keep watching the manifest.
		log.Printf("ERROR: initial rule load failed: %v", err)
		if err2 := g.restoreLastGood(); err2 == nil {
			log.Printf("restored the last-good manifest (v%d); the rejected file was replaced", g.rs.Load().version)
		} else {
			log.Printf("ERROR: %v. Starting with the OWASP Core Rule Set ONLY and NO AEGIS rules. "+
				"Restore the manifest (or delete it, to start empty).", err2)
			base, e3 := buildRuleSet(Manifest{}, g.staticInclude)
			if e3 != nil {
				log.Fatalf("cannot build the baseline rule set: %v", e3)
			}
			g.rs.Store(base)
		}
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("backend error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
	}
	g.proxy = proxy
	go writeLogs(*logPath, g.logs, *logMaxMB<<20)
	go g.watchManifest(500 * time.Millisecond)
	go func() {
		for range time.Tick(time.Minute) {
			g.rl.prune(time.Hour)
		}
	}()

	if *admin != "" {
		go func() {
			log.Printf("admin API on %s (loopback only)", *admin)
			log.Print(http.ListenAndServe(*admin, g.adminMux()))
		}()
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           g,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("AEGIS gateway: %s -> %s  mode=%s  manifest=%s  log=%s", *listen, *backend, *mode, *manifest, *logPath)
	log.Fatal(srv.ListenAndServe())
}

// isLoopbackAddr reports whether a listen address binds loopback only.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
