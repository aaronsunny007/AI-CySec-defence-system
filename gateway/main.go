// Command gateway is the AEGIS enforcement plane: a reverse proxy that runs
// every request through OWASP Coraza + the OWASP Core Rule Set before
// forwarding it to the protected app.
//
// Invariants (see CLAUDE.md §2):
//   - Fail open. Any error or panic inside the WAF path forwards the request
//     unmodified and is logged with fail_open=true.
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

// maxBody caps how much request body we buffer and inspect. Larger bodies are
// forwarded but only the first maxBody bytes are inspected and logged.
const maxBody = 1 << 20 // 1 MiB

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
	// (bearer token / session cookie, else client IP). Lets the observer
	// reconstruct one actor across requests without logging secrets. NOT a
	// detection signal on its own -- actors are grouped by it, then judged on
	// behaviour.
	Session      string   `json:"session"`
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
}

// rateRule is one gateway-native rate limit, compiled from a rate_limit IR by
// ir/compile.compile_rate. Enforced per actor (session) with a sliding window.
type rateRule struct {
	ID             string   `json:"id"`
	AttackClass    string   `json:"attack_class"`
	EndpointPrefix string   `json:"endpoint_prefix"`
	Methods        []string `json:"methods"`
	Count          int      `json:"count"`
	WindowS        int      `json:"window_s"`
}

func (rr rateRule) matches(method, path string) bool {
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

// rateLimiter holds per-(actor,rule) hit timestamps and the same sliding-window
// logic the gate validates (gate/ratelimit.py). Mirror the two deliberately.
type rateLimiter struct {
	mu    sync.Mutex
	rules []rateRule
	hits  map[string][]time.Time
}

// check reports whether this request exceeds any rate rule for this actor. It
// records the hit first, then counts the trailing window: block the (count+1)-th
// and beyond. Returns the offending rule id, or "" if within limits.
func (rl *rateLimiter) check(actor, method, path string) string {
	if rl == nil || len(rl.rules) == 0 {
		return ""
	}
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for i := range rl.rules {
		rr := rl.rules[i]
		if !rr.matches(method, path) {
			continue
		}
		key := actor + "\x00" + rr.ID
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
			return rr.ID
		}
	}
	return ""
}

func loadRateRules(path string) ([]rateRule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []rateRule
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

type gateway struct {
	waf     coraza.WAF
	proxy   *httputil.ReverseProxy
	logs    chan Record
	enforce bool
	rl      *rateLimiter
	dropped atomic.Int64
}

func newWAF(extra string) (coraza.WAF, error) {
	directives := `
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine On
SecResponseBodyAccess Off
` + extra
	return coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(directives).
		WithRootFS(mergefs.Merge(coreruleset.FS, mergefsio.OSFS)))
}

// sessionID derives a stable, non-reversible actor fingerprint. It prefers the
// bearer token, then Juice Shop's auth cookies, then the session cookie id,
// and finally falls back to the client IP. The raw value is hashed so no token
// or cookie is ever written to the log.
func sessionID(r *http.Request, ip string) string {
	raw := ""
	// aegis_vid: a per-client nonce the range sets so one client maps to one
	// actor for its whole lifecycle (anonymous + logged in). It stands in for
	// the distinct source IPs a real deployment has; see docs/DECISIONS.md. The
	// observer uses the resulting actor id only to GROUP requests, never as a
	// detection feature.
	if c, err := r.Cookie("aegis_vid"); err == nil && c.Value != "" {
		raw = "v:" + c.Value
	} else if a := r.Header.Get("Authorization"); a != "" {
		raw = "b:" + a
	} else if c, err := r.Cookie("token"); err == nil && c.Value != "" {
		raw = "t:" + c.Value
	} else if c, err := r.Cookie("continueCode"); err == nil && c.Value != "" {
		raw = "c:" + c.Value
	} else if c, err := r.Cookie("connect.sid"); err == nil && c.Value != "" {
		raw = "s:" + c.Value
	}
	if raw == "" {
		return "ip:" + ip
	}
	sum := sha256.Sum256([]byte(raw))
	return "h:" + hex.EncodeToString(sum[:8])
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
// means allow) and fills the WAF fields of rec. A panic inside Coraza is
// converted into an error so the caller can fail open.
func (g *gateway) inspect(r *http.Request, body []byte, rec *Record) (it *types.Interruption, err error) {
	defer func() {
		if p := recover(); p != nil {
			it, err = nil, fmt.Errorf("panic: %v", p)
		}
	}()

	tx := g.waf.NewTransactionWithID(rec.ID)
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
			return nil, err
		}
	}
	if it == nil {
		if it, err = tx.ProcessRequestBody(); err != nil {
			return nil, err
		}
	}

	tags := map[string]bool{}
	ids := map[string]bool{}
	for _, mr := range tx.MatchedRules() {
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
	return it, nil
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
		Session:       sessionID(r, ip),
		RuleIDs:       []string{},
		AttackTags:    []string{},
		Mode:          map[bool]string{true: "enforce", false: "detect"}[g.enforce],
	}

	// Buffer up to maxBody for inspection; stitch the rest back on for the app.
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err != nil {
			rec.FailOpen, rec.FailReason = true, "body read: "+err.Error()
		}
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(body), r.Body), r.Body}
	}
	rec.Body = string(body)
	rec.BodyLen = len(body)
	if r.ContentLength > int64(len(body)) {
		rec.BodyLen = int(r.ContentLength)
	}

	// Rate-limit check (stateful, per-actor). Independent of the WAF; a panic
	// here must not take the app down, so guard it and fail open.
	rateHit := ""
	func() {
		defer func() { _ = recover() }()
		rateHit = g.rl.check(rec.Session, r.Method, r.URL.Path)
	}()
	rec.RateRule = rateHit

	var it *types.Interruption
	if !rec.FailOpen {
		wafStart := time.Now()
		var err error
		it, err = g.inspect(r, body, &rec)
		rec.WAFMicros = time.Since(wafStart).Microseconds()
		if err != nil {
			it = nil
			rec.FailOpen, rec.FailReason = true, err.Error()
		}
	}

	sw := &statusWriter{ResponseWriter: w}
	switch {
	case rateHit != "" && g.enforce:
		rec.Blocked = true
		sw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		sw.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(sw, "Rate limit exceeded (AEGIS %s, ref %s)\n", rateHit, rec.ID)
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
		g.proxy.ServeHTTP(sw, r)
	}

	rec.Status = sw.status
	rec.TotalMicros = time.Since(start).Microseconds()
	select {
	case g.logs <- rec:
	default:
		g.dropped.Add(1) // never block the request path on logging
	}
}

func writeLogs(path string, in <-chan Record) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Fatalf("log dir: %v", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("open log: %v", err)
	}
	bw := bufio.NewWriterSize(f, 64<<10)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	tick := time.NewTicker(500 * time.Millisecond)
	for {
		select {
		case rec := <-in:
			if err := enc.Encode(rec); err != nil {
				log.Printf("log write: %v", err)
			}
		case <-tick.C:
			_ = bw.Flush()
		}
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "address to listen on")
	backend := flag.String("backend", "http://127.0.0.1:3000", "protected app URL")
	logPath := flag.String("log", "logs/gateway/requests.jsonl", "request log (JSONL, appended)")
	mode := flag.String("mode", "enforce", "enforce = block on CRS verdict; detect = log verdict, never block")
	rules := flag.String("rules", "", "optional extra rules file (loaded after CRS)")
	rateRulesPath := flag.String("raterules", "", "optional JSON file of AEGIS rate-limit rules")
	flag.Parse()

	if *mode != "enforce" && *mode != "detect" {
		log.Fatalf("-mode must be enforce or detect")
	}
	target, err := url.Parse(*backend)
	if err != nil {
		log.Fatalf("bad -backend: %v", err)
	}

	extra := ""
	if *rules != "" {
		extra = "Include " + filepath.ToSlash(*rules)
	}
	waf, err := newWAF(extra)
	if err != nil {
		log.Fatalf("load WAF: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("backend error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
	}

	var rl *rateLimiter
	if *rateRulesPath != "" {
		rrules, err := loadRateRules(*rateRulesPath)
		if err != nil {
			log.Fatalf("load rate rules: %v", err)
		}
		rl = &rateLimiter{rules: rrules, hits: make(map[string][]time.Time)}
		log.Printf("loaded %d rate-limit rule(s) from %s", len(rrules), *rateRulesPath)
	}

	g := &gateway{waf: waf, proxy: proxy, logs: make(chan Record, 8192),
		enforce: *mode == "enforce", rl: rl}
	go writeLogs(*logPath, g.logs)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           g,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("AEGIS gateway: %s -> %s  mode=%s  log=%s", *listen, *backend, *mode, *logPath)
	log.Fatal(srv.ListenAndServe())
}
