package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testGateway runs the real gateway (Coraza + CRS) in front of a backend that records what reaches it.
func testGateway(t *testing.T, mutate func(*gateway)) (gwURL string, reached *atomic.Int64, g *gateway) {
	t.Helper()
	reached = &atomic.Int64{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		reached.Add(1)
		w.Write([]byte("ok"))
	}))
	t.Cleanup(backend.Close)
	u, _ := url.Parse(backend.URL)
	g = &gateway{logs: make(chan Record, 256), enforce: true, rl: newRateLimiter(),
		cnt: map[string]*ruleCounters{}, slices: [2]*sliceStats{newSlice(), newSlice()},
		maxBody: 4096, oversize: "reject", logBodyMax: defaultLogBodyMax}
	if mutate != nil {
		mutate(g)
	}
	rs, err := buildRuleSet(Manifest{Version: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	g.rs.Store(rs)
	g.proxy = httputil.NewSingleHostReverseProxy(u)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	return srv.URL, reached, g
}

func post(t *testing.T, url, ctype, body string, hdr map[string]string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", url+"/login", strings.NewReader(body))
	req.Header.Set("Content-Type", ctype)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func lastRecord(t *testing.T, g *gateway) Record {
	t.Helper()
	select {
	case r := <-g.logs:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("no log record")
		return Record{}
	}
}

const sqli = "q=1' OR 1=1-- "

// The bug: padding the body past the inspected prefix carried a payload straight to the app.
func TestOversizeBodyCannotSmuggleAPayload(t *testing.T) {
	url, reached, _ := testGateway(t, nil)
	ct := "application/x-www-form-urlencoded"
	if c := post(t, url, ct, sqli, nil); c != 403 {
		t.Fatalf("control: plain SQLi should be blocked, got %d", c)
	}
	padded := "pad=" + strings.Repeat("A", 5000) + "&" + sqli
	if c := post(t, url, ct, padded, nil); c != http.StatusRequestEntityTooLarge {
		t.Errorf("padded body must be refused with 413, got %d", c)
	}
	if reached.Load() != 0 {
		t.Errorf("the backend received %d request(s); none should have got through", reached.Load())
	}
}

func TestOversizePassPolicyForwardsButFlags(t *testing.T) {
	url, reached, g := testGateway(t, func(g *gateway) { g.oversize = "pass" })
	if c := post(t, url, "application/x-www-form-urlencoded", "pad="+strings.Repeat("A", 9000), nil); c != 200 {
		t.Errorf("pass policy should forward, got %d", c)
	}
	if reached.Load() != 1 {
		t.Error("backend did not receive the large body")
	}
	if r := lastRecord(t, g); !r.Oversize {
		t.Error("an uninspected body must be flagged oversize in the log")
	}
}

// A body exactly at the cap is inspected in full and still blocked.
func TestBodyAtTheCapIsStillInspected(t *testing.T) {
	url, _, _ := testGateway(t, nil)
	body := sqli + "&pad=" + strings.Repeat("A", 4096-len(sqli)-5)
	if len(body) != 4096 {
		t.Fatalf("test setup: %d", len(body))
	}
	if c := post(t, url, "application/x-www-form-urlencoded", body, nil); c != 403 {
		t.Errorf("SQLi inside a body exactly at the cap must be blocked, got %d", c)
	}
}

func TestVisitorCookieIsIgnoredOutsideRangeMode(t *testing.T) {
	url, _, g := testGateway(t, nil)
	post(t, url, "application/json", `{"a":1}`, map[string]string{"Cookie": "aegis_vid=atk-evade-1"})
	r := lastRecord(t, g)
	if !strings.HasPrefix(r.Session, "ip:") || r.Ident != "ip" || r.GTLabel != "" {
		t.Errorf("aegis_vid must not set identity or ground truth in production: session=%q ident=%q gt=%q", r.Session, r.Ident, r.GTLabel)
	}
	url2, _, g2 := testGateway(t, func(g *gateway) { g.rangeMode = true })
	post(t, url2, "application/json", `{"a":1}`, map[string]string{"Cookie": "aegis_vid=benign-1"})
	r2 := lastRecord(t, g2)
	if !strings.HasPrefix(r2.Session, "h:") || r2.Ident != "vid" || r2.GTLabel != "benign" {
		t.Errorf("range mode should honour it: session=%q ident=%q gt=%q", r2.Session, r2.Ident, r2.GTLabel)
	}
}

func TestLogNeverContainsPasswordsOrTokens(t *testing.T) {
	url, _, g := testGateway(t, nil)
	req, _ := http.NewRequest("POST", url+"/rest/user/login?token=abc123secrettoken",
		strings.NewReader(`{"email":"victim@example.com","password":"Sup3rS3cret!"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	r := lastRecord(t, g)
	for _, leak := range []string{"Sup3rS3cret", "abc123secrettoken"} {
		if strings.Contains(r.Body, leak) || strings.Contains(r.URI, leak) {
			t.Errorf("secret %q reached the log: uri=%q body=%q", leak, r.URI, r.Body)
		}
	}
	if !strings.Contains(r.Body, "victim@example.com") || !strings.Contains(r.Body, `"password"`) {
		t.Errorf("the account and the password KEY must remain for the observer: %q", r.Body)
	}
}

func TestLogBodyIsCapped(t *testing.T) {
	url, _, g := testGateway(t, func(g *gateway) { g.maxBody = 1 << 20; g.logBodyMax = 100 })
	post(t, url, "application/x-www-form-urlencoded", "pad="+strings.Repeat("A", 4996), nil)
	r := lastRecord(t, g)
	if len(r.Body) != 100 || r.BodyLen != 5000 {
		t.Errorf("logged %d bytes (want 100), body_len=%d (want 5000)", len(r.Body), r.BodyLen)
	}
}
