package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testKey = []byte("test-key-not-a-secret")

func goodManifest() Manifest {
	return Manifest{Version: 5, Rules: []ManifestRule{
		{ID: "r1", Type: "rate", Mode: "enforce", Count: 5, WindowS: 60, EndpointPrefix: "/x"}}}
}

func TestSignedManifestRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.json")
	if err := writeManifest(p, goodManifest(), testKey); err != nil {
		t.Fatal(err)
	}
	m, err := readManifest(p, testKey)
	if err != nil || m.Version != 5 || len(m.Rules) != 1 {
		t.Fatalf("round trip failed: %v %+v", err, m)
	}
}

func TestSignedModeRefusesTamperedUnsignedAndWrongKey(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "m.json")
	if err := writeManifest(p, goodManifest(), testKey); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)

	// 1. payload edited on disk (rule switched to off), signature left as is
	tampered := strings.Replace(string(raw), `\"mode\": \"enforce\"`, `\"mode\": \"off\"`, 1)
	if tampered == string(raw) {
		t.Fatal("test bug: tamper did not change the file")
	}
	os.WriteFile(p, []byte(tampered), 0o644)
	if _, err := readManifest(p, testKey); err == nil {
		t.Error("tampered payload was accepted")
	}

	// 2. plain unsigned manifest while a key is configured
	if err := writeManifest(p, goodManifest(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifest(p, testKey); err == nil {
		t.Error("unsigned manifest was accepted in signed mode")
	}

	// 3. signed with a different key
	if err := writeManifest(p, goodManifest(), []byte("attacker-key")); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifest(p, testKey); err == nil {
		t.Error("manifest signed with the wrong key was accepted")
	}

	// 4. garbage
	os.WriteFile(p, []byte("not json"), 0o644)
	if _, err := readManifest(p, testKey); err == nil {
		t.Error("garbage was accepted")
	}
}

func TestUnsignedModeStillReadsPlainManifests(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.json")
	if err := writeManifest(p, goodManifest(), nil); err != nil {
		t.Fatal(err)
	}
	if m, err := readManifest(p, nil); err != nil || m.Version != 5 {
		t.Fatalf("unsigned read failed: %v", err)
	}
}

func TestAdminTokenGuardsMutations(t *testing.T) {
	called := 0
	h := requireToken([]byte("s3cret"), func(w http.ResponseWriter, r *http.Request) { called++ })
	for _, tc := range []struct {
		hdr  string
		want int
	}{{"", 401}, {"Bearer wrong", 401}, {"s3cret", 401}, {"Bearer s3cret", 200}} {
		req := httptest.NewRequest("POST", "/mode?id=a&mode=off", nil)
		if tc.hdr != "" {
			req.Header.Set("Authorization", tc.hdr)
		}
		w := httptest.NewRecorder()
		h(w, req)
		if w.Code != tc.want {
			t.Errorf("header %q: got %d want %d", tc.hdr, w.Code, tc.want)
		}
	}
	if called != 1 {
		t.Errorf("handler ran %d times, want 1", called)
	}
	// no token configured: open (loopback-only, as before)
	open := requireToken(nil, func(w http.ResponseWriter, r *http.Request) { called++ })
	w := httptest.NewRecorder()
	open(w, httptest.NewRequest("POST", "/mode", nil))
	if w.Code != 200 {
		t.Errorf("no-token mode should be open, got %d", w.Code)
	}
}

func TestReloadKeepsPreviousRulesOnBadOrOldManifest(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.json")
	g := &gateway{manifestPath: p, manifestKey: testKey}
	if err := writeManifest(p, goodManifest(), testKey); err != nil { // v5
		t.Fatal(err)
	}
	if err := g.reload(); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	if g.rs.Load().version != 5 {
		t.Fatal("v5 not loaded")
	}
	// replay of an older, validly signed manifest
	old := goodManifest()
	old.Version = 3
	writeManifest(p, old, testKey)
	if err := g.reload(); err == nil || g.rs.Load().version != 5 {
		t.Errorf("older signed manifest was not refused (err=%v)", err)
	}
	// unsigned manifest written by someone without the key
	bad := goodManifest()
	bad.Version = 9
	bad.Rules[0].Mode = "off"
	writeManifest(p, bad, nil)
	if err := g.reload(); err == nil || g.rs.Load().version != 5 {
		t.Errorf("unsigned manifest was not refused (err=%v)", err)
	}
	// a newer, correctly signed one is accepted
	good := goodManifest()
	good.Version = 6
	writeManifest(p, good, testKey)
	if err := g.reload(); err != nil || g.rs.Load().version != 6 {
		t.Errorf("valid newer manifest refused: %v", err)
	}
}

// Cross-language vector: tests/test_rulestore_signing.py asserts Python produces the same.
func TestSignatureMatchesPythonVector(t *testing.T) {
	got := signPayload(testKey, "abc")
	want := "51803ef0fd04de1cc4ee6975038f77e24a053eac7c93830ad6730f5930a98628"
	if got != want {
		t.Fatalf("HMAC mismatch: %s", got)
	}
}

// A validly signed OLDER manifest put on disk while the gateway is down must not be loaded on the
// next start: the high-water mark outlives the process.
func TestHighWaterMarkSurvivesRestart(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.json")
	g1 := &gateway{manifestPath: p, manifestKey: testKey}
	if err := writeManifest(p, goodManifest(), testKey); err != nil { // v5
		t.Fatal(err)
	}
	if err := g1.reload(); err != nil {
		t.Fatal(err)
	}
	// "restart": a new gateway object that reads the persisted mark, as main() does
	old := goodManifest()
	old.Version = 3
	writeManifest(p, old, testKey)
	g2 := &gateway{manifestPath: p, manifestKey: testKey}
	g2.hw = readHW(p, testKey)
	if g2.hw != 5 {
		t.Fatalf("high-water mark not persisted, got %d", g2.hw)
	}
	if err := g2.reload(); err == nil {
		t.Error("older signed manifest was accepted after a restart")
	}
	// a forged mark (wrong key) is ignored, not trusted
	os.WriteFile(hwPath(p), []byte(`{"v":999999,"sig":"00"}`), 0o644)
	if got := readHW(p, testKey); got != 0 {
		t.Errorf("forged high-water mark was honoured: %d", got)
	}
}

// A corrupt or rolled-back manifest at startup is replaced by the last good one: no lost rules.
func TestStartupRestoresLastGoodManifest(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.json")
	g1 := &gateway{manifestPath: p, manifestKey: testKey}
	if err := writeManifest(p, goodManifest(), testKey); err != nil { // v5
		t.Fatal(err)
	}
	if err := g1.reload(); err != nil {
		t.Fatal(err)
	}
	for name, corrupt := range map[string]func(){
		"garbage":     func() { os.WriteFile(p, []byte("{not json"), 0o644) },
		"unsigned":    func() { writeManifest(p, goodManifest(), nil) },
		"rolled back": func() { old := goodManifest(); old.Version = 2; writeManifest(p, old, testKey) },
	} {
		corrupt()
		g := &gateway{manifestPath: p, manifestKey: testKey}
		g.hw = readHW(p, testKey)
		if err := g.reload(); err == nil {
			t.Fatalf("%s: the bad manifest was accepted", name)
		}
		if err := g.restoreLastGood(); err != nil {
			t.Fatalf("%s: could not restore: %v", name, err)
		}
		if g.rs.Load() == nil || g.rs.Load().version != 5 {
			t.Errorf("%s: last-good v5 not restored", name)
		}
		if _, err := readManifest(p, testKey); err != nil {
			t.Errorf("%s: the manifest file was not healed: %v", name, err)
		}
	}
	// with no last-good copy there is nothing to restore (caller falls back to CRS only)
	os.Remove(goodPath(p))
	os.WriteFile(p, []byte("{not json"), 0o644)
	g := &gateway{manifestPath: p, manifestKey: testKey}
	if err := g.restoreLastGood(); err == nil {
		t.Error("restore with no last-good copy should fail")
	}
}
