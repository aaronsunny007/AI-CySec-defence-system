// Command replay evaluates a single candidate rule against a corpus of recorded
// requests, through the REAL Coraza engine -- so the validation gate tests
// exactly what would enforce, not a Python approximation of it.
//
//	replay -rule candidate.conf -corpus benign.jsonl [-limit N]
//
// Loads Coraza with ONLY the candidate rule (no CRS), so the match rate is the
// candidate's own blast radius in isolation. Reads the AEGIS v1 request schema
// (one JSON object per line), reconstructs each request, and reports how many
// the candidate would block.
//
// Output (JSON, one object): {"total":N,"matched":M,"rate":M/N,"samples":[...]}.
// The gate reads this: matched/total on the benign corpus is the FP rate;
// matched/total on attack+mutation corpora is efficacy.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"
)

type record struct {
	Method      string `json:"method"`
	URI         string `json:"uri"`
	Body        string `json:"body"`
	Host        string `json:"host"`
	ContentType string `json:"content_type"`
	UserAgent   string `json:"user_agent"`
}

func buildWAF(ruleFile string) (coraza.WAF, error) {
	// Recommended base config only (request-body access, URL decoding, etc.),
	// then the single candidate rule. No CRS: we measure the candidate alone.
	dir := "Include @coraza.conf-recommended\nSecRuleEngine On\nSecResponseBodyAccess Off\n"
	dir += "Include " + ruleFile + "\n"
	return coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(dir).
		WithRootFS(mergefs.Merge(coreruleset.FS, mergefsio.OSFS)))
}

func blocks(waf coraza.WAF, r record) bool {
	tx := waf.NewTransaction()
	defer func() { tx.ProcessLogging(); _ = tx.Close() }()

	method := r.Method
	if method == "" {
		method = "GET"
	}
	tx.ProcessURI(r.URI, method, "HTTP/1.1")
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
	}
	if r.ContentType != "" {
		tx.AddRequestHeader("Content-Type", r.ContentType)
	}
	if r.UserAgent != "" {
		tx.AddRequestHeader("User-Agent", r.UserAgent)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return true
	}
	if r.Body != "" && tx.IsRequestBodyAccessible() {
		if _, _, err := tx.WriteRequestBody([]byte(r.Body)); err == nil {
			if it, _ := tx.ProcessRequestBody(); it != nil {
				return true
			}
		}
	} else {
		if it, _ := tx.ProcessRequestBody(); it != nil {
			return true
		}
	}
	// Any matched AEGIS rule counts (deny interruption is the normal path; this
	// also catches detection-only compiles).
	for _, mr := range tx.MatchedRules() {
		for _, t := range mr.Rule().Tags() {
			if t == "aegis" {
				return true
			}
		}
	}
	return false
}

func main() {
	ruleFile := flag.String("rule", "", "candidate SecRule file (required)")
	corpus := flag.String("corpus", "", "JSONL request corpus (required)")
	limit := flag.Int("limit", 0, "max records (0 = all)")
	nsamples := flag.Int("samples", 5, "matched samples to include")
	flag.Parse()
	if *ruleFile == "" || *corpus == "" {
		fmt.Fprintln(os.Stderr, "need -rule and -corpus")
		os.Exit(2)
	}

	waf, err := buildWAF(*ruleFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load rule: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Open(*corpus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open corpus: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	total, matched := 0, 0
	var samples []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r record
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		total++
		if blocks(waf, r) {
			matched++
			if len(samples) < *nsamples {
				samples = append(samples, r.Method+" "+r.URI)
			}
		}
		if *limit > 0 && total >= *limit {
			break
		}
	}

	rate := 0.0
	if total > 0 {
		rate = float64(matched) / float64(total)
	}
	out, _ := json.Marshal(map[string]any{
		"total": total, "matched": matched, "rate": rate, "samples": samples,
	})
	fmt.Println(string(out))
}
