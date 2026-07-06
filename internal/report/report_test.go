package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sandtrap-sh/sandtrap/internal/analyzer"
)

func sampleSummary() *Summary {
	return &Summary{
		Scanned:    3,
		Errors:     1,
		Suppressed: 2,
		Elapsed:    1500 * time.Millisecond,
		ByRisk:     map[string]int{"CLEAN": 1, "CRITICAL": 1},
		worst:      analyzer.RiskCritical,
		Results: []analyzer.Result{
			{
				Package: analyzer.Package{Ecosystem: analyzer.NPM, Name: "evil-pkg", Version: "1.0.0", Source: "package-lock.json"},
				Risk:    analyzer.RiskCritical, Score: 120,
				Findings: []analyzer.Finding{{
					RuleID: "install-scripts", Severity: analyzer.SevCritical,
					Title: "npm lifecycle hook: postinstall", Detail: "fetches code at install time",
					Evidence: `curl x | sh`,
				}, {
					RuleID: "obfuscation", Severity: analyzer.SevMedium,
					Title: "possible obfuscation", Detail: "two signals", File: "index.js",
				}},
			},
			{Package: analyzer.Package{Ecosystem: analyzer.NPM, Name: "ok-pkg", Version: "2.0.0"}, Risk: analyzer.RiskClean},
			{Package: analyzer.Package{Ecosystem: analyzer.PyPI, Name: "broken", Version: "0.1"}, Err: "network"},
		},
	}
}

func TestJSONReportSchema(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleSummary(), Meta{Version: "test", Targets: []string{"package-lock.json"}, FailOn: "high"}); err != nil {
		t.Fatal(err)
	}
	var r map[string]any
	if err := json.Unmarshal(buf.Bytes(), &r); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	for _, key := range []string{"schema", "tool", "scan", "summary", "rules", "results"} {
		if _, ok := r[key]; !ok {
			t.Fatalf("missing top-level key %q", key)
		}
	}
	out := buf.String()
	// Severities and risks must be human-readable strings, never ordinals.
	if !strings.Contains(out, `"severity": "CRITICAL"`) || !strings.Contains(out, `"risk": "CRITICAL"`) {
		t.Fatalf("severity/risk must serialize as strings:\n%s", out)
	}
	// Rules section must document every rule that fired, with remediation.
	rules := r["rules"].(map[string]any)
	for _, id := range []string{"install-scripts", "obfuscation"} {
		m, ok := rules[id].(map[string]any)
		if !ok {
			t.Fatalf("rules section missing %q", id)
		}
		if m["remediation"] == "" || m["description"] == "" {
			t.Fatalf("rule %q missing remediation/description", id)
		}
	}
	if r["summary"].(map[string]any)["flagged"].(float64) != 1 {
		t.Fatalf("flagged should count non-clean non-error results")
	}
}

func TestSARIFStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sampleSummary(), Meta{Version: "test"}); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Message   struct{ Text string }
				Locations []any `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("want SARIF 2.1.0 with one run")
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "sandtrap" || len(run.Tool.Driver.Rules) < 5 {
		t.Fatalf("driver must carry the full rule catalog, got %d rules", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Fatalf("want 2 results (one per finding), got %d", len(run.Results))
	}
	levels := map[string]bool{}
	for _, res := range run.Results {
		levels[res.Level] = true
		if len(res.Locations) == 0 {
			t.Fatalf("every SARIF result needs a location")
		}
	}
	if !levels["error"] || !levels["warning"] {
		t.Fatalf("CRITICAL→error and MEDIUM→warning mapping broken: %v", levels)
	}
}

func TestSARIFEmptyScanIsValid(t *testing.T) {
	var buf bytes.Buffer
	s := &Summary{ByRisk: map[string]int{}}
	if err := SARIF(&buf, s, Meta{Version: "test"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"results": []`) {
		t.Fatal("clean scans must emit an empty results array, not null (spec requirement)")
	}
}

func TestRebuildAfterRetryMerge(t *testing.T) {
	results := []analyzer.Result{
		{Package: analyzer.Package{Ecosystem: analyzer.NPM, Name: "a", Version: "1"}, Risk: analyzer.RiskClean},
		{Package: analyzer.Package{Ecosystem: analyzer.NPM, Name: "b", Version: "1"}, Risk: analyzer.RiskHigh, Score: 40, Suppressed: 1},
		{Package: analyzer.Package{Ecosystem: analyzer.NPM, Name: "c", Version: "1"}, Err: "still failing"},
	}
	s := Rebuild(results, 5*time.Second)
	if s.Scanned != 3 || s.Errors != 1 || s.Suppressed != 1 {
		t.Fatalf("aggregates wrong: %+v", s)
	}
	if s.worst != analyzer.RiskHigh || s.ByRisk["HIGH"] != 1 || s.ByRisk["CLEAN"] != 2 {
		t.Fatalf("risk aggregation wrong: worst=%v byRisk=%v", s.worst, s.ByRisk)
	}
	if s.Results[0].Risk != analyzer.RiskHigh {
		t.Fatal("results must be sorted worst-first")
	}
}
