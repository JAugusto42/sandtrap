package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/JAugusto42/sandtrap/internal/analyzer"
	"github.com/JAugusto42/sandtrap/internal/heuristics"
)

// Meta carries run-level context the CLI knows and the report layer doesn't.
type Meta struct {
	Version string   // tool version stamp
	Targets []string // lockfiles scanned, or "cli" for check mode
	FailOn  string   // configured threshold, so consumers know the gate
}

// jsonReport is the machine-readable report envelope. The shape follows the
// conventions of mature security scanners (tool block, scan block, rule
// catalog referenced by ID, then results): stable top-level keys that
// downstream dashboards and scripts can rely on.
type jsonReport struct {
	Schema string `json:"schema"` // report format version, semver
	Tool   struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Homepage string `json:"homepage"`
	} `json:"tool"`
	Scan struct {
		StartedAt       time.Time `json:"started_at"`
		DurationMS      int64     `json:"duration_ms"`
		Targets         []string  `json:"targets,omitempty"`
		PackagesScanned int       `json:"packages_scanned"`
		Errors          int       `json:"errors"`
		Suppressed      int       `json:"suppressed"`
		FailOn          string    `json:"fail_on"`
	} `json:"scan"`
	Summary struct {
		ByRisk    map[string]int `json:"by_risk"`
		Flagged   int            `json:"flagged"`
		WorstRisk string         `json:"worst_risk"`
	} `json:"summary"`
	// Rules holds full metadata (description, remediation, references) for
	// every rule that produced at least one finding; findings reference
	// them by rule_id to avoid repeating prose per finding.
	Rules   map[string]heuristics.RuleMeta `json:"rules"`
	Results []analyzer.Result              `json:"results"`
}

// JSON writes the structured machine-readable report.
func JSON(w io.Writer, s *Summary, meta Meta) error {
	var r jsonReport
	r.Schema = "sandtrap-report/1"
	r.Tool.Name = "sandtrap"
	r.Tool.Version = meta.Version
	r.Tool.Homepage = "https://github.com/JAugusto42/sandtrap"

	r.Scan.StartedAt = time.Now().Add(-s.Elapsed).UTC()
	r.Scan.DurationMS = s.Elapsed.Milliseconds()
	r.Scan.Targets = meta.Targets
	r.Scan.PackagesScanned = s.Scanned
	r.Scan.Errors = s.Errors
	r.Scan.Suppressed = s.Suppressed
	r.Scan.FailOn = meta.FailOn

	r.Summary.ByRisk = s.ByRisk
	r.Summary.WorstRisk = s.worst.String()

	catalog := heuristics.Catalog()
	r.Rules = map[string]heuristics.RuleMeta{}
	for _, res := range s.Results {
		if res.Risk > analyzer.RiskClean && res.Err == "" {
			r.Summary.Flagged++
		}
		for _, f := range res.Findings {
			if m, ok := catalog[f.RuleID]; ok {
				r.Rules[f.RuleID] = m
			}
		}
	}
	r.Results = s.Results

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
