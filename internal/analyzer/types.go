package analyzer

import (
	"encoding/json"
	"time"
)

// Ecosystem identifies the package registry a dependency belongs to.
type Ecosystem string

const (
	NPM  Ecosystem = "npm"
	PyPI Ecosystem = "pypi"
)

// Package is a single dependency to analyze.
type Package struct {
	Ecosystem Ecosystem `json:"ecosystem"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	// Source is where the dependency was discovered (lockfile path or "cli").
	Source string `json:"source,omitempty"`
}

func (p Package) String() string {
	return string(p.Ecosystem) + ":" + p.Name + "@" + p.Version
}

// Severity ranks how dangerous a finding is.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// MarshalJSON renders severities as their human-readable names — JSON
// consumers should never need to know internal ordinal values.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// Score converts a severity into the weight used for the package risk score.
func (s Severity) Score() int {
	switch s {
	case SevCritical:
		return 100
	case SevHigh:
		return 40
	case SevMedium:
		return 15
	case SevLow:
		return 5
	default:
		return 1
	}
}

// Finding is a single suspicious signal detected in a package.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	// Detail explains why this matters, referencing real attack patterns.
	Detail string `json:"detail"`
	// File is the path inside the package archive where the signal was found
	// (empty for metadata findings).
	File string `json:"file,omitempty"`
	// Evidence is a short redacted excerpt of the matching content.
	Evidence string `json:"evidence,omitempty"`
}

// RiskLevel is the aggregated verdict for a package.
type RiskLevel int

const (
	RiskClean RiskLevel = iota
	RiskLow
	RiskMedium
	RiskHigh
	RiskCritical
)

func (r RiskLevel) String() string {
	switch r {
	case RiskCritical:
		return "CRITICAL"
	case RiskHigh:
		return "HIGH"
	case RiskMedium:
		return "MEDIUM"
	case RiskLow:
		return "LOW"
	default:
		return "CLEAN"
	}
}

// Result is the full analysis outcome for one package.
type Result struct {
	Package    Package       `json:"package"`
	Risk       RiskLevel     `json:"risk"`
	Score      int           `json:"score"`
	Findings   []Finding     `json:"findings,omitempty"`
	Err        string        `json:"error,omitempty"`
	Elapsed    time.Duration `json:"-"`
	DurationMS int64         `json:"duration_ms"`
	// FilesScanned is how many files inside the archive were inspected.
	FilesScanned int `json:"files_scanned"`
	// Suppressed counts findings accepted by the baseline file.
	Suppressed int `json:"suppressed,omitempty"`
}

// MarshalJSON renders risk levels as their human-readable names.
func (r RiskLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

// riskFromScore maps an accumulated score to a verdict.
func riskFromScore(score int) RiskLevel {
	switch {
	case score >= 100:
		return RiskCritical
	case score >= 40:
		return RiskHigh
	case score >= 15:
		return RiskMedium
	case score >= 5:
		return RiskLow
	default:
		return RiskClean
	}
}
