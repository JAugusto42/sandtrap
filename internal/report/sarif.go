package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/JAugusto42/sandtrap/internal/analyzer"
	"github.com/JAugusto42/sandtrap/internal/heuristics"
)

// SARIF (Static Analysis Results Interchange Format) 2.1.0 output. This is
// the lingua franca of security tooling: GitHub code scanning ingests it
// natively (upload-sarif action), as do most vulnerability dashboards.
// Only the subset of the spec we need is modeled here.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Name           string      `json:"name"`
			Version        string      `json:"version"`
			InformationURI string      `json:"informationUri"`
			Rules          []sarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	FullDescription struct {
		Text string `json:"text"`
	} `json:"fullDescription"`
	Help struct {
		Text string `json:"text"`
	} `json:"help"`
	HelpURI string `json:"helpUri,omitempty"`
}

type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"` // error | warning | note
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []sarifLocation `json:"locations"`
	// Properties carries sandtrap-specific context GitHub renders as metadata.
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
	} `json:"physicalLocation"`
	LogicalLocations []struct {
		FullyQualifiedName string `json:"fullyQualifiedName"`
	} `json:"logicalLocations,omitempty"`
}

func sarifLevel(sev analyzer.Severity) string {
	switch {
	case sev >= analyzer.SevHigh:
		return "error"
	case sev == analyzer.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

// SARIF writes the scan results as a SARIF 2.1.0 log.
func SARIF(w io.Writer, s *Summary, meta Meta) error {
	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    make([]sarifRun, 1),
	}
	run := &log.Runs[0]
	run.Tool.Driver.Name = "sandtrap"
	run.Tool.Driver.Version = meta.Version
	run.Tool.Driver.InformationURI = "https://github.com/JAugusto42/sandtrap"

	// Emit the full rule catalog so viewers can render help even for rules
	// with no findings in this run.
	for _, m := range heuristics.Catalog() {
		var r sarifRule
		r.ID = m.ID
		r.Name = m.Name
		r.ShortDescription.Text = m.Name
		r.FullDescription.Text = m.Description
		r.Help.Text = m.Remediation
		if len(m.References) > 0 {
			r.HelpURI = m.References[0]
		}
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, r)
	}

	run.Results = []sarifResult{} // valid empty array on clean scans
	for _, res := range s.Results {
		for _, f := range res.Findings {
			var sr sarifResult
			sr.RuleID = f.RuleID
			sr.Level = sarifLevel(f.Severity)
			msg := fmt.Sprintf("[%s] %s@%s: %s — %s",
				f.Severity, res.Package.Name, res.Package.Version, f.Title, f.Detail)
			if f.Evidence != "" {
				msg += fmt.Sprintf(" Evidence: %q", f.Evidence)
			}
			sr.Message.Text = msg

			// Physical location: the lockfile that pulled the dependency in
			// (that's the file the developer can act on); logical location:
			// the exact file inside the package archive.
			var loc sarifLocation
			uri := res.Package.Source
			if uri == "" || uri == "cli" {
				uri = string(res.Package.Ecosystem) + "/" + res.Package.Name
			}
			loc.PhysicalLocation.ArtifactLocation.URI = uri
			if f.File != "" {
				loc.LogicalLocations = append(loc.LogicalLocations, struct {
					FullyQualifiedName string `json:"fullyQualifiedName"`
				}{FullyQualifiedName: res.Package.String() + "/" + f.File})
			}
			sr.Locations = []sarifLocation{loc}

			sr.Properties = map[string]any{
				"package":   res.Package.String(),
				"ecosystem": res.Package.Ecosystem,
				"risk":      res.Risk.String(),
				"score":     res.Score,
			}
			run.Results = append(run.Results, sr)
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}
