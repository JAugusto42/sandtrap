package heuristics

import (
	"fmt"
	"time"

	"github.com/sandtrap-sh/sandtrap/internal/analyzer"
	"github.com/sandtrap-sh/sandtrap/internal/registry"
)

// FreshPublish raises awareness for versions published very recently. The
// axios compromise was live for roughly three hours; installing a version
// minutes after release is when you are most exposed to a hijacked release.
// This is informational by design — freshness alone is not malice, but it
// amplifies the weight of other findings during triage.
type FreshPublish struct{}

func (FreshPublish) ID() string { return "fresh-publish" }

func (FreshPublish) Check(a *registry.Artifact) []analyzer.Finding {
	if a.Meta.PublishedAt.IsZero() {
		return nil
	}
	age := time.Since(a.Meta.PublishedAt)
	var out []analyzer.Finding

	switch {
	case age < 24*time.Hour:
		out = append(out, analyzer.Finding{
			RuleID: "fresh-publish", Severity: analyzer.SevMedium,
			Title:  "version published in the last 24h",
			Detail: fmt.Sprintf("Published %s ago. Hijacked releases are typically detected and yanked within hours-to-days; pinning to a version that has survived a few days drastically reduces compromise-window risk.", roundDur(age)),
		})
	case age < 7*24*time.Hour:
		out = append(out, analyzer.Finding{
			RuleID: "fresh-publish", Severity: analyzer.SevLow,
			Title:  "version published in the last 7 days",
			Detail: fmt.Sprintf("Published %s ago — still inside the typical detection window for hijacked releases.", roundDur(age)),
		})
	}

	// Brand-new package (not just version): common for typosquats and
	// dependency-confusion placeholders.
	if !a.Meta.FirstPublishedAt.IsZero() && time.Since(a.Meta.FirstPublishedAt) < 30*24*time.Hour {
		out = append(out, analyzer.Finding{
			RuleID: "fresh-publish", Severity: analyzer.SevMedium,
			Title:  "package created less than 30 days ago",
			Detail: "Very young packages are the primary vehicle for typosquatting and dependency-confusion attacks.",
		})
	}
	return out
}

func roundDur(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
