package heuristics

import (
	"regexp"

	"github.com/JAugusto42/sandtrap/internal/analyzer"
	"github.com/JAugusto42/sandtrap/internal/registry"
)

// Exfiltration flags network primitives commonly used to ship stolen secrets
// out of developer machines and CI runners. The April 2026 wave that hit npm,
// PyPI and Docker Hub in 48h targeted exactly this: API keys, cloud
// credentials, SSH keys and CI tokens.
type Exfiltration struct{}

func (Exfiltration) ID() string { return "exfiltration" }

var (
	// Disposable/exfil-friendly endpoints seen across recent campaigns.
	reExfilHost = regexp.MustCompile(
		`(?i)https?://(?:[a-z0-9-]+\.)?(webhook\.site|discord(?:app)?\.com/api/webhooks|` +
			`pipedream\.net|requestbin\.[a-z]+|burpcollaborator\.net|oastify\.com|` +
			`interact\.sh|pastebin\.com/raw|transfer\.sh|termbin\.com|ngrok(?:-free)?\.(?:io|app))`)
	// Hardcoded raw-IP HTTP endpoints (C2 style) — excludes loopback/private.
	reRawIP = regexp.MustCompile(
		`https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/`)
	rePrivateIP = regexp.MustCompile(
		`https?://(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0|localhost|` +
			// documentation/example addresses: 1.2.3.4 and RFC 5737 TEST-NETs
			`1\.2\.3\.4|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|255\.255\.255\.255)`)
	// Shell one-liners that fetch-and-execute inside source files.
	rePipeShell = regexp.MustCompile(
		`(?i)(curl|wget)[^\n|]{0,200}\|\s*(sudo\s+)?(sh|bash|zsh)\b`)
	// Mass environment harvesting — the classic first line of a stealer.
	reEnvDump = regexp.MustCompile(
		`JSON\.stringify\s*\(\s*process\.env\s*\)|` +
			`(?m)^.*(urlencode|b64encode|dumps)\s*\(\s*(dict\s*\()?\s*os\.environ`)
)

func (Exfiltration) Check(a *registry.Artifact) []analyzer.Finding {
	var out []analyzer.Finding
	for _, f := range a.Files {
		if !isCodeFile(f.Path) && ext(f.Path) != ".json" && ext(f.Path) != ".yml" && ext(f.Path) != ".yaml" {
			continue
		}
		c := string(f.Content)

		if m := reExfilHost.FindString(c); m != "" {
			out = append(out, analyzer.Finding{
				RuleID: "exfiltration", Severity: adjustForTestPath(analyzer.SevCritical, f.Path),
				Title:  "known exfiltration endpoint",
				Detail: "References a disposable webhook/tunnel service used to receive stolen data. No legitimate library ships hardcoded endpoints like this.",
				File:   f.Path, Evidence: truncate(m, 120),
			})
		}
		if m := reRawIP.FindString(c); m != "" && !rePrivateIP.MatchString(m) {
			out = append(out, analyzer.Finding{
				RuleID: "exfiltration", Severity: adjustForTestPath(analyzer.SevHigh, f.Path),
				Title:  "hardcoded raw-IP endpoint",
				Detail: "HTTP requests to a hardcoded public IP bypass DNS-based monitoring — a common C2/exfil pattern.",
				File:   f.Path, Evidence: truncate(m, 80),
			})
		}
		if m := rePipeShell.FindString(c); m != "" {
			out = append(out, analyzer.Finding{
				RuleID: "exfiltration", Severity: adjustForTestPath(analyzer.SevCritical, f.Path),
				Title:  "fetch-and-execute (pipe to shell)",
				Detail: "Downloads and executes remote code in one step. Stage-two loaders in the 2026 campaigns use this to pull the real payload after install.",
				File:   f.Path, Evidence: truncate(m, 120),
			})
		}
		if m := reEnvDump.FindString(c); m != "" {
			out = append(out, analyzer.Finding{
				RuleID: "exfiltration", Severity: adjustForTestPath(analyzer.SevHigh, f.Path),
				Title:  "bulk environment variable capture",
				Detail: "Serializes the entire process environment — where CI systems inject cloud keys, npm tokens and GitHub PATs. Combined with any network call this is a credential stealer.",
				File:   f.Path, Evidence: truncate(m, 120),
			})
		}
	}
	return out
}
