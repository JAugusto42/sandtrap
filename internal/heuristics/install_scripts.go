package heuristics

import (
	"regexp"
	"strings"

	"github.com/sandtrap-sh/sandtrap/internal/analyzer"
	"github.com/sandtrap-sh/sandtrap/internal/registry"
)

// InstallScripts flags lifecycle hooks that execute code automatically at
// install time. This is the #1 initial-execution vector: Shai-Hulud, Mini
// Shai-Hulud and the axios compromise all detonated via install hooks or
// import-time payloads.
type InstallScripts struct{}

func (InstallScripts) ID() string { return "install-scripts" }

// Patterns inside a hook command that escalate it from "suspicious by
// existence" to "actively dangerous".
var dangerousHookPattern = regexp.MustCompile(
	`(?i)(curl|wget|iwr|invoke-webrequest)\s|` + // remote fetch
		`\|\s*(sh|bash|zsh|node|python)\b|` + // pipe-to-shell
		`node\s+-e\s|python[23]?\s+-c\s|` + // inline interpreters
		`base64\s+(-d|--decode)|` + // decode-and-run staging
		`\beval\b|\$\(\s*echo`, // command substitution tricks
)

// benignHookPattern matches commands overwhelmingly used by legitimate
// packages; they stay visible as LOW instead of MEDIUM to keep noise down —
// low false-positive rate is what makes a scanner actually get used.
var benignHookPattern = regexp.MustCompile(
	`(?i)^(node-gyp rebuild|husky( install)?|opencollective(-postinstall)?|patch-package)\b`)

func (InstallScripts) Check(a *registry.Artifact) []analyzer.Finding {
	var out []analyzer.Finding
	for hook, cmd := range a.Meta.InstallScripts {
		if hook == "setup.py" {
			// Presence alone is normal for Python sdists; content is covered
			// by the file-level rules. Only note it as context.
			out = append(out, analyzer.Finding{
				RuleID:   "install-scripts",
				Severity: analyzer.SevInfo,
				Title:    "sdist executes setup.py on install",
				Detail:   "Code in setup.py runs during `pip install`. File-level rules below inspect its content.",
				File:     "setup.py",
			})
			continue
		}
		// prepare/postprepare do NOT run when a consumer installs the
		// published tarball from the registry — only for git deps and local
		// development. Report as info so triage still sees them.
		if strings.HasPrefix(hook, "prepare") || strings.HasSuffix(hook, "prepare") {
			out = append(out, analyzer.Finding{
				RuleID:   "install-scripts",
				Severity: analyzer.SevInfo,
				Title:    "npm lifecycle hook (dev-only): " + hook,
				Detail:   "Runs for git dependencies and local development, not on registry installs.",
				Evidence: truncate(cmd, 160),
			})
			continue
		}
		sev := analyzer.SevMedium
		detail := "Lifecycle hooks run arbitrary code during `npm install`. Most benign packages do not need them; every Shai-Hulud wave used them as the detonation point."
		switch {
		case dangerousHookPattern.MatchString(cmd):
			sev = analyzer.SevCritical
			detail = "Install hook fetches or evaluates code at install time (pipe-to-shell / inline interpreter / base64 staging). This is the exact detonation pattern of the 2025–2026 npm worm campaigns."
		case benignHookPattern.MatchString(strings.TrimSpace(cmd)):
			sev = analyzer.SevLow
			detail = "Common tooling hook (native build / git hooks / funding notice). Low risk, but still executes at install time — kept visible by design."
		case strings.Contains(cmd, "node ") || strings.HasSuffix(cmd, ".js"):
			sev = analyzer.SevHigh
			detail = "Install hook executes a bundled script at install time. Inspect the referenced file — recent campaigns hide obfuscated payloads there."
		}
		out = append(out, analyzer.Finding{
			RuleID:   "install-scripts",
			Severity: sev,
			Title:    "npm lifecycle hook: " + hook,
			Detail:   detail,
			Evidence: truncate(cmd, 160),
		})
	}
	return out
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
