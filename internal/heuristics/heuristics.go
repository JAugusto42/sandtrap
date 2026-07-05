// Package heuristics contains the detection rules Sandtrap runs against a
// package artifact. Each rule is independent, stateless and safe to run
// concurrently. Rules are tuned against the tradecraft observed in the
// 2025–2026 supply chain campaigns (Shai-Hulud lineage, axios/UNC1069,
// TeamPCP CI/CD compromises).
package heuristics

import (
	"github.com/sandtrap-sh/sandtrap/internal/analyzer"
	"github.com/sandtrap-sh/sandtrap/internal/registry"
)

// Rule inspects an artifact and emits zero or more findings.
type Rule interface {
	ID() string
	Check(a *registry.Artifact) []analyzer.Finding
}

// All returns the default rule set, in execution order.
func All() []Rule {
	return []Rule{
		InstallScripts{},
		Obfuscation{},
		Exfiltration{},
		CredentialAccess{},
		FreshPublish{},
	}
}

// adjustForTestPath lowers a finding's severity by one tier when it comes
// from a test/example/docs tree. That code does not execute at install or
// import time, so a matching pattern there is far more likely a fixture —
// but it stays visible because "hide it in tests/" is a known evasion.
func adjustForTestPath(sev analyzer.Severity, path string) analyzer.Severity {
	if !isTestPath(path) {
		return sev
	}
	if sev > analyzer.SevLow {
		return sev - 1
	}
	return sev
}

func isTestPath(p string) bool {
	for _, seg := range []string{"test/", "tests/", "__tests__/", "spec/", "examples/", "example/", "docs/", "fixtures/"} {
		if len(p) >= len(seg) && (p[:len(seg)] == seg || containsSeg(p, "/"+seg)) {
			return true
		}
	}
	return false
}

func containsSeg(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
