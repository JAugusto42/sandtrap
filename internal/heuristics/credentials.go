package heuristics

import (
	"regexp"

	"github.com/JAugusto42/sandtrap/internal/analyzer"
	"github.com/JAugusto42/sandtrap/internal/registry"
)

// CredentialAccess flags reads of developer/CI secret stores. The Shai-Hulud
// worm propagates precisely by stealing maintainer npm/GitHub tokens and
// republishing trojanized versions — so touching these paths from library
// code is a red flag of the highest order.
type CredentialAccess struct{}

func (CredentialAccess) ID() string { return "credential-access" }

var (
	// High-signal: no library has business reading another tool's tokens or
	// browser credential stores.
	reSecretPath = regexp.MustCompile(
		`(?i)(\.npmrc|\.pypirc|\.git-credentials|` +
			`\.ssh/id_[a-z0-9]+|` +
			`Login Data|Cookies\.sqlite|\.mozilla/firefox|keychain-db)`)
	// Context-dependent: legitimate for libraries in that domain (an HTTP
	// client reading .netrc, the AWS SDK reading .aws/credentials) but a
	// strong signal anywhere else. Reported at MEDIUM so humans triage.
	reSecretPathCtx = regexp.MustCompile(
		`(?i)(\.netrc|\.aws/credentials|\.config/gcloud|\.azure/|` +
			`\.kube/config|\.docker/config\.json|\.ssh/(known_hosts|config))`)
	reTokenEnv = regexp.MustCompile(
		`(?i)\b(NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|` +
			`AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GOOGLE_APPLICATION_CREDENTIALS|` +
			`AZURE_CLIENT_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY|VAULT_TOKEN|` +
			`CI_JOB_TOKEN|ACTIONS_RUNTIME_TOKEN)\b`)
	reCloudMeta = regexp.MustCompile(
		`169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data/`)
	reGitConfigScan = regexp.MustCompile(
		`(?i)git\s+config\s+.*credential|credential\.helper`)
)

func (CredentialAccess) Check(a *registry.Artifact) []analyzer.Finding {
	var out []analyzer.Finding
	for _, f := range a.Files {
		if !isCodeFile(f.Path) {
			continue
		}
		c := string(f.Content)

		if m := reSecretPath.FindString(c); m != "" {
			out = append(out, analyzer.Finding{
				RuleID: "credential-access", Severity: adjustForTestPath(analyzer.SevHigh, f.Path),
				Title:  "reads developer secret store",
				Detail: "References registry tokens, SSH private keys or browser credential stores. No library has a legitimate reason to touch these; this is how the Shai-Hulud lineage steals maintainer tokens to self-propagate.",
				File:   f.Path, Evidence: truncate(m, 80),
			})
		} else if m := reSecretPathCtx.FindString(c); m != "" {
			out = append(out, analyzer.Finding{
				RuleID: "credential-access", Severity: adjustForTestPath(analyzer.SevMedium, f.Path),
				Title:  "reads credential file (context-dependent)",
				Detail: "References a credential path that is legitimate for libraries in that domain (HTTP clients read .netrc, cloud SDKs read their own config) but suspicious anywhere else. Verify the package's purpose matches.",
				File:   f.Path, Evidence: truncate(m, 80),
			})
		}
		if m := reCloudMeta.FindString(c); m != "" {
			out = append(out, analyzer.Finding{
				RuleID: "credential-access", Severity: adjustForTestPath(analyzer.SevHigh, f.Path),
				Title:  "cloud metadata endpoint access",
				Detail: "Queries the cloud instance metadata service, which mints live IAM credentials inside CI runners and production hosts.",
				File:   f.Path, Evidence: truncate(m, 80),
			})
		}
		if hits := reTokenEnv.FindAllString(c, -1); len(hits) >= 3 {
			out = append(out, analyzer.Finding{
				RuleID: "credential-access", Severity: adjustForTestPath(analyzer.SevMedium, f.Path),
				Title:  "enumerates multiple secret env vars",
				Detail: "References several unrelated credential environment variables — libraries legitimately read their own, stealers read everyone's.",
				File:   f.Path, Evidence: truncate(joinStrings(hits, ", ", 5), 120),
			})
		}
		if reGitConfigScan.MatchString(c) {
			out = append(out, analyzer.Finding{
				RuleID: "credential-access", Severity: adjustForTestPath(analyzer.SevMedium, f.Path),
				Title:  "probes git credential helpers",
				Detail: "Interacts with git credential storage from library code.",
				File:   f.Path,
			})
		}
	}
	return out
}

func joinStrings(ss []string, sep string, max int) string {
	if len(ss) > max {
		ss = ss[:max]
	}
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}
