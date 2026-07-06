package heuristics

// RuleMeta documents a detection rule for report consumers: what the rule
// looks for, what a human should do about a finding, and where to read more.
// This feeds the JSON report's "rules" section and SARIF's tool.driver.rules.
type RuleMeta struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
}

// Catalog returns metadata for every rule in the default set, keyed by rule ID.
func Catalog() map[string]RuleMeta {
	return map[string]RuleMeta{
		"install-scripts": {
			ID:   "install-scripts",
			Name: "Install-time code execution",
			Description: "Detects npm lifecycle hooks (preinstall/install/postinstall) and Python sdist build scripts " +
				"that execute code automatically during dependency installation. This is the primary initial-execution " +
				"vector of modern supply chain worms: the Shai-Hulud lineage detonates via install hooks that fetch or " +
				"evaluate a payload before the developer has run a single line of their own code.",
			Remediation: "Verify the hook command against the package's repository. Prefer installing with scripts " +
				"disabled (npm: `npm ci --ignore-scripts`; pip: prefer wheels over sdists). If the behavior is expected " +
				"(native builds, platform binary downloads), accept it into the baseline with " +
				"`sandtrap scan --write-baseline` so only NEW hook behavior fails future scans.",
			References: []string{
				"https://docs.npmjs.com/cli/v10/using-npm/scripts#life-cycle-scripts",
				"https://github.com/JAugusto42/sandtrap#what-it-detects",
			},
		},
		"obfuscation": {
			ID:   "obfuscation",
			Name: "Obfuscated executable payload",
			Description: "Detects stacked obfuscation techniques characteristic of real campaign payloads: dynamic " +
				"code execution (eval / new Function / exec) combined with decoders feeding it (atob / base64), " +
				"embedded encoded payload material, obfuscator-mangled identifiers (_0x…) and hex-escape floods. " +
				"Single techniques alone do not fire: legitimate code uses each of them; malware stacks them.",
			Remediation: "Open the flagged file at the exact path reported and locate the evidence excerpt. Compare the " +
				"published tarball against the package's source repository (the code in the registry is what runs — " +
				"repos can differ). If the file is legitimate compiled output, accept it into the baseline; if the code " +
				"decodes-and-executes content you cannot account for, remove the package and rotate credentials that " +
				"were available to any machine that installed it.",
			References: []string{
				"https://github.com/JAugusto42/sandtrap#what-it-detects",
			},
		},
		"exfiltration": {
			ID:   "exfiltration",
			Name: "Data exfiltration primitives",
			Description: "Detects network primitives used to ship stolen data out: hardcoded disposable-webhook and " +
				"tunnel endpoints (webhook.site, Discord webhooks, ngrok…), raw-IP HTTP endpoints that bypass DNS " +
				"monitoring, fetch-and-execute one-liners, and bulk environment-variable serialization — the first " +
				"line of every credential stealer, since CI systems inject cloud keys and registry tokens via env.",
			Remediation: "Treat a confirmed exfiltration endpoint as an active incident: remove the package, then " +
				"rotate every secret that was present in the environment of any machine that installed it (npm/PyPI " +
				"tokens, GitHub PATs, cloud keys, CI secrets). Search CI logs for outbound calls to the reported " +
				"endpoint to scope the exposure window.",
			References: []string{
				"https://github.com/JAugusto42/sandtrap#what-it-detects",
			},
		},
		"credential-access": {
			ID:   "credential-access",
			Name: "Credential store access",
			Description: "Detects reads of developer and CI secret stores: registry token files (.npmrc/.pypirc), " +
				"SSH private keys, git credentials, browser credential databases, cloud credential files and the " +
				"cloud instance metadata endpoint. Maintainer-token theft from these stores is how the Shai-Hulud " +
				"worm self-propagates: steal the token, republish trojanized versions, repeat.",
			Remediation: "Confirm whether the package's stated purpose justifies the access (an HTTP client reading " +
				".netrc is normal; a color library reading .npmrc is an incident). For unjustified access: remove the " +
				"package and rotate the specific credentials referenced in the finding. Scope tokens minimally " +
				"(granular npm tokens, fine-grained PATs) so a single theft cannot cascade.",
			References: []string{
				"https://github.com/JAugusto42/sandtrap#what-it-detects",
			},
		},
		"fresh-publish": {
			ID:   "fresh-publish",
			Name: "Fresh publish window",
			Description: "Informational signal: the exact version was published very recently, or the package itself " +
				"is very young. Hijacked releases are typically detected and yanked within hours-to-days (the axios " +
				"compromise window was ~3 hours), so freshly published versions carry elevated compromise-window " +
				"risk; brand-new packages are the primary vehicle for typosquatting and dependency confusion.",
			Remediation: "Not malicious on its own — use it to amplify other findings during triage. Reduce exposure " +
				"structurally: pin exact versions in lockfiles and adopt a cooldown policy (only upgrade to versions " +
				"that have survived a few days).",
			References: []string{
				"https://github.com/JAugusto42/sandtrap#what-it-detects",
			},
		},
	}
}
