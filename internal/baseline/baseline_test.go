package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JAugusto42/sandtrap/internal/analyzer"
)

func TestLoadMatchAndWildcard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFile)
	os.WriteFile(path, []byte(`{
	  "version": 1,
	  "accept": [
	    "npm:esbuild@*/install-scripts",
	    "npm:vue-demi@0.14.10/install-scripts",
	    "npm:@scope/pkg@1.0.0/*"
	  ]
	}`), 0o644)

	b, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	f := analyzer.Finding{RuleID: "install-scripts"}

	if !b.Suppress(analyzer.Package{Ecosystem: analyzer.NPM, Name: "esbuild", Version: "0.99.0"}, f) {
		t.Fatal("wildcard version must match any esbuild version")
	}
	if b.Suppress(analyzer.Package{Ecosystem: analyzer.NPM, Name: "vue-demi", Version: "0.15.0"}, f) {
		t.Fatal("pinned version must NOT match a different version — that is the hijack signal")
	}
	if !b.Suppress(analyzer.Package{Ecosystem: analyzer.NPM, Name: "@scope/pkg", Version: "1.0.0"},
		analyzer.Finding{RuleID: "obfuscation"}) {
		t.Fatal("wildcard rule must match any rule for that exact version")
	}
	if b.Suppress(analyzer.Package{Ecosystem: analyzer.PyPI, Name: "esbuild", Version: "0.99.0"}, f) {
		t.Fatal("ecosystem must be respected")
	}
}

func TestWriteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFile)
	results := []analyzer.Result{{
		Package:  analyzer.Package{Ecosystem: analyzer.NPM, Name: "esbuild", Version: "0.27.4"},
		Findings: []analyzer.Finding{{RuleID: "install-scripts"}, {RuleID: "install-scripts"}},
	}}
	if err := Write(path, results); err != nil {
		t.Fatal(err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Suppress(results[0].Package, results[0].Findings[0]) {
		t.Fatal("written baseline must suppress the findings it was built from")
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{"esbuild/rule", "npm:esbuild/rule", "npm:esbuild@1.0.0"} {
		if _, err := parseEntry(bad); err == nil {
			t.Fatalf("expected parse error for %q", bad)
		}
	}
}
