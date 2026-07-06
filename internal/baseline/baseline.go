// Package baseline implements accepted-findings files (.sandtrap.json).
//
// A baseline records the behavioral findings a team has reviewed and accepted
// (esbuild's postinstall, vue-demi's version switcher…). Scans then fail only
// on findings NOT in the baseline — which is precisely the signature of a
// hijacked release: a trusted package suddenly doing something new.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/JAugusto42/sandtrap/internal/analyzer"
)

// DefaultFile is auto-loaded from the scan directory when present.
const DefaultFile = ".sandtrap.json"

// File is the on-disk format.
type File struct {
	Version int      `json:"version"`
	Accept  []string `json:"accept"`
}

// entry is a parsed accept rule: "eco:name@version/rule",
// where version and rule may be "*".
type entry struct {
	eco, name, version, rule string
}

// Baseline is a loaded, parsed accept list.
type Baseline struct {
	entries []entry
	Path    string
}

// Load reads and parses a baseline file.
func Load(path string) (*Baseline, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	b := &Baseline{Path: path}
	for _, s := range f.Accept {
		e, err := parseEntry(s)
		if err != nil {
			return nil, fmt.Errorf("baseline %s: %w", path, err)
		}
		b.entries = append(b.entries, e)
	}
	return b, nil
}

func parseEntry(s string) (entry, error) {
	slash := strings.LastIndexByte(s, '/')
	if slash <= 0 || slash == len(s)-1 {
		return entry{}, fmt.Errorf("invalid accept entry %q (want eco:name@version/rule)", s)
	}
	rule := s[slash+1:]
	pkg := s[:slash]
	at := strings.LastIndexByte(pkg, '@')
	if at <= 0 { // no version or leading @scope
		return entry{}, fmt.Errorf("invalid accept entry %q: missing @version (use @* to match all)", s)
	}
	version := pkg[at+1:]
	rest := pkg[:at]
	colon := strings.IndexByte(rest, ':')
	if colon <= 0 {
		return entry{}, fmt.Errorf("invalid accept entry %q: missing ecosystem prefix (npm:|pypi:)", s)
	}
	return entry{eco: rest[:colon], name: rest[colon+1:], version: version, rule: rule}, nil
}

// Suppress reports whether a finding is covered by the baseline.
func (b *Baseline) Suppress(p analyzer.Package, f analyzer.Finding) bool {
	if b == nil {
		return false
	}
	for _, e := range b.entries {
		if e.eco == string(p.Ecosystem) && e.name == p.Name &&
			(e.version == "*" || e.version == p.Version) &&
			(e.rule == "*" || e.rule == f.RuleID) {
			return true
		}
	}
	return false
}

// Write produces a baseline accepting every finding in the given results.
// Versions are pinned exactly: when the package version changes the finding
// resurfaces, forcing a fresh review — that is the point.
func Write(path string, results []analyzer.Result) error {
	seen := map[string]bool{}
	var accept []string
	for _, r := range results {
		for _, f := range r.Findings {
			key := fmt.Sprintf("%s:%s@%s/%s", r.Package.Ecosystem, r.Package.Name, r.Package.Version, f.RuleID)
			if !seen[key] {
				seen[key] = true
				accept = append(accept, key)
			}
		}
	}
	sort.Strings(accept)
	raw, err := json.MarshalIndent(File{Version: 1, Accept: accept}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
