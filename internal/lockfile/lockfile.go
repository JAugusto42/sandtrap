// Package lockfile discovers and parses dependency manifests into the flat
// package list the analyzer consumes.
package lockfile

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/JAugusto42/sandtrap/internal/analyzer"
)

// Discover walks dir (non-recursively, then one level of common subdirs is
// intentionally NOT scanned — lockfiles live at the root) and parses every
// supported lockfile it finds.
func Discover(dir string) ([]analyzer.Package, []string, error) {
	var (
		pkgs  []analyzer.Package
		found []string
	)
	candidates := []struct {
		file  string
		parse func(path string) ([]analyzer.Package, error)
	}{
		{"package-lock.json", parseNPMLock},
		{"yarn.lock", parseYarnLock},
		{"requirements.txt", parseRequirements},
		{"requirements-dev.txt", parseRequirements},
	}
	for _, c := range candidates {
		p := filepath.Join(dir, c.file)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		list, err := c.parse(p)
		if err != nil {
			return nil, found, fmt.Errorf("%s: %w", c.file, err)
		}
		pkgs = append(pkgs, list...)
		found = append(found, c.file)
	}
	return dedupe(pkgs), found, nil
}

type npmLock struct {
	LockfileVersion int `json:"lockfileVersion"`
	Packages        map[string]struct {
		// Name is set when the dependency is installed under an alias
		// ("string-width-cjs": {"name": "string-width", ...}); the registry
		// only knows the real name.
		Name    string `json:"name"`
		Version string `json:"version"`
		Link    bool   `json:"link"`
	} `json:"packages"`
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

func parseNPMLock(path string) ([]analyzer.Package, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock npmLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}
	var pkgs []analyzer.Package
	if len(lock.Packages) > 0 { // v2/v3
		for key, entry := range lock.Packages {
			if key == "" || entry.Link || entry.Version == "" {
				continue
			}
			name := npmNameFromKey(key)
			if entry.Name != "" { // npm alias: registry name differs from the install path
				name = entry.Name
			}
			if name == "" {
				continue
			}
			pkgs = append(pkgs, analyzer.Package{
				Ecosystem: analyzer.NPM, Name: name, Version: entry.Version, Source: path,
			})
		}
		return pkgs, nil
	}
	for name, entry := range lock.Dependencies { // v1
		if entry.Version == "" {
			continue
		}
		pkgs = append(pkgs, analyzer.Package{
			Ecosystem: analyzer.NPM, Name: name, Version: entry.Version, Source: path,
		})
	}
	return pkgs, nil
}

// npmNameFromKey turns "node_modules/@scope/name" / "node_modules/a/node_modules/b"
// into the innermost package name.
func npmNameFromKey(key string) string {
	const marker = "node_modules/"
	i := strings.LastIndex(key, marker)
	if i < 0 {
		return ""
	}
	return key[i+len(marker):]
}

var reReqLine = regexp.MustCompile(`^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.!+_-]+)`)

func parseRequirements(path string) ([]analyzer.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []analyzer.Package
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if m := reReqLine.FindStringSubmatch(line); m != nil {
			pkgs = append(pkgs, analyzer.Package{
				Ecosystem: analyzer.PyPI, Name: m[1], Version: m[2], Source: path,
			})
		}
	}
	return pkgs, sc.Err()
}

func dedupe(in []analyzer.Package) []analyzer.Package {
	seen := map[string]bool{}
	out := in[:0]
	for _, p := range in {
		k := p.String()
		if !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	return out
}
