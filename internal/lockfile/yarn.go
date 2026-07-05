package lockfile

import (
	"bufio"
	"os"
	"strings"

	"github.com/sandtrap-sh/sandtrap/internal/analyzer"
)

// parseYarnLock handles both yarn classic (v1) and yarn berry (v2+) lockfiles.
//
// Classic v1:
//
//	"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.22.0":
//	  version "7.22.13"
//
// Berry v2+ (YAML):
//
//	"@babel/code-frame@npm:^7.0.0":
//	  version: 7.22.13
//	  resolution: "@babel/code-frame@npm:7.22.13"
//
// Both share the same shape: an unindented header line listing specs ending
// with ':', followed by indented fields including the resolved version.
func parseYarnLock(path string) ([]analyzer.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var (
		pkgs        []analyzer.Package
		currentName string
		isWorkspace bool
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Header line: unindented, ends with ':'.
		if line[0] != ' ' && line[0] != '\t' && strings.HasSuffix(strings.TrimSpace(line), ":") {
			currentName, isWorkspace = "", false
			header := strings.TrimSuffix(strings.TrimSpace(line), ":")
			if header == "__metadata" { // berry preamble block
				continue
			}
			// Multiple specs may share one entry; all resolve to the same
			// package, so the first is enough.
			firstSpec := header
			if i := strings.Index(header, ","); i >= 0 {
				firstSpec = header[:i]
			}
			firstSpec = strings.Trim(strings.TrimSpace(firstSpec), `"`)
			name, rng := yarnSpecParts(firstSpec)
			// npm aliases put the REAL registry name inside the range:
			// "string-width-cjs@npm:string-width@^4.2.0". Works in both
			// classic v1 and berry lockfiles.
			if rest, ok := strings.CutPrefix(rng, "npm:"); ok {
				if i := strings.LastIndexByte(rest, '@'); i > 0 {
					name = rest[:i]
				}
			}
			currentName = name
			// Only registry-resolvable entries are scannable. Berry encodes
			// the protocol in the range ("npm:^1.0.0", "workspace:.",
			// "patch:...", "portal:..."); classic v1 git/url deps look like
			// "pkg@https://..." — anything with a non-npm protocol is local
			// or non-registry code and must be skipped.
			if i := strings.Index(rng, ":"); i >= 0 && !strings.HasPrefix(rng, "npm:") {
				isWorkspace = true
			}
			continue
		}

		if currentName == "" || isWorkspace {
			continue
		}
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "version") {
			ver := strings.TrimPrefix(trimmed, "version")
			ver = strings.TrimPrefix(strings.TrimSpace(ver), ":")
			ver = strings.Trim(strings.TrimSpace(ver), `"`)
			if ver != "" && currentName != "" && !strings.HasPrefix(ver, "0.0.0-use.local") {
				pkgs = append(pkgs, analyzer.Package{
					Ecosystem: analyzer.NPM, Name: currentName, Version: ver, Source: path,
				})
			}
			currentName = "" // one version per entry
		}
	}
	return pkgs, sc.Err()
}

// yarnSpecParts splits "name@range" respecting scoped names, e.g.
// "@scope/pkg@npm:^1.0.0" → ("@scope/pkg", "npm:^1.0.0") and
// "patched@patch:patched@npm%3A1.0.0#..." → ("patched", "patch:...").
// The first '@' after the (optional) leading scope marker delimits the range,
// which is what makes ranges containing '@' parse correctly.
func yarnSpecParts(spec string) (name, rng string) {
	start := 0
	if strings.HasPrefix(spec, "@") {
		start = 1
	}
	i := strings.Index(spec[start:], "@")
	if i < 0 {
		return spec, ""
	}
	i += start
	return spec[:i], spec[i+1:]
}
