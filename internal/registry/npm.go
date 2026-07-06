package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"
)

// NPMClient talks to the public npm registry (or a compatible mirror).
type NPMClient struct {
	BaseURL string // default https://registry.npmjs.org
}

func NewNPM() *NPMClient { return &NPMClient{BaseURL: "https://registry.npmjs.org"} }

type npmPackument struct {
	Time     map[string]string `json:"time"` // version -> RFC3339, plus "created"
	Versions map[string]struct {
		// Old packages sometimes publish malformed manifests (scripts as a
		// string, arrays, etc.) — decode leniently instead of failing the
		// whole packument.
		Scripts     json.RawMessage `json:"scripts"`
		Maintainers []struct {
			Name string `json:"name"`
		} `json:"maintainers"`
		Dist struct {
			Tarball string `json:"tarball"`
		} `json:"dist"`
	} `json:"versions"`
	DistTags map[string]string `json:"dist-tags"`
}

// decodeScripts tolerates the malformed shapes found in old packuments.
func decodeScripts(raw json.RawMessage) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil // string/array/other garbage: no scripts we can reason about
	}
	return m
}

// Fetch implements Client for the npm ecosystem.
func (c *NPMClient) Fetch(ctx context.Context, name, version string) (*Artifact, error) {
	u := c.BaseURL + "/" + url.PathEscape(name)
	resp, err := getWithRetry(ctx, u, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("npm package %q not found", name)
	}
	if resp.StatusCode != 200 {
		return nil, errors.New("npm registry error: " + resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	var pk npmPackument
	if err := json.Unmarshal(body, &pk); err != nil {
		return nil, fmt.Errorf("npm packument parse: %w", err)
	}

	if version == "" || version == "latest" {
		version = pk.DistTags["latest"]
	}
	v, ok := pk.Versions[version]
	if !ok {
		return nil, fmt.Errorf("npm %s@%s: version not found", name, version)
	}

	meta := Metadata{
		Name:           name,
		Version:        version,
		InstallScripts: lifecycleScripts(decodeScripts(v.Scripts)),
		TarballURL:     v.Dist.Tarball,
	}
	for _, m := range v.Maintainers {
		meta.Maintainers = append(meta.Maintainers, m.Name)
	}
	if t, err := time.Parse(time.RFC3339, pk.Time[version]); err == nil {
		meta.PublishedAt = t
	}
	if t, err := time.Parse(time.RFC3339, pk.Time["created"]); err == nil {
		meta.FirstPublishedAt = t
	}

	raw, err := download(ctx, v.Dist.Tarball)
	if err != nil {
		return nil, fmt.Errorf("npm tarball: %w", err)
	}
	files, err := extractTarGz(raw)
	if err != nil && len(files) == 0 {
		return nil, fmt.Errorf("npm extract: %w", err)
	}
	return &Artifact{Meta: meta, Files: files}, nil
}

// lifecycleScripts keeps only the hooks that execute automatically during
// `npm install` — the exact mechanism Shai-Hulud and Mini Shai-Hulud used.
func lifecycleScripts(scripts map[string]string) map[string]string {
	hooks := map[string]string{}
	for _, h := range []string{"preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare"} {
		if s, ok := scripts[h]; ok && s != "" {
			hooks[h] = s
		}
	}
	if len(hooks) == 0 {
		return nil
	}
	return hooks
}
