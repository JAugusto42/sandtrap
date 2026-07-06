package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// PyPIClient talks to the public PyPI JSON API.
type PyPIClient struct {
	BaseURL string // default https://pypi.org
}

func NewPyPI() *PyPIClient { return &PyPIClient{BaseURL: "https://pypi.org"} }

type pypiRelease struct {
	Info struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"info"`
	URLs []struct {
		URL         string `json:"url"`
		PackageType string `json:"packagetype"` // sdist | bdist_wheel
		UploadTime  string `json:"upload_time_iso_8601"`
		Filename    string `json:"filename"`
	} `json:"urls"`
}

// Fetch implements Client for PyPI. It prefers the sdist (closer to what
// executes at install time via setup.py) and falls back to the wheel.
func (c *PyPIClient) Fetch(ctx context.Context, name, version string) (*Artifact, error) {
	endpoint := c.BaseURL + "/pypi/" + url.PathEscape(name)
	if version != "" && version != "latest" {
		endpoint += "/" + url.PathEscape(version)
	}
	endpoint += "/json"

	resp, err := getWithRetry(ctx, endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("pypi package %q@%q not found", name, version)
	}
	if resp.StatusCode != 200 {
		return nil, errors.New("pypi error: " + resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	var rel pypiRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, fmt.Errorf("pypi parse: %w", err)
	}
	if len(rel.URLs) == 0 {
		return nil, fmt.Errorf("pypi %s@%s: no downloadable artifacts", name, version)
	}
	chosen := rel.URLs[0]
	for _, u := range rel.URLs {
		if u.PackageType == "sdist" {
			chosen = u
			break
		}
	}

	meta := Metadata{Name: rel.Info.Name, Version: rel.Info.Version, TarballURL: chosen.URL}
	if t, err := time.Parse(time.RFC3339, chosen.UploadTime); err == nil {
		meta.PublishedAt = t
	}

	raw, err := download(ctx, chosen.URL)
	if err != nil {
		return nil, fmt.Errorf("pypi download: %w", err)
	}

	var files []File
	switch {
	case strings.HasSuffix(chosen.Filename, ".whl"), strings.HasSuffix(chosen.Filename, ".zip"):
		files, err = extractZip(raw)
	default: // .tar.gz sdist
		files, err = extractTarGz(raw)
	}
	if err != nil && len(files) == 0 {
		return nil, fmt.Errorf("pypi extract: %w", err)
	}
	for _, f := range files {
		if f.Path == "setup.py" {
			if meta.InstallScripts == nil {
				meta.InstallScripts = map[string]string{}
			}
			meta.InstallScripts["setup.py"] = "(python sdist build script — executes on pip install)"
		}
	}
	return &Artifact{Meta: meta, Files: files}, nil
}
