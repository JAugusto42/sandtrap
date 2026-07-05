// Package registry fetches package metadata and archives from npm and PyPI.
package registry

import (
	"context"
	"net/http"
	"time"
)

// Limits applied while downloading and extracting archives. They keep memory
// bounded and defend against decompression bombs shipped by hostile packages.
const (
	MaxArchiveBytes  = 80 << 20 // 80 MiB compressed download cap
	MaxFileBytes     = 2 << 20  // 2 MiB per extracted file (enough for source)
	MaxFilesPerPkg   = 4000     // hard cap of files inspected per package
	MaxTotalUnpacked = 256 << 20
)

// File is one extracted file from a package archive, truncated to MaxFileBytes.
type File struct {
	Path      string
	Content   []byte
	Truncated bool
}

// Metadata is registry-level information about a specific package version.
type Metadata struct {
	Name             string
	Version          string
	PublishedAt      time.Time // when this exact version was published
	FirstPublishedAt time.Time // when the package first appeared
	Maintainers      []string
	// InstallScripts are lifecycle hooks declared in the manifest
	// (npm: preinstall/install/postinstall — the Shai-Hulud entry point).
	InstallScripts map[string]string
	TarballURL     string
}

// Artifact bundles everything the analyzer needs about one package version.
type Artifact struct {
	Meta  Metadata
	Files []File
}

// Client resolves a package version into an analyzable Artifact.
type Client interface {
	Fetch(ctx context.Context, name, version string) (*Artifact, error)
}

// httpClient is shared by all registry clients: sane timeouts, no surprises.
var httpClient = &http.Client{
	Timeout: 60 * time.Second,
	Transport: &http.Transport{
		MaxIdleConnsPerHost:   8,
		ResponseHeaderTimeout: 30 * time.Second,
	},
}
