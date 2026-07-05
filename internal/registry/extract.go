package registry

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"path"
	"strings"
	"time"
)

var errArchiveTooLarge = errors.New("archive exceeds extraction limits")

// shouldInspect filters extracted entries down to files worth scanning.
// Binary blobs are kept (small ones) because attackers hide payloads in
// unexpected extensions, but huge media/binary files are skipped.
func shouldInspect(name string, size int64) bool {
	if size <= 0 {
		return false
	}
	base := strings.ToLower(path.Base(name))
	switch path.Ext(base) {
	case ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
		".ttf", ".eot", ".mp3", ".mp4", ".pdf", ".wasm":
		return false
	}
	return true
}

// cleanPath strips the archive's top-level directory ("package/" for npm,
// "<name>-<version>/" for sdists) and rejects path traversal.
func cleanPath(p string) (string, bool) {
	p = path.Clean(strings.ReplaceAll(p, "\\", "/"))
	if p == "." || strings.HasPrefix(p, "..") || path.IsAbs(p) {
		return "", false
	}
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	if p == "" {
		return "", false
	}
	return p, true
}

// extractTarGz decompresses an npm tarball / PyPI sdist fully in memory,
// enforcing the package-level limits.
func extractTarGz(raw []byte) ([]File, error) {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	var (
		files []File
		total int64
	)
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return files, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name, ok := cleanPath(hdr.Name)
		if !ok || !shouldInspect(name, hdr.Size) {
			continue
		}
		if len(files) >= MaxFilesPerPkg || total >= MaxTotalUnpacked {
			return files, errArchiveTooLarge
		}
		limit := int64(MaxFileBytes)
		truncated := hdr.Size > limit
		buf, err := io.ReadAll(io.LimitReader(tr, limit))
		if err != nil {
			return files, err
		}
		total += int64(len(buf))
		files = append(files, File{Path: name, Content: buf, Truncated: truncated})
	}
	return files, nil
}

// extractZip handles PyPI wheels (which are zip archives).
func extractZip(raw []byte) ([]File, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, err
	}
	var (
		files []File
		total int64
	)
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name, ok := cleanPath(f.Name)
		if !ok {
			// wheels have no single top-level dir; retry without stripping
			name = path.Clean(f.Name)
			if name == "." || strings.HasPrefix(name, "..") || path.IsAbs(name) {
				continue
			}
		}
		if !shouldInspect(name, int64(f.UncompressedSize64)) {
			continue
		}
		if len(files) >= MaxFilesPerPkg || total >= MaxTotalUnpacked {
			return files, errArchiveTooLarge
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		truncated := int64(f.UncompressedSize64) > MaxFileBytes
		buf, err := io.ReadAll(io.LimitReader(rc, MaxFileBytes))
		rc.Close()
		if err != nil {
			return files, err
		}
		total += int64(len(buf))
		files = append(files, File{Path: name, Content: buf, Truncated: truncated})
	}
	return files, nil
}

// download fetches a URL enforcing MaxArchiveBytes, retrying once on
// transient network failures (HTTP/2 stream resets, timeouts, 5xx).
func download(url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		buf, retryable, err := downloadOnce(url)
		if err == nil {
			return buf, nil
		}
		lastErr = err
		if !retryable {
			break
		}
	}
	return nil, lastErr
}

func downloadOnce(url string) (buf []byte, retryable bool, err error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, true, err // network-level failure: worth one retry
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode >= 500, errors.New("download failed: " + resp.Status)
	}
	buf, err = io.ReadAll(io.LimitReader(resp.Body, MaxArchiveBytes+1))
	if err != nil {
		return nil, true, err // mid-stream reset: worth one retry
	}
	if len(buf) > MaxArchiveBytes {
		return nil, false, errArchiveTooLarge
	}
	return buf, false, nil
}
