// SPDX-License-Identifier: MIT

package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// Build metadata — set by GoReleaser via ldflags for tagged releases.
// For plain `go build` (developer iteration) the ldflags are missing,
// so init() backfills commit + date from debug.BuildInfo's vcs.* keys.
// -buildvcs=true is in the project's default GOFLAGS, so the VCS stamp
// is always present in dev builds; we read it only when the ldflags
// slot is still at its compile-time default to keep release builds
// authoritative.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func init() {
	if commit != "none" && date != "unknown" {
		return // release build — ldflags already populated
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if commit == "none" && s.Value != "" {
				// Keep the short form so it matches Makefile's
				// `git rev-parse --short HEAD` output.
				if len(s.Value) > 7 {
					commit = s.Value[:7]
				} else {
					commit = s.Value
				}
			}
		case "vcs.time":
			if date == "unknown" && s.Value != "" {
				date = s.Value
			}
		case "vcs.modified":
			if s.Value == "true" && commit != "none" && !strings.HasSuffix(commit, "-dirty") {
				commit += "-dirty"
			}
		}
	}
}

const githubRepo = "sungurerdim/dizgin"

// maxChecksumBytes caps the download size of the release checksums.txt
// to prevent unexpectedly large responses from exhausting memory.
const maxChecksumBytes = 1 * 1024 * 1024 // 1 MB

// validAssetURLPrefixes lists the URL prefixes that GitHub uses for
// release asset downloads. Only URLs with these prefixes are accepted
// before fetching, preventing open redirects or supply-chain confusion.
var validAssetURLPrefixes = []string{
	"https://github.com/",
	"https://objects.githubusercontent.com/",
}

var updateCmd = &cobra.Command{
	Use:          "update",
	Short:        "Update dizgin to the latest version",
	SilenceUsage: true,
	RunE:         runUpdate,
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

func runUpdate(_ *cobra.Command, _ []string) error {
	current := strings.TrimPrefix(version, "v")
	if current == "" {
		current = "dev"
	}
	fmt.Fprintf(os.Stderr, brand.Name+": current version: %s\n", current)
	fmt.Fprintf(os.Stderr, brand.Name+": checking for updates...\n")

	rel, err := fetchLatestRelease()
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	latest := strings.TrimPrefix(rel.TagName, "v")

	if current != "dev" && current == latest {
		fmt.Fprintf(os.Stderr, brand.Name+": already up to date (%s)\n", current)
		return nil
	}
	fmt.Fprintf(os.Stderr, brand.Name+": updating %s → %s\n", current, rel.TagName)

	assetName := platformAssetName(latest)
	var assetURL, checksumURL string
	for _, a := range rel.Assets {
		switch a.Name {
		case assetName:
			assetURL = a.BrowserDownloadURL
		case "checksums.txt":
			checksumURL = a.BrowserDownloadURL
		}
	}
	if assetURL == "" {
		return fmt.Errorf("update: no release asset for %s/%s (wanted %s)", runtime.GOOS, runtime.GOARCH, assetName)
	}
	if !isValidAssetURL(assetURL) {
		return fmt.Errorf("update: asset URL has unexpected prefix (got %q) — refusing to download", assetURL)
	}
	if checksumURL != "" && !isValidAssetURL(checksumURL) {
		return fmt.Errorf("update: checksum URL has unexpected prefix (got %q) — refusing to download", checksumURL)
	}

	fmt.Fprintf(os.Stderr, brand.Name+": downloading %s...\n", assetName)
	client := &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &http.Transport{
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
	assetData, err := httpFetch(client, assetURL)
	if err != nil {
		return fmt.Errorf("update: download: %w", err)
	}

	if checksumURL == "" {
		return fmt.Errorf("update: no checksums.txt in release — refusing to install unverified binary")
	}
	fmt.Fprintf(os.Stderr, brand.Name+": verifying checksum...\n")
	checksumData, cErr := httpFetchLimit(client, checksumURL, maxChecksumBytes)
	if cErr != nil {
		return fmt.Errorf("update: fetch checksums: %w", cErr)
	}
	if vErr := verifyChecksum(assetData, assetName, checksumData); vErr != nil {
		return fmt.Errorf("update: %w", vErr)
	}

	newBinary, err := extractBinary(assetData, assetName)
	if err != nil {
		return fmt.Errorf("update: extract: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("update: executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("update: symlinks: %w", err)
	}
	fi, err := os.Lstat(exe)
	if err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("update: %q is not a regular file", exe)
	}

	if err := replaceBinary(exe, newBinary); err != nil {
		return fmt.Errorf("update: replace: %w", err)
	}

	fmt.Printf(brand.Name+": updated to %s\n", rel.TagName)
	return nil
}

// ── GitHub API ────────────────────────────────────────────────────────────────

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// isValidAssetURL returns true when url starts with one of the known-good
// GitHub asset prefixes. This prevents an attacker-controlled JSON body
// from redirecting the download to an arbitrary host.
func isValidAssetURL(url string) bool {
	for _, pfx := range validAssetURLPrefixes {
		if strings.HasPrefix(url, pfx) {
			return true
		}
	}
	return false
}

func fetchLatestRelease() (*githubRelease, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	data, err := httpFetch(client, "https://api.github.com/repos/"+githubRepo+"/releases/latest")
	if err != nil {
		return nil, err
	}
	var rel githubRelease
	if err := json.Unmarshal(data, &rel); err != nil {
		return nil, fmt.Errorf("parse release: %w", err)
	}
	return &rel, nil
}

func httpFetch(client *http.Client, url string) ([]byte, error) {
	return httpFetchLimit(client, url, 512*1024*1024) // 512 MB
}

func httpFetchLimit(client *http.Client, url string, maxSize int64) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxSize))
}

// ── platform ──────────────────────────────────────────────────────────────────

func platformAssetName(ver string) string {
	// Must match .goreleaser.yml's archive name_template:
	// "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}".
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("%s_%s_%s_%s.zip", brand.Name, ver, runtime.GOOS, runtime.GOARCH)
	}
	return fmt.Sprintf("%s_%s_%s_%s.tar.gz", brand.Name, ver, runtime.GOOS, runtime.GOARCH)
}

// ── checksum ──────────────────────────────────────────────────────────────────

func verifyChecksum(data []byte, filename string, checksums []byte) error {
	sum := sha256.Sum256(data)
	got := fmt.Sprintf("%x", sum)
	for _, line := range strings.Split(string(checksums), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[1] == filename {
			if parts[0] == got {
				return nil
			}
			return fmt.Errorf("checksum mismatch for %s:\n  got  %s\n  want %s", filename, got, parts[0])
		}
	}
	return fmt.Errorf("checksum not found for %s", filename)
}

// ── extract ───────────────────────────────────────────────────────────────────

func extractBinary(data []byte, _ string) ([]byte, error) {
	binName := brand.Name
	if runtime.GOOS == "windows" {
		binName = brand.Name + ".exe"
		return extractFromZip(data, binName)
	}
	return extractFromTarGz(data, binName)
}

// maxExtractedSize is the maximum allowed size for a decompressed binary.
// Prevents zip bombs from exhausting memory during self-update.
const maxExtractedSize = 256 * 1024 * 1024 // 256 MB

func extractFromZip(data []byte, name string) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, f := range r.File {
		if filepath.Base(f.Name) == name {
			if f.UncompressedSize64 > maxExtractedSize {
				return nil, fmt.Errorf("extracted file too large: %d bytes (max %d)", f.UncompressedSize64, maxExtractedSize)
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer func() { _ = rc.Close() }()
			return io.ReadAll(io.LimitReader(rc, maxExtractedSize+1))
		}
	}
	return nil, fmt.Errorf("%q not found in archive", name)
}

func extractFromTarGz(data []byte, name string) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = gr.Close() }()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if filepath.Base(hdr.Name) == name {
			if hdr.Size > maxExtractedSize {
				return nil, fmt.Errorf("extracted file too large: %d bytes (max %d)", hdr.Size, maxExtractedSize)
			}
			return io.ReadAll(io.LimitReader(tr, maxExtractedSize+1))
		}
	}
	return nil, fmt.Errorf("%q not found in archive", name)
}

// ── replace ───────────────────────────────────────────────────────────────────

func replaceBinary(exe string, newData []byte) error {
	// Create a temp file in the same directory as exe so the eventual
	// os.Rename is guaranteed to stay on the same filesystem (atomic on
	// Unix; works on Windows too because same-volume renames are allowed
	// while the current binary is running).
	tmp, err := os.CreateTemp(filepath.Dir(exe), ".dizgin-update-*")
	if err != nil {
		return fmt.Errorf("create temp binary: %w", err)
	}
	tmpPath := tmp.Name()
	// Ensure temp file is cleaned up on any failure path.
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(newData); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write new binary: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod new binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close new binary: %w", err)
	}

	if runtime.GOOS == "windows" {
		// Windows: cannot delete a running exe, but can rename it.
		// Rename current → .old (allowed while running), then tmp → current.
		oldFile := exe + ".old"
		_ = os.Remove(oldFile) // clean up any leftover from a previous update

		if err := os.Rename(exe, oldFile); err != nil {
			return fmt.Errorf("rename current binary: %w", err)
		}
		if err := os.Rename(tmpPath, exe); err != nil {
			_ = os.Rename(oldFile, exe) // best-effort restore
			return fmt.Errorf("rename new binary: %w", err)
		}
		tmpPath = "" // rename succeeded — defer must not remove it
		// .old stays locked until process exits; cleaned on next update call.
		return nil
	}

	// Unix: atomic replace (same filesystem → os.Rename is atomic).
	if err := os.Rename(tmpPath, exe); err != nil {
		return fmt.Errorf("rename new binary: %w", err)
	}
	tmpPath = "" // rename succeeded — defer must not remove it
	return nil
}
