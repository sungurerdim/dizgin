// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
)

const versionCheckTTL = 24 * time.Hour

type versionCheckCache struct {
	CheckedAt time.Time `json:"checked_at"`
	Latest    string    `json:"latest"`
}

// versionCheckTimeout caps the total wall time the background version-check
// goroutine may spend, including DNS resolution and the HTTP round trip.
// This prevents a network stall from keeping the goroutine alive after dizgin
// itself has finished.
const versionCheckTimeout = 5 * time.Second

// startVersionCheck asynchronously checks for a newer release and prints a
// single-line notice to stderr if one is available.  Uses a 24-hour cache so
// the GitHub API is hit at most once per day.  No-ops in dev builds (version="").
func startVersionCheck() {
	if version == "" {
		return // dev build — skip
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), versionCheckTimeout)
		defer cancel()
		latest, err := latestVersionCached(ctx)
		if err != nil || latest == "" {
			return
		}
		current := strings.TrimPrefix(version, "v")
		newest := strings.TrimPrefix(latest, "v")
		if newest != current {
			fmt.Fprintf(os.Stderr, brand.Name+": update available: v%s → run 'dizgin update'\n", newest)
		}
	}()
}

func latestVersionCached(ctx context.Context) (string, error) {
	if c, err := readVersionCache(); err == nil && time.Since(c.CheckedAt) < versionCheckTTL {
		return c.Latest, nil
	}
	rel, err := fetchLatestReleaseCtx(ctx)
	if err != nil {
		return "", err
	}
	writeVersionCache(versionCheckCache{Latest: rel.TagName, CheckedAt: time.Now()})
	return rel.TagName, nil
}

// fetchLatestReleaseCtx is a context-aware variant of fetchLatestRelease
// used by the background version check goroutine.
func fetchLatestReleaseCtx(ctx context.Context) (*githubRelease, error) {
	client := &http.Client{Timeout: versionCheckTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/"+githubRepo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from GitHub releases API", resp.StatusCode)
	}
	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("parse release: %w", err)
	}
	return &rel, nil
}

func versionCachePath() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, brand.Name)
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, "version-check.json")
}

func readVersionCache() (versionCheckCache, error) {
	data, err := os.ReadFile(versionCachePath())
	if err != nil {
		return versionCheckCache{}, err
	}
	var c versionCheckCache
	return c, json.Unmarshal(data, &c)
}

func writeVersionCache(c versionCheckCache) {
	data, err := json.Marshal(c)
	if err != nil {
		return
	}
	os.WriteFile(versionCachePath(), data, 0o600) //nolint:errcheck
}
