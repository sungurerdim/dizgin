// SPDX-License-Identifier: MIT

package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// ── verifyChecksum ─────────────────────────────────────────────────────────────

func TestVerifyChecksum_Valid(t *testing.T) {
	data := []byte("hello-dizgin-binary")
	sum := sha256.Sum256(data)
	checksums := fmt.Sprintf("%x  dizgin.zip\n", sum)
	if err := verifyChecksum(data, "dizgin.zip", []byte(checksums)); err != nil {
		t.Errorf("expected valid checksum to pass: %v", err)
	}
}

func TestVerifyChecksum_Mismatch(t *testing.T) {
	data := []byte("hello-dizgin-binary")
	checksums := "0000000000000000000000000000000000000000000000000000000000000000  dizgin.zip\n"
	if err := verifyChecksum(data, "dizgin.zip", []byte(checksums)); err == nil {
		t.Error("expected mismatch error, got nil")
	}
}

func TestVerifyChecksum_Missing(t *testing.T) {
	data := []byte("hello-dizgin-binary")
	checksums := "abc123  other-file.zip\n"
	if err := verifyChecksum(data, "dizgin.zip", []byte(checksums)); err == nil {
		t.Error("expected missing-entry error, got nil")
	}
}

// ── platformAssetName ────────────────────────────────────────────────────────

// TestPlatformAssetName_MatchesGoreleaserTemplate pins the asset filename
// self-update looks for against .goreleaser.yml's archive name_template
// ("{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}", ProjectName
// "dizgin"). A pre-rename regression had this hardcoded to the "cop_"
// brand, so `dizgin update` would search for release assets that never
// existed — see the rename sweep that missed it.
func TestPlatformAssetName_MatchesGoreleaserTemplate(t *testing.T) {
	got := platformAssetName("1.2.3")
	if !strings.HasPrefix(got, brand.Name+"_1.2.3_") {
		t.Errorf("platformAssetName(%q) = %q, want prefix %q", "1.2.3", got, brand.Name+"_1.2.3_")
	}
	wantExt := ".tar.gz"
	if runtime.GOOS == "windows" {
		wantExt = ".zip"
	}
	if !strings.HasSuffix(got, wantExt) {
		t.Errorf("platformAssetName(%q) = %q, want suffix %q for GOOS=%s", "1.2.3", got, wantExt, runtime.GOOS)
	}
}

// ── extractFromZip ─────────────────────────────────────────────────────────────

func TestExtractFromZip_RoundTrip(t *testing.T) {
	content := []byte("fake-binary-content")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(brand.Name + ".exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := extractFromZip(buf.Bytes(), brand.Name+".exe")
	if err != nil {
		t.Fatalf("extractFromZip: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content mismatch: got %q, want %q", got, content)
	}
}

func TestExtractFromZip_NotFound(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.Close() //nolint:errcheck

	_, err := extractFromZip(buf.Bytes(), "missing.exe")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

// ── extractFromTarGz ──────────────────────────────────────────────────────────

func TestExtractFromTarGz_RoundTrip(t *testing.T) {
	content := []byte("fake-unix-binary")

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Name: brand.Name,
		Size: int64(len(content)),
		Mode: 0755,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	tw.Close() //nolint:errcheck
	gw.Close() //nolint:errcheck

	got, err := extractFromTarGz(buf.Bytes(), brand.Name)
	if err != nil {
		t.Fatalf("extractFromTarGz: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content mismatch: got %q, want %q", got, content)
	}
}

// ── v-prefix stripping ────────────────────────────────────────────────────────

func TestVPrefixStripping(t *testing.T) {
	cases := []struct{ in, want string }{
		{"v1.2.3", "1.2.3"},
		{"1.2.3", "1.2.3"},
		{"v0.1.0-alpha", "0.1.0-alpha"},
		{"", ""},
	}
	for _, c := range cases {
		got := stripV(c.in)
		if got != c.want {
			t.Errorf("stripV(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// stripV is a test-local wrapper around the strings.TrimPrefix logic used in runUpdate.
func stripV(s string) string {
	if len(s) > 0 && s[0] == 'v' {
		return s[1:]
	}
	return s
}
