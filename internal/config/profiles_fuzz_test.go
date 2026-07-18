// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseProfile exercises the YAML strict-mode loader with random
// bytes. The contract under test: parseProfile must never panic, never
// hang, never write outside the dest map, regardless of input. Crashes
// are corpus reductions that get committed to testdata/fuzz/ for
// regression coverage.
//
// Seed corpus mixes real bundled profiles with deliberate edge cases
// (empty file, deeply nested maps, oversized strings, schema typos)
// so fuzzing starts from a meaningful baseline rather than random
// noise that mostly bounces off the YAML lexer.
//
// Run locally:
//
//	go test -run=^$ -fuzz=FuzzParseProfile -fuzztime=30s ./internal/config
func FuzzParseProfile(f *testing.F) {
	seeds := [][]byte{
		nil,
		[]byte(""),
		[]byte("\x00\x00\x00"),
		[]byte("name: foo\nbinary: foo\nversion: 1\n"),
		[]byte("name: foo\nbinary: foo\nversion: 1\nmcp_dir: typo\n"),
		[]byte("name: foo\nversion: 99\nbinary: foo\n"),
		[]byte("name: foo\nversion: 1\nbinary: foo\nnetwork:\n  hosts: [a.example.com, b.example.com]\n"),
		[]byte("config_dirs:\n  - " + repeatChar('x', 4096) + "\n"),
		[]byte("env:\n  KEY: " + repeatChar('v', 8192) + "\n"),
		[]byte("name: ../../../etc/passwd\nbinary: foo\nversion: 1\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dest := make(map[string]ToolDef)
		// parseProfile takes a filename for error context — synthesize
		// one per call so a fuzz failure can be reproduced from the
		// generated corpus entry.
		parseProfile("fuzz.yaml", data, dest)
		// No assertion: the contract is "do not panic / hang / write
		// outside dest". A panic would terminate the fuzz worker; the
		// fuzzer treats that as a crash and shrinks the input.
	})
}

// FuzzLoadProfileDir feeds the directory loader random *.yaml file
// contents and asserts the same no-panic contract. Catches issues at
// the readFile + Decode boundary that the parseProfile-only fuzz
// could miss.
func FuzzLoadProfileDir(f *testing.F) {
	f.Add([]byte("name: a\nbinary: a\nversion: 1\n"))
	f.Add([]byte("not: yaml: at: all"))
	f.Add([]byte{0xff, 0xfe, 0xfd}) // invalid UTF-8

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "fuzz.yaml"), data, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		dest := make(map[string]ToolDef)
		// Suppress stderr noise so the fuzz output stays readable.
		// parseProfile writes validation errors to stderr; we don't
		// care about them in the fuzz, only about panics.
		stderr := os.Stderr
		devnull, _ := os.Open(os.DevNull)
		if devnull != nil {
			os.Stderr = devnull
			defer func() {
				os.Stderr = stderr
				_ = devnull.Close()
			}()
		}
		loadProfileDir(dir, dest)
	})
}

func repeatChar(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
