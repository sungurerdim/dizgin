// SPDX-License-Identifier: MIT

package depclosure

import (
	"reflect"
	"sort"
	"testing"
	"time"
)

// fakeGraph lets tests drive Resolve's BFS/dedup/cycle-safety logic
// without needing a real binary format — parseDeps is swapped for a
// lookup into a plain map for the duration of each test.
func withFakeGraph(t *testing.T, graph map[string][]string) {
	t.Helper()
	orig := parseDeps
	parseDeps = func(path string) ([]string, error) {
		deps, ok := graph[path]
		if !ok {
			return nil, errNotFound
		}
		return deps, nil
	}
	t.Cleanup(func() { parseDeps = orig })
}

type notFoundError struct{}

func (notFoundError) Error() string { return "not found" }

var errNotFound = notFoundError{}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func TestResolve_TransitiveClosure(t *testing.T) {
	withFakeGraph(t, map[string][]string{
		"/seed": {"/liba"},
		"/liba": {"/libb"},
		"/libb": {},
	})
	got := sorted(Resolve([]string{"/seed"}))
	want := []string{"/liba", "/libb"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Resolve = %v, want %v", got, want)
	}
}

func TestResolve_ExcludesSeedsFromResult(t *testing.T) {
	withFakeGraph(t, map[string][]string{
		"/seed": {"/seed"}, // pathological: a binary "depending on itself"
	})
	got := Resolve([]string{"/seed"})
	if len(got) != 0 {
		t.Errorf("Resolve should never include a seed in its own result, got %v", got)
	}
}

func TestResolve_CycleSafe(t *testing.T) {
	// /liba and /libb depend on each other — a real-world impossibility
	// for dylibs but a cheap way to prove the visited-set stops an
	// infinite loop instead of hanging or OOMing.
	withFakeGraph(t, map[string][]string{
		"/seed": {"/liba"},
		"/liba": {"/libb"},
		"/libb": {"/liba"},
	})
	done := make(chan []string, 1)
	go func() { done <- Resolve([]string{"/seed"}) }()
	select {
	case got := <-done:
		want := []string{"/liba", "/libb"}
		if !reflect.DeepEqual(sorted(got), want) {
			t.Errorf("Resolve = %v, want %v", sorted(got), want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Resolve did not return — cycle safety broken")
	}
}

func TestResolve_DedupsSharedDependency(t *testing.T) {
	// Both /liba and /libb depend on /libshared — it must appear once.
	withFakeGraph(t, map[string][]string{
		"/seed":      {"/liba", "/libb"},
		"/liba":      {"/libshared"},
		"/libb":      {"/libshared"},
		"/libshared": {},
	})
	got := Resolve([]string{"/seed"})
	count := 0
	for _, d := range got {
		if d == "/libshared" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("/libshared should appear exactly once, appeared %d times in %v", count, got)
	}
}

func TestResolve_UnparseableSeedSkippedNotFatal(t *testing.T) {
	withFakeGraph(t, map[string][]string{
		// "/seed" deliberately absent from the graph — simulates a
		// PATH entry that isn't this platform's binary format (a shell
		// script, a text file, ...).
	})
	got := Resolve([]string{"/seed"})
	if got != nil {
		t.Errorf("unparseable seed should yield no deps, got %v", got)
	}
}

func TestResolve_NilParseDepsIsNoOp(t *testing.T) {
	orig := parseDeps
	parseDeps = nil
	defer func() { parseDeps = orig }()

	if got := Resolve([]string{"/anything"}); got != nil {
		t.Errorf("Resolve with nil parseDeps (non-Darwin today) should return nil, got %v", got)
	}
}
