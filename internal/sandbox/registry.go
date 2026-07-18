// SPDX-License-Identifier: MIT

package sandbox

import (
	"fmt"
	"sort"
	"sync"
)

var (
	mu       sync.RWMutex
	backends = make(map[string]Backend)
)

// Register adds a Backend to the global registry.
// It panics if a backend with the same name is registered twice,
// which catches misconfigured init() blocks at startup.
func Register(b Backend) {
	mu.Lock()
	defer mu.Unlock()

	name := b.Name()
	if _, exists := backends[name]; exists {
		panic(fmt.Sprintf("sandbox: backend %q registered twice", name))
	}
	backends[name] = b
}

// Get returns the Backend registered under name.
// Returns an error if no backend with that name has been registered.
func Get(name string) (Backend, error) {
	mu.RLock()
	defer mu.RUnlock()

	b, ok := backends[name]
	if !ok {
		return nil, fmt.Errorf("sandbox: backend %q not found (registered: %v)", name, registeredNames())
	}
	return b, nil
}

// registeredNames returns the sorted list of registered backend names.
// Caller must hold mu (at least read lock).
func registeredNames() []string {
	names := make([]string, 0, len(backends))
	for n := range backends {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
