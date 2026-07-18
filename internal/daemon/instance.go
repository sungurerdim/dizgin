// SPDX-License-Identifier: MIT

package daemon

import (
	"sync"
	"time"
)

// InstanceStatus represents the lifecycle state of a sandbox session as seen
// by the daemon.
type InstanceStatus string

const (
	StatusRunning   InstanceStatus = "running"
	StatusSuspended InstanceStatus = "suspended"
	StatusDead      InstanceStatus = "dead"
)

// heartbeatTimeout is the duration after which an instance without a heartbeat
// is considered dead.
const heartbeatTimeout = 60 * time.Second

// InstanceData holds the value fields of an Instance, safe to copy by value.
type InstanceData struct {
	LastHeartbeat  time.Time
	ID             string
	Tool           string
	Workdir        string
	Backend        string
	Status         InstanceStatus
	LastSnippet    string
	ChildPIDs      []int
	Args           []string
	CPUPercent     float64
	MemoryBytes    uint64
	PIDs           int
	ExitCode       int
	IOReadBytes    uint64
	IOWriteBytes   uint64
	DiskUsageBytes uint64
	UptimeSeconds  int64
	ThreadCount    int
	HandleCount    int
	PID            int
}

// Instance holds the last known state of a running dizgin session.
type Instance struct {
	InstanceData
	mu sync.Mutex
}

// update applies a heartbeat message to the instance.
func (inst *Instance) update(msg Message) {
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if msg.Status != "" {
		inst.Status = InstanceStatus(msg.Status)
	}
	if msg.Snippet != "" {
		inst.LastSnippet = msg.Snippet
	}
	if msg.Memory > 0 {
		inst.MemoryBytes = msg.Memory
	}
	if msg.CPU > 0 {
		inst.CPUPercent = msg.CPU
	}
	if msg.PIDs > 0 {
		inst.PIDs = msg.PIDs
	}
	// Extended metrics.
	if msg.IORead > 0 {
		inst.IOReadBytes = msg.IORead
	}
	if msg.IOWrite > 0 {
		inst.IOWriteBytes = msg.IOWrite
	}
	if msg.DiskUsage > 0 {
		inst.DiskUsageBytes = msg.DiskUsage
	}
	if msg.Uptime > 0 {
		inst.UptimeSeconds = msg.Uptime
	}
	if msg.ThreadCount > 0 {
		inst.ThreadCount = msg.ThreadCount
	}
	if msg.HandleCount > 0 {
		inst.HandleCount = msg.HandleCount
	}
	if len(msg.ChildPIDs) > 0 && len(msg.ChildPIDs) <= 10000 {
		inst.ChildPIDs = msg.ChildPIDs
	}
	inst.LastHeartbeat = time.Now()
}

// isDead reports whether the instance has missed the heartbeat timeout.
func (inst *Instance) isDead() bool {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	return time.Since(inst.LastHeartbeat) > heartbeatTimeout
}

// Snapshot returns a copy of the instance data safe for reading without a lock.
func (inst *Instance) Snapshot() InstanceData {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	s := InstanceData{
		ID:             inst.ID,
		PID:            inst.PID,
		Tool:           inst.Tool,
		Workdir:        inst.Workdir,
		Backend:        inst.Backend,
		Status:         inst.Status,
		LastHeartbeat:  inst.LastHeartbeat,
		LastSnippet:    inst.LastSnippet,
		MemoryBytes:    inst.MemoryBytes,
		CPUPercent:     inst.CPUPercent,
		PIDs:           inst.PIDs,
		ExitCode:       inst.ExitCode,
		IOReadBytes:    inst.IOReadBytes,
		IOWriteBytes:   inst.IOWriteBytes,
		DiskUsageBytes: inst.DiskUsageBytes,
		UptimeSeconds:  inst.UptimeSeconds,
		ThreadCount:    inst.ThreadCount,
		HandleCount:    inst.HandleCount,
	}
	if len(inst.Args) > 0 {
		s.Args = make([]string, len(inst.Args))
		copy(s.Args, inst.Args)
	}
	if len(inst.ChildPIDs) > 0 {
		s.ChildPIDs = make([]int, len(inst.ChildPIDs))
		copy(s.ChildPIDs, inst.ChildPIDs)
	}
	return s
}

// Registry stores active sandbox instances, keyed by session ID.
type Registry struct {
	instances map[string]*Instance
	mu        sync.RWMutex
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{instances: make(map[string]*Instance)}
}

// Register adds a new instance. If an instance with the same ID already exists
// it is replaced.
func (r *Registry) Register(inst *Instance) {
	r.mu.Lock()
	defer r.mu.Unlock()
	inst.LastHeartbeat = time.Now()
	r.instances[inst.ID] = inst
}

// Update applies a heartbeat update to the named instance.
// Returns false if the instance is not registered.
func (r *Registry) Update(id string, msg Message) bool {
	r.mu.RLock()
	inst, ok := r.instances[id]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	inst.update(msg)
	return true
}

// Remove deletes the instance and returns it. Returns nil if not found.
func (r *Registry) Remove(id string) *Instance {
	r.mu.Lock()
	defer r.mu.Unlock()
	inst := r.instances[id]
	delete(r.instances, id)
	return inst
}

// Get returns the instance with the given ID, or nil.
func (r *Registry) Get(id string) *Instance {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.instances[id]
}

// Snapshots returns a snapshot of all registered instances.
func (r *Registry) Snapshots() []InstanceData {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]InstanceData, 0, len(r.instances))
	for _, inst := range r.instances {
		out = append(out, inst.Snapshot())
	}
	return out
}

// Info returns a JSON-serialisable InstanceInfo for this instance.
func (inst *Instance) Info() InstanceInfo {
	s := inst.Snapshot()
	return InstanceInfo{
		ID:             s.ID,
		PID:            s.PID,
		Tool:           s.Tool,
		Workdir:        s.Workdir,
		Backend:        s.Backend,
		Status:         s.Status,
		LastHeartbeat:  s.LastHeartbeat.Unix(),
		LastSnippet:    s.LastSnippet,
		MemoryBytes:    s.MemoryBytes,
		CPUPercent:     s.CPUPercent,
		PIDs:           s.PIDs,
		ExitCode:       s.ExitCode,
		IOReadBytes:    s.IOReadBytes,
		IOWriteBytes:   s.IOWriteBytes,
		DiskUsageBytes: s.DiskUsageBytes,
		UptimeSeconds:  s.UptimeSeconds,
		ThreadCount:    s.ThreadCount,
		HandleCount:    s.HandleCount,
		ChildPIDs:      s.ChildPIDs,
		Args:           s.Args,
	}
}

// Count returns the number of registered instances under a read lock.
// Cheaper than Infos() for hot-loop polling (no per-instance copy).
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.instances)
}

// Infos returns JSON-serialisable InstanceInfo slices for all registered instances.
func (r *Registry) Infos() []InstanceInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]InstanceInfo, 0, len(r.instances))
	for _, inst := range r.instances {
		out = append(out, inst.Info())
	}
	return out
}

// PruneDeadInstances removes instances that have exceeded the heartbeat timeout.
func (r *Registry) PruneDeadInstances() {
	// First pass: collect dead IDs under read lock to reduce contention.
	r.mu.RLock()
	var deadIDs []string
	for id, inst := range r.instances {
		if inst.isDead() {
			deadIDs = append(deadIDs, id)
		}
	}
	r.mu.RUnlock()

	if len(deadIDs) == 0 {
		return
	}

	// Second pass: remove under write lock, re-checking dead to avoid
	// removing instances that received a heartbeat between the two passes.
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range deadIDs {
		inst, ok := r.instances[id]
		if !ok {
			continue
		}
		if inst.isDead() {
			inst.mu.Lock()
			inst.Status = StatusDead
			inst.mu.Unlock()
			delete(r.instances, id)
		}
	}
}
