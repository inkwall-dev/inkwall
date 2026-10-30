// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package distribution serves bundles to the engines (0004 §4.7): every
// operator replica runs the BundleService, pushes each new bundle to its
// connected engines, and records what they applied. The leader merges the
// replicas' records into the Enforced condition of each policy.
package distribution

import (
	"slices"
	"strings"
	"sync"
	"time"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
)

// Engine is what a replica knows about one connected engine.
type Engine struct {
	// ID is the engine's own, from its Hello.
	ID string `json:"id"`
	// ServiceAccount authenticated the stream, as "namespace/name".
	ServiceAccount string `json:"serviceAccount"`
	// Pod and node: from the token when it is bound to a pod, otherwise as
	// the engine reported them.
	PodNamespace  string `json:"podNamespace,omitempty"`
	PodName       string `json:"podName,omitempty"`
	NodeName      string `json:"nodeName,omitempty"`
	EngineVersion string `json:"engineVersion,omitempty"`
	// Applied is the newest bundle version the engine runs.
	Applied uint64 `json:"applied"`
	// Rejected is the newest version the engine refused, and why.
	Rejected    uint64 `json:"rejected,omitempty"`
	RejectError string `json:"rejectError,omitempty"`
	// TrustedKeys are the IDs of the bundle signing keys the engine
	// accepts; empty from an engine older than key rotation.
	TrustedKeys []string `json:"trustedKeys,omitempty"`
	// Replica is the operator replica the engine is connected to.
	Replica     string    `json:"replica"`
	ConnectedAt time.Time `json:"connectedAt"`

	// conn identifies the stream that owns the record: an engine that
	// reconnects to the same replica replaces it.
	conn uint64
}

// Table is a replica's connected engines.
type Table struct {
	mu      sync.Mutex
	engines map[string]*Engine
	gen     uint64
	conns   uint64
}

// NewTable returns an empty table.
func NewTable() *Table { return &Table{engines: map[string]*Engine{}} }

// Update changes the engine with id, if it is connected; f reports whether
// it changed anything.
func (t *Table) Update(id string, f func(*Engine) bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.engines[id]; ok && f(e) {
		t.gen++
	}
}

// Connect records a new stream for the engine e.ID, replacing an older one,
// and returns the connection to pass to Disconnect.
func (t *Table) Connect(e Engine) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conns++
	e.conn = t.conns
	t.engines[e.ID] = &e
	t.gen++
	return e.conn
}

// Disconnect forgets the engine id if conn still owns its record.
func (t *Table) Disconnect(id string, conn uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.engines[id]; ok && e.conn == conn {
		delete(t.engines, id)
		t.gen++
	}
}

// Snapshot returns the engines sorted by ID, and a generation that changes
// whenever the table does.
func (t *Table) Snapshot() ([]Engine, uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Engine, 0, len(t.engines))
	for _, e := range t.engines {
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b Engine) int { return strings.Compare(a.ID, b.ID) })
	return out, t.gen
}

// Store holds the current bundle and tells streams when it changes.
type Store struct {
	mu      sync.Mutex
	signed  *bundlev1.SignedBundle
	version uint64
	changed chan struct{}
}

// NewStore returns an empty store.
func NewStore() *Store { return &Store{changed: make(chan struct{})} }

// Set makes signed, of version, the current bundle.
func (s *Store) Set(signed *bundlev1.SignedBundle, version uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if version == s.version && s.signed != nil {
		return
	}
	s.signed, s.version = signed, version
	close(s.changed)
	s.changed = make(chan struct{})
}

// Current returns the current bundle (nil before the first), its version,
// and a channel closed when it is replaced.
func (s *Store) Current() (*bundlev1.SignedBundle, uint64, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signed, s.version, s.changed
}
