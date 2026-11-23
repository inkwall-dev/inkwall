// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package distribution serves bundles to the engines (0004 §4.7): every
// operator replica runs the BundleService, pushes each new bundle to its
// connected engines, and records what they applied. The leader merges the
// replicas' records into the Enforced condition of each policy.
package distribution

import (
	"bytes"
	"slices"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/inkwall-dev/inkwall/api/agent/v1"
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
	// ProbeReceipts are the receipts of the operator's probes the engine
	// verified where the proxy discards its answer (#475), as its last
	// heartbeat reported them: the leader's probe matches them.
	ProbeReceipts []string `json:"probeReceipts,omitempty"`
	// GeoTable is the hash of the country table the engine holds, in hex
	// (design 0011 §4.4); empty if none, or from an engine before 0.7.0.
	GeoTable string `json:"geoTable,omitempty"`
	// Replica is the operator replica the engine is connected to.
	Replica     string    `json:"replica"`
	ConnectedAt time.Time `json:"connectedAt"`

	// key is the record's key in the table (Key); conn identifies the
	// stream that owns the record: an engine that reconnects to the same
	// replica replaces it.
	key  string
	conn uint64
}

// Key is the table key of an engine authenticated as id that says it is
// engineID: the pod its token is bound to, otherwise its ServiceAccount
// and engineID. An engine can't take the record of another pod, or of
// another ServiceAccount's engine, by naming its engine ID.
func Key(id Identity, engineID string) string {
	if id.PodName != "" {
		return "pod/" + id.PodNamespace + "/" + id.PodName
	}
	return "sa/" + id.ServiceAccount + "/" + engineID
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

// Update changes the record of key if conn still owns it; f reports
// whether it changed anything.
func (t *Table) Update(key string, conn uint64, f func(*Engine) bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.engines[key]; ok && e.conn == conn && f(e) {
		t.gen++
	}
}

// Connect records a new stream for the engine e under key (Key), replacing
// an older one, and returns the connection to pass to Update and
// Disconnect.
func (t *Table) Connect(key string, e Engine) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conns++
	e.key, e.conn = key, t.conns
	t.engines[key] = &e
	t.gen++
	return e.conn
}

// Disconnect forgets the record of key if conn still owns it.
func (t *Table) Disconnect(key string, conn uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.engines[key]; ok && e.conn == conn {
		delete(t.engines, key)
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
	slices.SortFunc(out, func(a, b Engine) int {
		if c := strings.Compare(a.ID, b.ID); c != 0 {
			return c
		}
		return strings.Compare(a.key, b.key)
	})
	return out, t.gen
}

// Store holds the current bundle and tells streams when it changes.
type Store struct {
	mu      sync.Mutex
	signed  *bundlev1.SignedBundle
	version uint64
	changed chan struct{}
	// policies are the bundle's policies: by ID, the first bundle that
	// enforces each as it is in this one (bundle.PolicyVersions).
	policies map[string]uint64
	// suspended: the bundle suspends inspection.
	suspended bool
	// geo is the table hash the current bundle names, nil if none; tables
	// are the country tables the replica serves, newest first: the current
	// one and the one before, for streams still sending it.
	geo    []byte
	tables []*agentv1.WatchResponse
}

// geoTables is how many country tables a Store keeps.
const geoTables = 2

// NewStore returns an empty store.
func NewStore() *Store { return &Store{changed: make(chan struct{})} }

// Set makes signed, of version, the current bundle.
func (s *Store) Set(signed *bundlev1.SignedBundle, version uint64) {
	s.SetWithGeo(signed, version, nil)
}

// SetWithGeo makes signed, of version, the current bundle, naming the
// country table geo (nil: none), which the Store must hold already
// (AddGeoTable): a stream never sends a bundle before its table.
func (s *Store) SetWithGeo(signed *bundlev1.SignedBundle, version uint64, geo []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if version == s.version && s.signed != nil {
		return
	}
	s.signed, s.version, s.geo = signed, version, geo
	close(s.changed)
	s.changed = make(chan struct{})
}

// AddGeoTable keeps the gzipped country table gz, of table hash hash, to
// send to engines.
func (s *Store) AddGeoTable(hash, gz []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.geoTable(hash) != nil {
		return
	}
	m := &agentv1.WatchResponse{Msg: &agentv1.WatchResponse_GeoTable{GeoTable: &agentv1.CountryTableMessage{Sha256: hash, Table: gz}}}
	s.tables = append([]*agentv1.WatchResponse{m}, s.tables...)
	if len(s.tables) > geoTables {
		s.tables = s.tables[:geoTables]
	}
}

// GeoNamed reports whether the current bundle names a country table.
func (s *Store) GeoNamed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.geo != nil
}

// HasGeoTable reports whether the Store holds the table hash.
func (s *Store) HasGeoTable(hash []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.geoTable(hash) != nil
}

// GeoTable returns the message carrying the table hash, nil if the Store
// doesn't hold it.
func (s *Store) GeoTable(hash []byte) *agentv1.WatchResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.geoTable(hash)
}

func (s *Store) geoTable(hash []byte) *agentv1.WatchResponse {
	for _, m := range s.tables {
		if bytes.Equal(m.GetGeoTable().GetSha256(), hash) {
			return m
		}
	}
	return nil
}

// SetPolicies records the current bundle's policies, the only ones whose
// request counts are taken from engines, with the first bundle that
// enforces each as it is now; and whether the bundle suspends inspection.
func (s *Store) SetPolicies(versions map[string]uint64, suspended bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies, s.suspended = versions, suspended
}

// HasPolicy reports whether the current bundle has the policy id.
func (s *Store) HasPolicy(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.policies[id]
	return ok
}

// PolicyVersion returns the first bundle that enforces the policy id as
// the current bundle does; 0 if it doesn't have it.
func (s *Store) PolicyVersion(id string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policies[id]
}

// Suspended reports whether the current bundle suspends inspection.
func (s *Store) Suspended() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.suspended
}

// Current returns the current bundle (nil before the first), its version,
// and a channel closed when it is replaced.
func (s *Store) Current() (*bundlev1.SignedBundle, uint64, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signed, s.version, s.changed
}

// current is Current, with the table hash the bundle names.
func (s *Store) current() (*bundlev1.SignedBundle, uint64, []byte, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signed, s.version, s.geo, s.changed
}
