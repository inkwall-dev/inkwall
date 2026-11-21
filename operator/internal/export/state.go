// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"sync"
	"time"
)

// statusWindow: a sink that failed this long without a success is
// failing; one that dropped for a full buffer this recently is dropping
// (design 0010 §8).
const statusWindow = 5 * time.Minute

// The state classes of a sink, in the order of precedence of the
// EventsExported condition: the first that applies wins.
const (
	StateConfigInvalid  = "ConfigInvalid"
	StateAddressRefused = "AddressRefused"
	StateFailing        = "Failing"
	StateDropping       = "Dropping"
	StateExporting      = "Exporting"
)

// SinkStatus is a sink's state on this replica.
type SinkStatus struct {
	Name string `json:"name"`
	// State is one of the State constants.
	State string `json:"state"`
	// Message says why, for every state but Exporting: the error class,
	// never a Secret or more than a short, escaped part of a response.
	Message string `json:"message,omitempty"`
	// Pending counts the events the sink hasn't had answered.
	Pending uint64 `json:"pending"`
	// Plaintext: the sink's endpoint is http:// or grpc://.
	Plaintext   bool      `json:"plaintext,omitempty"`
	LastSuccess time.Time `json:"lastSuccess,omitzero"`
}

// sinkState tracks what the condition needs of a sink.
type sinkState struct {
	mu           sync.Mutex
	configErr    string
	plaintext    bool
	lastSuccess  time.Time
	lastFailure  time.Time
	failingSince time.Time // since the first failure after a success
	lastDetail   string
	lastKind     string
	refused      string
	lastFullDrop time.Time
}

func (s *sinkState) succeeded(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSuccess, s.failingSince, s.refused = now, time.Time{}, ""
}

func (s *sinkState) failed(now time.Time, r result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failingSince.IsZero() {
		s.failingSince = now
	}
	s.lastFailure, s.lastKind, s.lastDetail, s.refused = now, r.kind, r.detail, r.refused
}

func (s *sinkState) droppedFull(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastFullDrop = now
}

func (s *sinkState) configure(err error, plaintext bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configErr, s.plaintext = "", plaintext
	if err != nil {
		s.configErr = err.Error()
	}
}

// status classes the sink at now.
func (s *sinkState) status(name string, pending uint64, now time.Time) SinkStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := SinkStatus{Name: name, Pending: pending, Plaintext: s.plaintext, LastSuccess: s.lastSuccess, State: StateExporting}
	failing := !s.failingSince.IsZero() && s.lastFailure.After(s.lastSuccess)
	switch {
	case s.configErr != "":
		st.State, st.Message = StateConfigInvalid, s.configErr
	case failing && s.refused != "":
		st.State, st.Message = StateAddressRefused, "the sink's host resolves only to refused addresses: "+s.refused
	case failing && now.Sub(s.failingSince) >= statusWindow:
		st.State, st.Message = StateFailing, "failing since "+s.failingSince.UTC().Format(time.RFC3339)+": "+s.lastKind+": "+s.lastDetail
	case !s.lastFullDrop.IsZero() && now.Sub(s.lastFullDrop) < statusWindow:
		st.State, st.Message = StateDropping, "dropping events for a full buffer: the sink can't keep up"
	}
	return st
}
