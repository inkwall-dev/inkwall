// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controlplanev1_test

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	agentv1 "github.com/inkwall-dev/inkwall/api/agent/v1"
	controlplanev1 "github.com/inkwall-dev/inkwall/api/controlplane/v1"
	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
)

// The request counts were added to the contracts without renumbering:
// their field numbers are fixed, so older and newer peers understand each
// other.
func TestRequestStatsFieldNumbers(t *testing.T) {
	for _, tc := range []struct {
		msg   proto.Message
		field protoreflect.Name
		want  protowire.Number
	}{
		{&agentv1.WatchRequest{}, "events", 5},
		{&agentv1.WatchRequest{}, "stats", 6},
		{&controlplanev1.ConnectRequest{}, "renew_certificate", 7},
		{&controlplanev1.ConnectRequest{}, "request_stats", 8},
		{&controlplanev1.Welcome{}, "accept_events", 2},
		{&controlplanev1.Welcome{}, "accept_request_stats", 3},
		{&controlplanev1.RequestStatsUpload{}, "stats", 3},
		{&eventsv1.RequestStats{}, "policies", 2},
		{&eventsv1.PolicyStats{}, "latency_counts", 5},
	} {
		d := tc.msg.ProtoReflect().Descriptor()
		f := d.Fields().ByName(tc.field)
		if f == nil || f.Number() != tc.want {
			t.Errorf("%s.%s: want field %d", d.FullName(), tc.field, tc.want)
		}
	}
}

// An older control plane's Welcome (without accept_request_stats) asks for
// no request counts; an older reader of a WatchRequest or ConnectRequest
// sees no message it knows in one that carries them, rather than an error.
func TestRequestStatsCompatibility(t *testing.T) {
	old, err := proto.Marshal(&controlplanev1.Welcome{AcceptEvents: true})
	if err != nil {
		t.Fatal(err)
	}
	var w controlplanev1.Welcome
	if err := proto.Unmarshal(old, &w); err != nil || w.GetAcceptRequestStats() || !w.GetAcceptEvents() {
		t.Errorf("an older Welcome: %v, %v", &w, err)
	}

	// The same bytes as the newer message, decoded as an empty one: only
	// the unknown field is left.
	stats := &eventsv1.RequestStats{Policies: []*eventsv1.PolicyStats{{Policy: "shop/site", Allowed: 1}}}
	for _, m := range []proto.Message{
		&agentv1.WatchRequest{Msg: &agentv1.WatchRequest_Stats{Stats: stats}},
		&controlplanev1.ConnectRequest{Msg: &controlplanev1.ConnectRequest_RequestStats{RequestStats: &controlplanev1.RequestStatsUpload{Stats: stats}}},
	} {
		raw, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var empty eventsv1.EventBatch // no field 6 or 8: as an older reader
		if err := proto.Unmarshal(raw, &empty); err != nil || len(empty.GetEvents()) != 0 || len(empty.ProtoReflect().GetUnknown()) == 0 {
			t.Errorf("%T read by an older peer: %v, %v", m, &empty, err)
		}
	}
}
