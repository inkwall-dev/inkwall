// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package router

import "testing"

func TestDecide(t *testing.T) {
	table, err := New(
		[]string{"/healthz", "/static/*"},
		[]string{"/upload/*"},
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		uri  string
		want Decision
	}{
		{"/healthz", SkipAll},
		{"/healthz?verbose=1", SkipAll},
		{"/healthzz", InspectAll},
		{"/static/app.css", SkipAll},
		{"/static/js/app.js?v=3", SkipAll},
		{"/staticfoo", InspectAll},
		{"/upload/avatar", SkipBody},
		{"/api/login", InspectAll},
		{"/", InspectAll},

		// Ambiguous paths are always inspected, even when they look like a
		// skipped prefix: this is what stops skip rules becoming bypasses.
		{"/static/../api/login", InspectAll},
		{"/static/./app.css", InspectAll},
		{"/static/%2e%2e/api/login", InspectAll},
		{"/static/..%2fapi/login", InspectAll},
		{"/static%2fapp.css", InspectAll},
		{"/static\\..\\api", InspectAll},
		{"/static/app.css;/../../api", InspectAll},
		{"//static/app.css", InspectAll},
		{"/static//app.css", InspectAll},
		{"/upload/../api/login", InspectAll},
		{"/static/\uff0e\uff0e/admin", InspectAll},     // fullwidth full stops
		{"/static/\xc0\xae\xc0\xae/admin", InspectAll}, // overlong-UTF-8 dots
		{"/static/caf\u00e9.css", InspectAll},          // any non-ASCII byte
		{"http://evil.example/static/x", InspectAll},
		{"*", InspectAll},
		{"", InspectAll},
	}
	for _, tt := range tests {
		if got := table.Decide(tt.uri); got != tt.want {
			t.Errorf("Decide(%q) = %d, want %d", tt.uri, got, tt.want)
		}
	}
}

func TestEmptyAndNilTablesInspectEverything(t *testing.T) {
	var nilTable *Table
	if nilTable.Decide("/healthz") != InspectAll {
		t.Fatal("nil table must inspect everything")
	}
	empty, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Decide("/healthz") != InspectAll {
		t.Fatal("empty table must inspect everything")
	}
}

func TestNewRejectsBadPatterns(t *testing.T) {
	for _, p := range []string{"static/*", "/st*tic/", "/a/../b", "/a/./b", "/a%2fb", "/a;b", "/a?b", "/a\\b", "/caf\u00e9"} {
		if _, err := New([]string{p}, nil); err == nil {
			t.Errorf("New(%q) succeeded, want error", p)
		}
	}
}

func BenchmarkDecide(b *testing.B) {
	table, err := New([]string{"/healthz", "/static/*", "/assets/*", "/favicon.ico"}, []string{"/upload/*"})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		table.Decide("/api/v2/users/42/orders?page=3&sort=desc")
	}
}
