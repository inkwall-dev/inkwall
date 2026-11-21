// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/inkwall-dev/inkwall/operator/enginereport"
)

// The replica's export sinks go into its report. A change of a sink's
// state class is written within the debounce; a count alone never causes
// a write (design 0010 §8).
func TestPublisherReportsExportSinks(t *testing.T) {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	c := fake.NewClientBuilder().WithScheme(s).Build()
	var mu sync.Mutex
	sinks := []enginereport.Sink{{Name: "splunk", State: enginereport.SinkExporting, Pending: 1}}
	p := &Publisher{Client: c, Reader: c, Namespace: "inkwall-system", Replica: "a", Engines: NewTable(),
		Interval: 10 * time.Millisecond, Refresh: time.Hour, ExportDebounce: 200 * time.Millisecond,
		Export: func() []enginereport.Sink {
			mu.Lock()
			defer mu.Unlock()
			return append([]enginereport.Sink(nil), sinks...)
		}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Start(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	read := func() []enginereport.ReplicaSinks {
		got, err := enginereport.ReadExport(ctx, c, "inkwall-system", time.Minute, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
		}
	}
	waitFor("the first report", func() bool { r := read(); return len(r) == 1 && r[0].Replica == "a" && len(r[0].Sinks) == 1 })
	set := func(state string, pending uint64) {
		mu.Lock()
		sinks[0].State, sinks[0].Pending = state, pending
		mu.Unlock()
	}
	set(enginereport.SinkExporting, 500)
	time.Sleep(300 * time.Millisecond)
	if got := read()[0].Sinks[0].Pending; got != 1 {
		t.Errorf("pending %d written: a count alone caused a write", got)
	}
	set(enginereport.SinkFailing, 600)
	waitFor("the state change", func() bool { return read()[0].Sinks[0].State == enginereport.SinkFailing })
	if got := read()[0].Sinks[0].Pending; got != 600 {
		t.Errorf("pending %d with the state change, want the current 600", got)
	}
}

// Within the debounce, flips of a sink's state class make no write; once
// it has passed, one write carries the latest state.
func TestPublisherDebouncesExportClassChanges(t *testing.T) {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	var writes atomic.Int32
	c := fake.NewClientBuilder().WithScheme(s).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.CreateOption) error {
			writes.Add(1)
			return c.Create(ctx, o, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.UpdateOption) error {
			writes.Add(1)
			return c.Update(ctx, o, opts...)
		},
	}).Build()
	var state atomic.Value
	state.Store(enginereport.SinkExporting)
	p := &Publisher{Client: c, Reader: c, Namespace: "inkwall-system", Replica: "a", Engines: NewTable(),
		Interval: 10 * time.Millisecond, Refresh: time.Hour, ExportDebounce: 500 * time.Millisecond,
		Export: func() []enginereport.Sink {
			return []enginereport.Sink{{Name: "splunk", State: state.Load().(string)}}
		}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Start(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	for deadline := time.Now().Add(5 * time.Second); writes.Load() == 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no first report")
		}
	}
	// Two flips within the debounce: no write.
	state.Store(enginereport.SinkFailing)
	time.Sleep(100 * time.Millisecond)
	state.Store(enginereport.SinkDropping)
	time.Sleep(100 * time.Millisecond)
	if n := writes.Load(); n != 1 {
		t.Errorf("%d writes within the debounce, want the first only", n)
	}
	// Past it: one write, with the latest state.
	time.Sleep(500 * time.Millisecond)
	if n := writes.Load(); n != 2 {
		t.Errorf("%d writes after the debounce, want 2", n)
	}
	got, err := enginereport.ReadExport(ctx, c, "inkwall-system", time.Minute, time.Now())
	if err != nil || len(got) != 1 || got[0].Sinks[0].State != enginereport.SinkDropping {
		t.Errorf("report %+v (%v), want the latest state, Dropping", got, err)
	}
}

// A replica without sinks still says so ([]), so the leader can tell it
// from one that doesn't report.
func TestReportWithoutSinks(t *testing.T) {
	if d := reportData([]byte("[]"), 0, []enginereport.Sink{}); d[enginereport.ExportKey] != "[]" {
		t.Errorf("export.json %q, want []", d[enginereport.ExportKey])
	}
	if _, ok := reportData([]byte("[]"), 0, nil)[enginereport.ExportKey]; ok {
		t.Error("export.json written without an exporter")
	}
}
