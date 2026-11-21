// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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
