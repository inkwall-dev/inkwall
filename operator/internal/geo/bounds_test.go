// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package geo

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/inkwall-dev/inkwall/operator/internal/geo/mmdbtest"
)

// largeDB is a database of n /24 networks with alternating countries, so
// nothing merges: n IPv4 ranges, each with a distinct record, as a City
// database's are mostly distinct.
func largeDB(t testing.TB, n int) []byte {
	t.Helper()
	nets := make([]mmdbtest.Network, n)
	for i := range nets {
		code := "AU"
		if i%2 == 1 {
			code = "NZ"
		}
		rec := &mmdbtest.Record{Country: code, Continent: strconv.Itoa(i)}
		nets[i] = mmdbtest.Network{Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(1 + i>>16), byte(i >> 8), byte(i), 0}), 24), Record: rec}
	}
	return must(mmdbtest.DB{Networks: nets}.Bytes())
}

// TestRefreshTruncated: the unchanged-source check hashes the mapped file
// inside Compile's guard, so a file truncated under it is a recovered
// fault, the stored table kept.
func TestRefreshTruncated(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mmap faults on Linux")
	}
	root := t.TempDir()
	path := filepath.Join(root, "country.mmdb")
	if err := os.WriteFile(path, largeDB(t, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := ReadFile(root, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	stored, _ := compileOK(t, sampleDB(t))
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	o := Refresh(context.Background(), src, nil, stored)
	if o.Reason != ReasonInvalid || o.Table != stored {
		t.Errorf("%s: %s, table %v", o.Reason, o.Message, o.Table)
	}
}

// TestNodeCountBound: a tree with more nodes than the walk may yield
// networks is refused from its header, before anything walks it.
func TestNodeCountBound(t *testing.T) {
	defer func(n int) { maxNetworks = n }(maxNetworks)
	maxNetworks = 64
	_, err := Compile(context.Background(), largeDB(t, 256), nil)
	if ReasonOf(err) != ReasonTooLarge {
		t.Errorf("%v, want TooLarge", err)
	}
	if MaxNetworks < MaxFileBytes/8 {
		t.Errorf("MaxNetworks %d refuses trees a file within the bound can hold", MaxNetworks)
	}
}

// TestAlternatingAliases: a tree of alternating aliases and empty leaves,
// under 1 KiB, would grow the walk's gap list by a gap per network, to
// gigabytes; it is refused at MaxAliases gaps, at once.
func TestAlternatingAliases(t *testing.T) {
	// A lower cap keeps the guard walk's yields (bounded by it) quick
	// under the race detector; the gaps stop at MaxAliases either way.
	defer func(n int) { maxNetworks = n }(maxNetworks)
	maxNetworks = 1 << 21
	// 1,024 aliases pass the guard walk; the gaps stop at MaxAliases.
	if _, err := Compile(context.Background(), mmdbtest.AlternatingAliases(10), nil); ReasonOf(err) != ReasonInvalid ||
		!strings.Contains(err.Error(), "prefixes alias the IPv4 subtree") {
		t.Errorf("1,024 aliases: %v", err)
	}
	db := mmdbtest.AlternatingAliases(26)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	_, err := Compile(context.Background(), db, nil)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if r := ReasonOf(err); r != ReasonInvalid && r != ReasonTooLarge {
		t.Errorf("%v, want Invalid or TooLarge", err)
	}
	// The guard walk's yields, bounded by the network cap: seconds under
	// the race detector, well within the deadline.
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("took %v", d)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Errorf("allocated %d MiB", grew>>20)
	}
}

func TestReadFileFIFO(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadFile(root, root+"/fifo")
		done <- err
	}()
	select {
	case err := <-done:
		if ReasonOf(err) != ReasonInvalid {
			t.Errorf("%v, want Invalid", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("opening a FIFO blocked")
	}
}

// TestTransient: the API server's errors and a cancelled context leave the
// condition as it is, and keep the stored table.
func TestTransient(t *testing.T) {
	ctx := context.Background()
	stored, _ := compileOK(t, sampleDB(t))
	broken := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errors.New("connection refused")
		},
	}).Build()
	src, err := ReadSecret(ctx, broken, ns, "geo-db", "country.mmdb")
	if ReasonOf(err) != "" {
		t.Fatalf("API error: reason %q", ReasonOf(err))
	}
	if o := Refresh(ctx, src, err, stored); !o.Transient() || o.Table != stored {
		t.Errorf("API error: %+v", o)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	newer := must(mmdbtest.DB{BuildEpoch: stored.BuildEpoch + 1, Networks: []mmdbtest.Network{nw("1.0.0.0/8", cc("DE"))}}.Bytes())
	o := Refresh(cancelled, &Source{Data: newer}, nil, stored)
	if !o.Transient() || o.Table != stored {
		t.Errorf("cancelled: reason %q, err %v", o.Reason, o.Err)
	}
}

// TestCompilePeakHeap: the compile's heap stays within a few times the
// table it builds (design 0011 §6: the ranges, their marshalled proto and
// its gzip), plus the record cache.
func TestCompilePeakHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("a large database")
	}
	const n = 200_000
	db := largeDB(t, n)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak uint64
	stop, sampled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sampled)
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
			runtime.ReadMemStats(&m)
			peak = max(peak, m.HeapInuse)
		}
	}()
	tb, err := Compile(context.Background(), db, nil)
	close(stop)
	<-sampled
	if err != nil {
		t.Fatal(err)
	}
	ranges := uint64(6 * tb.Ranges)
	grew := peak - min(peak, before.HeapInuse)
	t.Logf("%d ranges (%d KiB): peak heap %d KiB over the start", tb.Ranges, ranges>>10, grew>>10)
	if limit := 6*ranges + 16<<20; grew > limit {
		t.Errorf("peak heap grew %d KiB, over %d KiB", grew>>10, limit>>10)
	}
}

func TestLoadRestores(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().Build()
	tb, _ := compileOK(t, sampleDB(t, mmdbtest.MaxMindAliases...))
	if err := Store(ctx, c, c, ns, tb); err != nil {
		t.Fatal(err)
	}
	got, err := Load(ctx, c, ns)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Aliases, tb.Aliases) || got.BadCodes != tb.BadCodes || tb.BadCodes == 0 {
		t.Errorf("aliases %v, bad codes %d; stored %v, %d", got.Aliases, got.BadCodes, tb.Aliases, tb.BadCodes)
	}
}
