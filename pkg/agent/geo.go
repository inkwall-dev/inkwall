// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/prometheus/client_golang/prometheus"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/geo"
	"github.com/inkwall-dev/inkwall/pkg/policy"
)

// CapabilityGeoTable is what an engine that takes country tables on the
// stream advertises in its Hello (design 0011 §4.4).
const CapabilityGeoTable = "geo-table"

// pendingTable is a country table received before a bundle names it: held
// as the compressed bytes, unchecked and unused, one at a time.
type pendingTable struct {
	hash [32]byte
	gz   []byte
	// cached: read from the cache, with the size it was checked with. Its
	// table was loaded for a signed bundle before the restart: if the
	// cached bundle names another, it is the previous table (design 0011
	// §4.3), kept until the named one arrives.
	cached bool
	size   uint64
}

// geoCacheWrite is a table to write to the cache, once a.mu is released;
// without data, the cache file is removed.
type geoCacheWrite struct {
	seq  uint64
	data []byte
}

type geoMetrics struct {
	bytes    prometheus.Gauge
	built    prometheus.Gauge
	failures prometheus.Counter
}

func newGeoMetrics() geoMetrics {
	return geoMetrics{
		bytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "inkwall_geo_table_bytes",
			Help: "The size of the country table the engine holds, in memory; 0 without one.",
		}),
		built: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "inkwall_geo_table_built_timestamp_seconds",
			Help: "When the database of the country table the engine holds was built (Unix time); 0 without one.",
		}),
		failures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "inkwall_geo_table_load_failures_total",
			Help: "Country tables received that failed a check: too large, the wrong hash, or not a valid table. The engine keeps the one it had.",
		}),
	}
}

func (m geoMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{m.bytes, m.built, m.failures}
}

// GeoTableHash returns the hash of the country table the engine holds, nil
// if it holds none: what its Hello and heartbeats report.
func (a *Agent) GeoTableHash() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.table == nil {
		return nil
	}
	h := a.table.Hash()
	return h[:]
}

// GeoReady is closed once the engine enforces a bundle that names no
// country table, or holds the one it names. The engine waits for it only
// at bootstrap (design 0011 §4.5), within the time it waits for its first
// bundle.
func (a *Agent) GeoReady() <-chan struct{} { return a.geoReady }

// attachGeo returns set with the country table its bundle names: the one
// held, or the pending one, checked now; else the previous bundle's, kept
// until the named one arrives, or none. a.mu is held.
func (a *Agent) attachGeo(set *policy.Set, ref *bundlev1.GeoTableRef) *policy.Set {
	if ref == nil {
		// No geo: nothing to hold, nor to cache: a cached table would
		// otherwise come back, however old, as the previous one of a later
		// bundle that turns geo on again (design 0011 §4.3).
		if (a.table != nil || a.pending != nil) && a.cfg.GeoCacheFile != "" {
			a.geoSeq++
			a.geoWrite = &geoCacheWrite{seq: a.geoSeq} // no data: remove
		}
		a.table, a.pending = nil, nil
		a.geo.bytes.Set(0)
		a.geo.built.Set(0)
		a.markGeoReady()
		return set.WithGeo(false, nil)
	}
	if a.holds(ref) {
		a.markGeoReady()
		return set.WithGeo(true, a.table)
	}
	if p := a.pending; p != nil {
		a.pending = nil // used now, or not named: dropped either way
		if bytes.Equal(p.hash[:], ref.GetSha256()) {
			if t := a.loadTable(p.gz, ref); t != nil {
				a.markGeoReady()
				return set.WithGeo(true, t)
			}
		} else if p.cached && a.table == nil {
			// Restarted between a bundle naming a new table and the table:
			// the cached one is the previous.
			if t, err := geo.Decode(p.gz, p.hash[:], p.size); err == nil {
				a.setTable(t)
				a.log.Info("the bundle names a country table not received yet; enforcing with the cached previous one", slog.Int("previous_ranges", t.Ranges()))
				return set.WithGeo(true, t)
			}
		}
	}
	if a.table != nil {
		a.log.Info("the bundle names a country table not received yet; enforcing with the previous one", slog.Int("previous_ranges", a.table.Ranges()))
	}
	return set.WithGeo(true, a.table)
}

// holds reports whether the engine holds the table ref names. a.mu is
// held.
func (a *Agent) holds(ref *bundlev1.GeoTableRef) bool {
	if a.table == nil {
		return false
	}
	h := a.table.Hash()
	return bytes.Equal(h[:], ref.GetSha256())
}

// loadTable checks and decodes a table for ref, and makes it the one held;
// nil if it fails a check, which is logged and counted. a.mu is held.
func (a *Agent) loadTable(gz []byte, ref *bundlev1.GeoTableRef) *geo.Table {
	t, err := geo.Decode(gz, ref.GetSha256(), ref.GetSize())
	if err != nil {
		a.geo.failures.Inc()
		a.log.Error("country table rejected; keeping the one held", slog.Any("error", err))
		return nil
	}
	a.setTable(t)
	a.log.Info("country table loaded", slog.String("database", t.DatabaseType()), slog.Time("built", t.Built()), slog.Int("ranges", t.Ranges()))
	if a.cfg.GeoCacheFile != "" {
		// Written by flushGeoCache once a.mu is released: up to 14 MiB.
		a.geoSeq++
		data := binary.BigEndian.AppendUint64(make([]byte, 0, 8+len(gz)), ref.GetSize())
		a.geoWrite = &geoCacheWrite{seq: a.geoSeq, data: append(data, gz...)}
	}
	return t
}

// setTable makes t the table held. a.mu is held.
func (a *Agent) setTable(t *geo.Table) {
	a.table = t
	a.geo.bytes.Set(float64(t.Bytes()))
	a.geo.built.Set(float64(t.Built().Unix()))
}

// flushGeoCache writes the table loaded last to the cache: the table's size
// (8 bytes, big-endian), then the gzipped table. Called without a.mu.
func (a *Agent) flushGeoCache() {
	a.mu.Lock()
	w := a.geoWrite
	a.geoWrite = nil
	a.mu.Unlock()
	if w == nil {
		return
	}
	a.geoCacheMu.Lock()
	defer a.geoCacheMu.Unlock()
	if w.seq <= a.geoCached {
		return // a newer table was written meanwhile
	}
	a.geoCached = w.seq
	if w.data == nil {
		if err := os.Remove(a.cfg.GeoCacheFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			a.log.Warn("can't remove the cached country table", slog.Any("error", err))
		}
		return
	}
	if err := replaceFile(a.cfg.GeoCacheFile, ".geo-", w.data); err != nil {
		a.log.Warn("can't cache the country table", slog.Any("error", err))
	}
}

// offerTable takes a country table from the stream, the Secrets or the
// cache: used at once if the enforced bundle names it, else held until a
// bundle does.
func (a *Agent) offerTable(hash, gz []byte) { a.offer(&pendingTable{gz: gz}, hash) }

// offer takes a table: p, with the hash it is offered under.
func (a *Agent) offer(p *pendingTable, hash []byte) {
	switch {
	case len(p.gz) > geo.MaxCompressedBytes:
		a.geo.failures.Inc()
		a.log.Error("country table refused: too large", slog.Int("bytes", len(p.gz)), slog.Int("max", geo.MaxCompressedBytes))
		return
	case len(hash) != 32:
		a.geo.failures.Inc()
		a.log.Error("country table refused: its hash isn't a SHA-256", slog.Int("hash_bytes", len(hash)))
		return
	}
	p.hash = [32]byte(hash)
	gz := p.gz
	defer a.flushGeoCache()
	a.mu.Lock()
	defer a.mu.Unlock()
	ref := a.current.GetGeoTable()
	switch {
	case ref != nil && a.holds(ref) && bytes.Equal(hash, ref.GetSha256()):
		return // held already
	case ref != nil && bytes.Equal(hash, ref.GetSha256()) && a.set != nil:
		if t := a.loadTable(gz, ref); t != nil {
			a.set = a.set.WithGeo(true, t)
			a.cfg.Holder.Store(a.set)
			a.markGeoReady()
		}
		return
	}
	a.pending = p
}

// needsTable reports whether the enforced bundle names a table the engine
// doesn't hold.
func (a *Agent) needsTable() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	ref := a.current.GetGeoTable()
	return ref != nil && !a.holds(ref)
}

// markGeoReady closes geoReady once. a.mu is held.
func (a *Agent) markGeoReady() {
	select {
	case <-a.geoReady:
	default:
		close(a.geoReady)
	}
}

// loadGeoCache reads the cached country table, if any, to hold until a
// bundle names it.
func (a *Agent) loadGeoCache() {
	if a.cfg.GeoCacheFile == "" {
		return
	}
	f, err := os.Open(filepath.Clean(a.cfg.GeoCacheFile))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	var data []byte
	if err == nil {
		data, err = io.ReadAll(io.LimitReader(f, 8+geo.MaxCompressedBytes+1))
		_ = f.Close()
	}
	if err == nil && len(data) < 8 {
		err = errors.New("too short")
	}
	if err != nil {
		a.log.Warn("cached country table not usable", slog.String("file", a.cfg.GeoCacheFile), slog.Any("error", err))
		return
	}
	gz := data[8:]
	h := geo.Hash(gz)
	a.offer(&pendingTable{gz: gz, cached: true, size: binary.BigEndian.Uint64(data)}, h[:])
}

// loadSecretGeo reads the country table from its Secrets when the enforced
// bundle names one the engine doesn't hold: a new engine with no cache,
// while the operator is unreachable.
func (a *Agent) loadSecretGeo(ctx context.Context) {
	if a.cfg.Secret == nil || !a.needsTable() || ctx.Err() != nil {
		return
	}
	gz, err := a.cfg.Secret.fetchGeo(ctx)
	if err != nil {
		if ctx.Err() == nil {
			a.log.Warn("can't read the country table's Secrets; waiting for the operator", slog.Any("error", err))
		}
		return
	}
	h := geo.Hash(gz)
	a.offerTable(h[:], gz)
}

// replaceFile replaces name atomically.
func replaceFile(name, prefix string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(name), prefix)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), name)
}
