// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"net/http"
	"sync"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/geo"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// GeoRules is a policy's geo blocking (design 0011 §2): a deny list, or an
// allow list, of countries.
type GeoRules struct {
	// Countries are the listed countries.
	Countries geo.Set
	// Allow makes Countries an allow list: a client in any other country
	// is denied. It doesn't skip inspection, unlike an IP allow list.
	Allow bool
	// UnknownDeny denies a public address the table has no country for.
	UnknownDeny bool
	// Detect only logs, on a Block policy too.
	Detect bool
}

// geoSampleEvery is how often a (policy, country) makes an event: the
// first, then at most one per minute, each counting the requests it
// stands for (design 0011 §8).
const geoSampleEvery = time.Minute

// geoSampler samples a policy's geo events per country. Its keys are
// bounded: the 676 two-letter codes, unknown, and the table missing.
type geoSampler struct {
	mu sync.Mutex
	// last is each key's last event, in Unix nanoseconds (0: none); n the
	// requests since. Only a policy with geo has one: 8 KiB.
	last [26*26 + 2]int64
	n    [26*26 + 2]uint32
}

const (
	sampleUnknown = 26 * 26
	sampleNoTable = 26*26 + 1
)

// newGeoSampler returns a sampler for a policy with geo, nil without.
func newGeoSampler(g *GeoRules) *geoSampler {
	if g == nil {
		return nil
	}
	return &geoSampler{}
}

// sample reports whether a geo verdict of key at now makes an event, and
// how many requests that event stands for.
func (s *geoSampler) sample(key int, now time.Time) (bool, uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n[key]++
	t := now.UnixNano()
	if s.last[key] != 0 && t-s.last[key] < int64(geoSampleEvery) {
		return false, 0
	}
	n := s.n[key]
	s.last[key], s.n[key] = t, 0
	return true, n
}

func sampleKey(g request.Geo) int {
	switch g.Result {
	case geo.ResultCountry:
		if c := g.Country.String(); len(c) == 2 {
			return int(c[0]-'A')*26 + int(c[1]-'A')
		}
	case geo.ResultNoTable:
		return sampleNoTable
	}
	return sampleUnknown
}

// geoOutcome is what geo decided for a request.
type geoOutcome struct {
	deny    bool // the country is denied (or unknown, with UnknownDeny)
	noTable bool // the bundle names a table the engine doesn't hold
	detect  bool // geo only logs
	sampled bool // the verdict makes an event
	count   uint32
	country string
}

// geoCheck applies the policy's geo blocking to r, whose country the
// policy set looked up. Only a check that decides the request samples its
// event (sample).
func (p *Pipeline) geoCheck(r *request.Request, now time.Time, sample bool) geoOutcome {
	g := p.geo
	if g == nil || !r.Geo.Looked {
		// No geo, or the bundle names no table: skipped.
		return geoOutcome{}
	}
	o := geoOutcome{detect: p.mode == ModeDetect || g.Detect, country: r.Geo.Label()}
	switch r.Geo.Result {
	case geo.ResultNoTable:
		o.noTable = true
	case geo.ResultCountry:
		o.deny = g.Countries.Has(r.Geo.Country) != g.Allow
	case geo.ResultUnknown:
		o.deny = g.UnknownDeny
	}
	if sample && (o.deny || o.noTable && !o.detect && p.failure == FailClosed) {
		o.sampled, o.count = p.geoEvents.sample(sampleKey(r.Geo), now)
	}
	return o
}

// verdict is the geo verdict: 403 geo-deny in Block, logged in Detect.
func (o geoOutcome) verdict() Verdict {
	v := Verdict{Action: ActionLog, Reason: ReasonGeoDeny, GeoMatch: true, Country: o.country,
		SampledEvent: o.sampled, SampledCount: o.count}
	if !o.detect {
		v.Action, v.Status = ActionDeny, http.StatusForbidden
	}
	return v
}

// unavailable is the verdict for a named table the engine doesn't hold,
// with the policy failing closed: 503.
func (o geoOutcome) unavailable() Verdict {
	return Verdict{Action: ActionDeny, Status: http.StatusServiceUnavailable, Reason: ReasonGeoUnavailable,
		SampledEvent: o.sampled, SampledCount: o.count}
}

// mark records on v, decided by something else, that geo denied the
// request or would have: the geo metric counts it.
func (o geoOutcome) mark(v Verdict) Verdict {
	if o.deny {
		v.GeoMatch, v.Country = true, o.country
	}
	return v
}

// blocks reports whether geo decides the request on its own: a denied
// country in Block, or a missing table failing closed.
func (o geoOutcome) blocks(p *Pipeline) bool {
	return o.deny && !o.detect || o.noTable && !o.detect && p.failure == FailClosed
}
