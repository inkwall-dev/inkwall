// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"net/http"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/geo"
	"github.com/inkwall-dev/inkwall/pkg/iplist"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

func countries(codes ...string) geo.Set {
	var s geo.Set
	for _, c := range codes {
		cc, _ := geo.ParseCountry(c)
		s.Add(cc)
	}
	return s
}

// geoPipeline is a pipeline with IP lists (10/8 allowed, 203.0.113/24
// denied), /healthz skipped, the rules' result res, and geo rules g.
func geoPipeline(t *testing.T, mode Mode, failure FailureMode, g *GeoRules, res rules.Result, limits ...RateLimitConfig) (*Pipeline, *recordingEvaluator) {
	t.Helper()
	eval := &recordingEvaluator{res: res}
	allow, _ := iplist.Parse([]string{"10.0.0.0/8"})
	deny, _ := iplist.Parse([]string{"203.0.113.0/24"})
	routes, err := router.New([]string{"/healthz"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Mode: mode, FailureMode: failure, IPAllow: allow, IPDeny: deny, Routes: routes, Geo: g}
	if len(limits) > 0 {
		p, _ := limitedPipeline(t, mode, eval, limits...)
		p.geo, p.geoEvents, p.failure = g, newGeoSampler(g), failure.Resolve(mode)
		return p, eval
	}
	return New(eval, cfg), eval
}

// geoReq is a request from client, whose country the policy set found:
// code, "?" for unknown, "" for private, "-" for a missing table, "off"
// for no table named.
func geoReq(client, uri, country string) *request.Request {
	r := req(client, http.MethodGet, uri)
	switch country {
	case "off":
	case "?":
		r.Geo = request.Geo{Looked: true, Result: geo.ResultUnknown}
	case "":
		r.Geo = request.Geo{Looked: true, Result: geo.ResultPrivate}
	case "-":
		r.Geo = request.Geo{Looked: true, Result: geo.ResultNoTable}
	default:
		c, _ := geo.ParseCountry(country)
		r.Geo = request.Geo{Looked: true, Country: c, Result: geo.ResultCountry}
	}
	return r
}

func TestGeoOrder(t *testing.T) {
	denyRU := &GeoRules{Countries: countries("RU", "KP")}
	for _, tc := range []struct {
		name           string
		mode           Mode
		g              *GeoRules
		res            rules.Result
		client, uri    string
		country        string
		action         Action
		reason         Reason
		status         int
		evaluated, geo bool
	}{
		{"IP deny first", ModeBlock, denyRU, rules.Result{}, "203.0.113.5", "/", "RU", ActionDeny, ReasonIPDeny, 403, false, false},
		{"IP allow first", ModeBlock, denyRU, rules.Result{}, "10.1.1.1", "/", "RU", ActionAllow, ReasonIPAllow, 0, false, false},
		{"denied country", ModeBlock, denyRU, rules.Result{}, "198.51.100.1", "/", "RU", ActionDeny, ReasonGeoDeny, 403, false, true},
		{"denied on a skipped path", ModeBlock, denyRU, rules.Result{}, "198.51.100.1", "/healthz", "RU", ActionDeny, ReasonGeoDeny, 403, false, true},
		{"other country", ModeBlock, denyRU, rules.Result{}, "198.51.100.1", "/", "DE", ActionAllow, ReasonNone, 0, true, false},
		{"allow list, in", ModeBlock, &GeoRules{Countries: countries("DE"), Allow: true}, rules.Result{}, "198.51.100.1", "/", "DE", ActionAllow, ReasonNone, 0, true, false},
		{"allow list, out", ModeBlock, &GeoRules{Countries: countries("DE"), Allow: true}, rules.Result{}, "198.51.100.1", "/", "FR", ActionDeny, ReasonGeoDeny, 403, false, true},
		{"allow list, rules still run", ModeBlock, &GeoRules{Countries: countries("DE"), Allow: true}, blocked, "198.51.100.1", "/", "DE", ActionDeny, ReasonRule, 403, true, false},
		{"unknown allowed", ModeBlock, denyRU, rules.Result{}, "198.51.100.1", "/", "?", ActionAllow, ReasonNone, 0, true, false},
		{"unknown denied", ModeBlock, &GeoRules{Countries: countries("RU"), UnknownDeny: true}, rules.Result{}, "198.51.100.1", "/", "?", ActionDeny, ReasonGeoDeny, 403, false, true},
		{"private never denied", ModeBlock, &GeoRules{Countries: countries("DE"), Allow: true, UnknownDeny: true}, rules.Result{}, "192.168.1.1", "/", "", ActionAllow, ReasonNone, 0, true, false},
		{"no table named: skipped", ModeBlock, &GeoRules{Countries: countries("DE"), Allow: true}, rules.Result{}, "198.51.100.1", "/", "off", ActionAllow, ReasonNone, 0, true, false},
		{"Detect logs, rules run", ModeDetect, denyRU, rules.Result{}, "198.51.100.1", "/", "RU", ActionLog, ReasonGeoDeny, 0, true, true},
		{"Detect, a rule's reason wins", ModeDetect, denyRU, blocked, "198.51.100.1", "/", "RU", ActionLog, ReasonRule, 0, true, true},
		{"Detect on a skipped path logs geo-deny", ModeDetect, denyRU, rules.Result{}, "198.51.100.1", "/healthz", "RU", ActionLog, ReasonGeoDeny, 0, false, true},
		{"geo.mode Detect on a Block policy", ModeBlock, &GeoRules{Countries: countries("RU"), Detect: true}, rules.Result{}, "198.51.100.1", "/", "RU", ActionLog, ReasonGeoDeny, 0, true, true},
		{"geo.mode Detect, a Block rule still denies", ModeBlock, &GeoRules{Countries: countries("RU"), Detect: true}, blocked, "198.51.100.1", "/", "RU", ActionDeny, ReasonRule, 403, true, true},
	} {
		p, eval := geoPipeline(t, tc.mode, FailAuto, tc.g, tc.res)
		r := geoReq(tc.client, tc.uri, tc.country)
		v := check(p, r)
		if v.Action != tc.action || v.Reason != tc.reason || v.Status != tc.status || (eval.got != nil) != tc.evaluated || v.GeoMatch != tc.geo {
			t.Errorf("%s: %s/%s %d (evaluated %v, geo %v), want %s/%s %d (evaluated %v, geo %v)", tc.name,
				v.Action, v.Reason, v.Status, eval.got != nil, v.GeoMatch, tc.action, tc.reason, tc.status, tc.evaluated, tc.geo)
		}
		if tc.geo && v.Country != r.Geo.Label() {
			t.Errorf("%s: country %q", tc.name, v.Country)
		}
		// BodyLimit: 0 when geo decides alone, as for the IP lists.
		decides := tc.reason == ReasonGeoDeny && tc.action == ActionDeny
		if got := p.BodyLimit(r, 100); decides && got != 0 {
			t.Errorf("%s: body limit %d", tc.name, got)
		}
	}
}

// TestGeoMissingTable: a named table the engine doesn't hold follows the
// policy's failure mode; Detect never answers 503.
func TestGeoMissingTable(t *testing.T) {
	g := &GeoRules{Countries: countries("DE"), Allow: true}
	for _, tc := range []struct {
		name    string
		mode    Mode
		failure FailureMode
		g       *GeoRules
		action  Action
		reason  Reason
	}{
		{"Closed: 503", ModeBlock, FailClosed, g, ActionDeny, ReasonGeoUnavailable},
		{"Block defaults to Closed", ModeBlock, FailAuto, g, ActionDeny, ReasonGeoUnavailable},
		{"Open: skipped", ModeBlock, FailOpen, g, ActionAllow, ReasonNone},
		{"Detect policy: skipped", ModeDetect, FailClosed, g, ActionAllow, ReasonNone},
		{"geo Detect: skipped", ModeBlock, FailClosed, &GeoRules{Countries: countries("DE"), Allow: true, Detect: true}, ActionAllow, ReasonNone},
	} {
		p, _ := geoPipeline(t, tc.mode, tc.failure, tc.g, rules.Result{})
		r := geoReq("198.51.100.1", "/", "-")
		v := check(p, r)
		if v.Action != tc.action || v.Reason != tc.reason {
			t.Errorf("%s: %s/%s, want %s/%s", tc.name, v.Action, v.Reason, tc.action, tc.reason)
		}
		if tc.reason == ReasonGeoUnavailable && (v.Status != http.StatusServiceUnavailable || p.BodyLimit(r, 100) != 0) {
			t.Errorf("%s: status %d", tc.name, v.Status)
		}
	}
}

// TestGeoBeforeRateLimits: a denied country spends no tokens; in Detect it
// goes on to the limits, and a Detect limit's reason loses to geo's.
func TestGeoBeforeRateLimits(t *testing.T) {
	limit := RateLimitConfig{Name: "one", Requests: 1, Period: time.Hour, Burst: 1}
	p, _ := geoPipeline(t, ModeBlock, FailAuto, &GeoRules{Countries: countries("RU")}, rules.Result{}, limit)
	for range 3 {
		if v := check(p, geoReq("198.51.100.1", "/", "RU")); v.Reason != ReasonGeoDeny {
			t.Fatalf("got %s", v.Reason)
		}
	}
	// The client's token is still there.
	if v := check(p, geoReq("198.51.100.1", "/", "DE")); v.Reason != ReasonNone {
		t.Errorf("the denied requests spent the token: %s", v.Reason)
	}
	detectLimit := limit
	detectLimit.Detect = true
	d, _ := geoPipeline(t, ModeBlock, FailAuto, &GeoRules{Countries: countries("RU"), Detect: true}, rules.Result{}, detectLimit)
	check(d, geoReq("198.51.100.2", "/", "RU"))
	if v := check(d, geoReq("198.51.100.2", "/", "RU")); v.Reason != ReasonGeoDeny || v.Action != ActionLog {
		t.Errorf("geo and a Detect limit: %s/%s, want log/geo-deny", v.Action, v.Reason)
	}
}

// TestGeoSampling: the first geo event of a (policy, country), then at
// most one a minute, counting the requests it stands for.
func TestGeoSampling(t *testing.T) {
	var s geoSampler
	t0 := time.Now()
	if ok, n := s.sample(1, t0); !ok || n != 1 {
		t.Fatalf("first: %v %d", ok, n)
	}
	for i := range 5 {
		if ok, _ := s.sample(1, t0.Add(time.Duration(i+1)*time.Second)); ok {
			t.Fatal("sampled again within the minute")
		}
	}
	if ok, _ := s.sample(2, t0); !ok {
		t.Error("another country isn't sampled on its own")
	}
	if ok, n := s.sample(1, t0.Add(time.Minute)); !ok || n != 6 {
		t.Errorf("after a minute: %v %d, want true 6", ok, n)
	}
	p, _ := geoPipeline(t, ModeBlock, FailAuto, &GeoRules{Countries: countries("RU")}, rules.Result{})
	first, second := check(p, geoReq("198.51.100.1", "/", "RU")), check(p, geoReq("198.51.100.1", "/", "RU"))
	if !first.SampledEvent || second.SampledEvent {
		t.Errorf("events: %v %v", first.SampledEvent, second.SampledEvent)
	}
	if ReasonGeoDeny.String() != "geo-deny" || ReasonGeoUnavailable.String() != "geo-unavailable" {
		t.Error("reason names")
	}
}

// BenchmarkCheckGeo is one request through a policy with and without geo
// (design 0011 §10).
func BenchmarkCheckGeo(b *testing.B) {
	for _, g := range []*GeoRules{nil, {Countries: countries("RU", "KP")}} {
		name := "without"
		if g != nil {
			name = "with"
		}
		b.Run(name, func(b *testing.B) {
			p := New(&recordingEvaluator{}, Config{Mode: ModeBlock, Geo: g})
			r := geoReq("198.51.100.1", "/", "DE")
			b.ReportAllocs()
			for b.Loop() {
				check(p, r)
			}
		})
	}
}
