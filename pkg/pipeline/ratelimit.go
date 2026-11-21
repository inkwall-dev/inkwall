// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/ratelimit"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
)

// DefaultIPv6Prefix is the prefix IPv6 clients are counted by when a limit
// doesn't set one: a subscriber holds at least a /64, often a /56 or a /48.
const DefaultIPv6Prefix = 56

// RateLimitConfig is one of a policy's rate limits (design 0009).
type RateLimitConfig struct {
	// Name names the limit in verdicts, events and logs.
	Name string
	// Requests per Period, in bursts of at most Burst (0: Requests).
	Requests int64
	Period   time.Duration
	Burst    int64
	// Header counts by this request header's first value (lower case), and
	// a request without it by its client IP. Empty: the client IP.
	Header string
	// IPv6Prefix counts IPv6 clients by this prefix (0: DefaultIPv6Prefix).
	IPv6Prefix int
	// Paths are exact paths or prefixes ending in "*", as skip paths; empty:
	// every path. Methods, upper case; empty: every method.
	Paths   []string
	Methods []string
	// Detect logs the requests over the limit instead of denying them.
	Detect bool
}

// RateLimits are a policy's compiled limits, all in one Store.
type RateLimits struct {
	store  *ratelimit.Store
	live   *ratelimit.Live
	limits []rateLimit
}

type rateLimit struct {
	name    string
	lim     ratelimit.Limit
	header  string
	prefix  int
	paths   []limitPath
	methods []string
	detect  bool
}

// limitPath is a path pattern compared in ASCII lower case, with one
// trailing slash ignored for an exact path.
type limitPath struct {
	value  string
	prefix bool
}

// CompileRateLimits compiles a policy's limits into store. Their buckets
// are named by the policy, each limit's name and its key, so the same
// limit in a later bundle keeps them. live collects every limit of the
// bundle, for reusing the entries of limits no longer in it.
func CompileRateLimits(store *ratelimit.Store, live *ratelimit.Live, policy string, cfgs []RateLimitConfig) (*RateLimits, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}
	if store == nil {
		return nil, fmt.Errorf("rate limits without a rate limit store")
	}
	rl := &RateLimits{store: store, live: live}
	for _, c := range cfgs {
		if c.Requests < 1 || c.Period < time.Second {
			return nil, fmt.Errorf("rate limit %q: requests and period must be at least 1 and 1s", c.Name)
		}
		prefix := c.IPv6Prefix
		if prefix == 0 {
			prefix = DefaultIPv6Prefix
		}
		key := fmt.Sprintf("ip/%d", prefix)
		if c.Header != "" {
			key = fmt.Sprintf("header/%s/ip/%d", strings.ToLower(c.Header), prefix)
		}
		l := rateLimit{
			name:   c.Name,
			lim:    store.Limit(ratelimit.Identity{PolicyUID: policy, Name: c.Name, Key: key}, c.Requests, c.Period, c.Burst),
			header: strings.ToLower(c.Header),
			prefix: prefix,
			detect: c.Detect,
		}
		for _, p := range c.Paths {
			lp, err := compileLimitPath(p)
			if err != nil {
				return nil, fmt.Errorf("rate limit %q: %w", c.Name, err)
			}
			l.paths = append(l.paths, lp)
		}
		for _, m := range c.Methods {
			l.methods = append(l.methods, strings.ToUpper(m))
		}
		live.Add(l.lim)
		rl.limits = append(rl.limits, l)
	}
	return rl, nil
}

func compileLimitPath(p string) (limitPath, error) {
	prefix := strings.HasSuffix(p, "*")
	value := strings.TrimSuffix(p, "*")
	if !strings.HasPrefix(value, "/") || strings.Contains(value, "*") {
		return limitPath{}, fmt.Errorf("path pattern %q must start with / and have * only at the end", p)
	}
	if c := path.Clean(value); c != strings.TrimSuffix(value, "/") && c != value {
		return limitPath{}, fmt.Errorf("path pattern %q is not clean (use %q)", p, c)
	}
	value = strings.ToLower(value)
	if !prefix {
		value = trimSlash(value)
	}
	return limitPath{value: value, prefix: prefix}, nil
}

func trimSlash(p string) string {
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		return p[:len(p)-1]
	}
	return p
}

// matches reports whether l counts r: its method, and its path, or any
// path when r's can't be read one way. path is r's path in lower case,
// "" when ambiguous.
func (l *rateLimit) matches(r *request.Request, path string, ambiguous bool) bool {
	if len(l.methods) > 0 && !slices.Contains(l.methods, r.Method) {
		return false
	}
	if len(l.paths) == 0 || ambiguous {
		return true
	}
	for _, lp := range l.paths {
		if lp.prefix {
			if strings.HasPrefix(path, lp.value) {
				return true
			}
		} else if trimSlash(path) == lp.value {
			return true
		}
	}
	return false
}

// key is what l counts r by: its header's value, or its client IP.
func (rl *RateLimits) key(l *rateLimit, r *request.Request) (ratelimit.Key, bool) {
	if l.header != "" {
		if v := r.Headers.Get(l.header); v != "" {
			return rl.store.HeaderKey(v), true
		}
	}
	return ratelimit.IPKey(r.ClientIP, l.prefix)
}

// limited is the outcome of a request's limits.
type limited struct {
	// over is the limit that refused it, nil when none did.
	over *rateLimit
	// detect: a Detect limit over its rate, when no Block one refused it.
	detect     *rateLimit
	retryAfter time.Duration
	event      bool
	sampled    uint32
}

// check charges r against the limits at t: the Block ones together, a
// token from each or none (a refused request spends no token of another
// limit), then each Detect one on its own, which only logs. block is
// whether the policy denies (Block mode): in Detect mode every limit logs.
func (rl *RateLimits) check(r *request.Request, t time.Time, block bool) limited {
	var out limited
	if rl == nil {
		return out
	}
	p, ok := router.UnambiguousPath(r.RawURI)
	p = strings.ToLower(p)
	var charged [8]struct {
		l *rateLimit
		k ratelimit.Key
	}
	n := 0
	refund := func() {
		for _, c := range charged[:n] {
			rl.store.Refund(c.l.lim, c.k)
		}
	}
	for i := range rl.limits {
		l := &rl.limits[i]
		if l.detect || !block || !l.matches(r, p, !ok) {
			continue
		}
		k, valid := rl.key(l, r)
		if !valid {
			rl.store.SkippedNoKey()
			continue
		}
		d := rl.store.Take(l.lim, k, t, rl.live)
		if d.Allowed {
			if n < len(charged) {
				charged[n].l, charged[n].k = l, k
				n++
			}
			continue
		}
		refund()
		out.over, out.retryAfter, out.event, out.sampled = l, d.RetryAfter, d.Event, d.Sampled
		// The largest wait of the limits the request would also exceed.
		for j := i + 1; j < len(rl.limits); j++ {
			m := &rl.limits[j]
			if m.detect || !m.matches(r, p, !ok) {
				continue
			}
			if mk, valid := rl.key(m, r); valid {
				if wait := rl.store.Wait(m.lim, mk, t); wait > out.retryAfter {
					out.retryAfter = wait
				}
			}
		}
		break
	}
	if out.over != nil {
		out.event = out.event && rl.store.AllowEvent(out.over.lim, t)
		return out
	}
	for i := range rl.limits {
		l := &rl.limits[i]
		if block && !l.detect || !l.matches(r, p, !ok) {
			continue
		}
		k, valid := rl.key(l, r)
		if !valid {
			rl.store.SkippedNoKey()
			continue
		}
		if d := rl.store.Take(l.lim, k, t, rl.live); !d.Allowed && out.detect == nil {
			out.detect, out.retryAfter, out.event, out.sampled = l, d.RetryAfter, d.Event, d.Sampled
		}
	}
	if out.detect != nil {
		out.event = out.event && rl.store.AllowEvent(out.detect.lim, t)
	}
	return out
}

// decisions are the rate limit outcomes charged for one request, by
// pipeline: up to 4, the policies a request can have (pkg/policy).
type decisions struct {
	n int
	d [4]struct {
		p *Pipeline
		o limited
	}
}

// limitsFor charges r against p's limits at now, once: BodyLimit and Check
// both ask, and the second gets the first's outcome. A pipeline of another
// bundle (a swap between the two) finds none of its own and decides again.
func (p *Pipeline) limitsFor(r *request.Request, now time.Time) limited {
	if p.limits == nil {
		return limited{}
	}
	ds, _ := r.RateLimits.(*decisions)
	if ds != nil {
		for _, d := range ds.d[:ds.n] {
			if d.p == p {
				return d.o
			}
		}
	}
	o := p.limits.check(r, now, p.mode == ModeBlock)
	if ds == nil {
		ds = &decisions{}
		r.RateLimits = ds
	}
	if ds.n < len(ds.d) {
		ds.d[ds.n].p, ds.d[ds.n].o = p, o
		ds.n++
	}
	return o
}

// RateLimited reports whether r was charged and found over one of p's
// Block limits (in BodyLimit): pkg/policy stops charging other policies
// then, as Check stops at the first deny.
func (p *Pipeline) RateLimited(r *request.Request) bool {
	ds, _ := r.RateLimits.(*decisions)
	if ds == nil {
		return false
	}
	for _, d := range ds.d[:ds.n] {
		if d.p == p {
			return d.o.over != nil
		}
	}
	return false
}

// rateLimited is the verdict of a request over a Block limit: 429 with
// Retry-After.
func (p *Pipeline) rateLimited(o limited) Verdict {
	v := p.enforce(Verdict{Reason: ReasonRateLimit, RateLimit: o.over.name, RetryAfter: o.retryAfter}, http.StatusTooManyRequests)
	v.RateLimitEvent, v.SampledCount = o.event, o.sampled
	return v
}
