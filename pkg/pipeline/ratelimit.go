// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/inkwall-dev/inkwall/pkg/ratelimit"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/router"
)

// MaxRateLimits is the most limits a policy has (spec.rateLimits).
const MaxRateLimits = 8

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
	// The CRD allows 8, with unique names; the engine doesn't trust the
	// bundle for it: a 9th limit couldn't be refunded, and two of one name
	// would share their buckets.
	if len(cfgs) > MaxRateLimits {
		return nil, fmt.Errorf("%d rate limits, at most %d", len(cfgs), MaxRateLimits)
	}
	rl := &RateLimits{store: store, live: live}
	names := map[string]bool{}
	for _, c := range cfgs {
		if names[c.Name] {
			return nil, fmt.Errorf("rate limit %q twice", c.Name)
		}
		names[c.Name] = true
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

// limitPath is r's path as limits compare it: decoded and in lower case.
// ambiguous: the path can be read more than one way by the application,
// through an encoding that changes routing (an encoded /, . or \, a ;, a
// //, a dot segment, invalid UTF-8, fullwidth forms some applications fold
// to ASCII); it then counts against every limit with paths. Other
// percent-encoding (an é, a space) is decoded and compared as usual.
func limitPathOf(rawURI string) (p string, ambiguous bool) {
	if p, ok := router.UnambiguousPath(rawURI); ok {
		return strings.ToLower(p), false
	}
	raw, _, _ := strings.Cut(rawURI, "?")
	lower := strings.ToLower(raw)
	if raw == "" || raw[0] != '/' || strings.ContainsAny(raw, ";\\") ||
		strings.Contains(lower, "%2f") || strings.Contains(lower, "%2e") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%00") {
		return "", true
	}
	dec, err := url.PathUnescape(raw)
	if err != nil || !utf8.ValidString(dec) || strings.Contains(dec, "//") {
		return "", true
	}
	for _, c := range dec {
		if c < 0x20 || c == 0x7f || c >= 0xFF01 && c <= 0xFF5E {
			return "", true
		}
	}
	clean := path.Clean(dec)
	if strings.HasSuffix(dec, "/") && clean != "/" {
		clean += "/"
	}
	if clean != dec {
		return "", true // a dot segment
	}
	return strings.ToLower(dec), false
}

// matches reports whether l counts r, whose method is method (upper case):
// its method, and its path, or any path when r's is ambiguous (path is
// limitPathOf's).
func (l *rateLimit) matches(method, path string, ambiguous bool) bool {
	if len(l.methods) > 0 && !slices.Contains(l.methods, method) {
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
	// key is the key of over or detect, for giving back the count of an
	// event the caps dropped.
	key ratelimit.Key
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
	p, ambiguous := limitPathOf(r.RawURI)
	method := strings.ToUpper(r.Method)
	var charged [MaxRateLimits]struct {
		l *rateLimit
		k ratelimit.Key
		d ratelimit.Decision
	}
	n := 0
	noKey := false
	key := func(l *rateLimit) (ratelimit.Key, bool) {
		k, valid := rl.key(l, r)
		noKey = noKey || !valid
		return k, valid
	}
	for i := range rl.limits {
		l := &rl.limits[i]
		if l.detect || !block || !l.matches(method, p, ambiguous) {
			continue
		}
		k, valid := key(l)
		if !valid {
			continue
		}
		d := rl.store.Take(l.lim, k, t, rl.live)
		if d.Allowed {
			charged[n].l, charged[n].k, charged[n].d = l, k, d
			n++
			continue
		}
		for _, c := range charged[:n] {
			rl.store.Refund(c.l.lim, c.k, c.d)
		}
		out.over, out.key, out.retryAfter, out.event, out.sampled = l, k, d.RetryAfter, d.Event, d.Sampled
		// The largest wait of the limits the request would also exceed.
		for j := i + 1; j < len(rl.limits); j++ {
			m := &rl.limits[j]
			if m.detect || !m.matches(method, p, ambiguous) {
				continue
			}
			if mk, valid := rl.key(m, r); valid {
				out.retryAfter = max(out.retryAfter, rl.store.Wait(m.lim, mk, t))
			}
		}
		break
	}
	if out.over == nil {
		for i := range rl.limits {
			l := &rl.limits[i]
			if block && !l.detect || !l.matches(method, p, ambiguous) {
				continue
			}
			k, valid := key(l)
			if !valid {
				continue
			}
			if d := rl.store.Observe(l.lim, k, t, rl.live); !d.Allowed && out.detect == nil {
				out.detect, out.key, out.retryAfter, out.event, out.sampled = l, k, d.RetryAfter, d.Event, d.Sampled
			}
		}
	}
	if noKey {
		rl.store.SkippedNoKey() // once per request, however many limits
	}
	limit := out.over
	if limit == nil {
		limit = out.detect
	}
	if limit != nil {
		rl.store.Exceeded(out.over == nil)
		if out.event && !rl.store.AllowEvent(limit.lim, t) {
			// Dropped by the caps: its count goes to the key's next event.
			rl.store.Unsample(limit.lim, out.key, out.sampled)
			out.event, out.sampled = false, 0
		}
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
// bundle (a swap between the two) finds none of its own and decides again,
// charging r twice; and if BodyLimit had found r over (body limit 0) while
// the new bundle allows it, r is inspected without its body, as for a
// skip.bodyPaths change in between. Both are rare, and err toward denying
// or toward the new bundle's settings.
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
	v.SampledEvent, v.SampledCount = o.event, o.sampled
	return v
}
