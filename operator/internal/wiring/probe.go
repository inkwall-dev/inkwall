// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"maps"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/enginereport"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/pkg/haproxyprobe"
)

// ProbeJob is what the prober proves for one wired route: that each pod
// answers the probe on each of its targets (#282, #372).
type ProbeJob struct {
	// Route is the route, for the messages and the results' keys.
	Route ProbeRoute
	// Proxy names the proxy in the messages: "HAProxy", "Istio".
	Proxy string
	// Fingerprint changes when the wiring does (the snippet): the route
	// is probed again.
	Fingerprint string
	Targets     []ProbeTarget
	Pods        []ProbePod
	// Receipt: the proxy discards the engine's answer (Envoy's ext_proc
	// in observability mode, a Detect-mode Istio route), so the route is
	// proven by the receipt of the probe that the pod's engine reports
	// (#475) instead.
	Receipt bool
}

// ProbeRoute names a probed route: "Ingress", "HTTPRoute" or
// "VirtualService", and its namespace and name.
type ProbeRoute struct {
	Kind string
	Key  types.NamespacedName
}

func (r ProbeRoute) String() string { return r.Kind + " " + r.Key.Name }

// ProbeTarget is a request that reaches one of the route's backends: a
// host (any, for a rule without one), and a Prefix path, under which the
// probe takes its reserved path, or an Exact one, probed as itself with a
// query; over TLS when the route has it for the host (HAProxy then
// redirects plain HTTP, an Istio listener serves only TLS). Method, Query
// and Headers are what the route's match asks for besides the path (an
// Istio route); Port, when set, is the listener's on the pod, instead of
// the pod's HTTP or HTTPS port.
type ProbeTarget struct {
	Host    string
	Path    string
	Prefix  bool
	TLS     bool
	Port    int32
	Method  string
	Query   string
	Headers map[string]string
}

// ProbePod is a controller pod, probed directly.
type ProbePod struct {
	Name      string
	UID       types.UID
	IP        string
	HTTPPort  int32
	HTTPSPort int32
}

// anyHost is the Host of a probe to a rule without one.
const anyHost = "inkwall-probe.invalid"

// probeTargets are an Ingress's targets: the first path of each backend
// Service it routes to (each is a backend of its own in HAProxy).
func probeTargets(ing *networkingv1.Ingress) []ProbeTarget {
	tlsHosts := map[string]bool{}
	for _, t := range ing.Spec.TLS {
		for _, h := range t.Hosts {
			tlsHosts[h] = true
		}
	}
	seen := map[string]bool{}
	var out []ProbeTarget
	add := func(host, path string, prefix bool, b *networkingv1.IngressBackend) {
		key := "default"
		if b != nil && b.Service != nil {
			key = b.Service.Name + ":" + b.Service.Port.Name + strconv.Itoa(int(b.Service.Port.Number))
		}
		if seen[key] {
			return
		}
		seen[key] = true
		t := ProbeTarget{Host: host, Path: path, Prefix: prefix, TLS: tlsHosts[host]}
		if host == "" {
			t.Host = anyHost
		}
		out = append(out, t)
	}
	for _, r := range ing.Spec.Rules {
		if r.HTTP == nil {
			continue
		}
		for _, p := range r.HTTP.Paths {
			exact := p.PathType != nil && *p.PathType == networkingv1.PathTypeExact
			add(r.Host, p.Path, !exact, &p.Backend)
		}
	}
	if ing.Spec.DefaultBackend != nil {
		add("", "/", true, ing.Spec.DefaultBackend)
	}
	return out
}

// probePod is a pod's address and the controller's ports: those its
// container names http and https, else the chart's defaults.
func probePod(pod *corev1.Pod) ProbePod {
	p := ProbePod{Name: pod.Namespace + "/" + pod.Name, UID: pod.UID, IP: pod.Status.PodIP, HTTPPort: 8080, HTTPSPort: 8443}
	for _, c := range pod.Spec.Containers {
		if c.Name != injection.HAProxyContainer && len(pod.Spec.Containers) > 1 {
			continue
		}
		for _, port := range c.Ports {
			switch port.Name {
			case "http":
				p.HTTPPort = port.ContainerPort
			case "https":
				p.HTTPSPort = port.ContainerPort
			}
		}
	}
	return p
}

// Probe cadence: a proven route is probed again every haproxyReprobe, one
// that isn't, every haproxyRetry; at most haproxyParallel probes at once.
const (
	haproxyReprobe  = 5 * time.Minute
	haproxyRetry    = 20 * time.Second
	haproxyParallel = 4
	haproxyTimeout  = 3 * time.Second
	// receiptWait is how long the operator waits for an engine to report
	// the receipt of a probe (its heartbeat, every 5 s, then its replica's
	// report, every 2 s) before the probe fails; the engine keeps
	// receipts for haproxyprobe.ReceiptAge.
	receiptWait = 30 * time.Second
	// maxReceiptsPending bounds the probes waiting for a receipt per pod,
	// under what an engine keeps (haproxyprobe.MaxReceipts): a pod's
	// receipts aren't pushed out before they are reported.
	maxReceiptsPending = haproxyprobe.MaxReceipts / 2
	// engineReportStale: a replica's report older than this is ignored
	// (as the status aggregator does).
	engineReportStale = 30 * time.Second
)

// Prober probes the wired HAProxy routes (0002 §6.4): for each pod
// and route, a GET through the pod's HAProxy to the route, with a MAC
// under the bundle's probe key, which only the engine behind the route's
// filter answers (status 299 and its own MAC). It runs on the leader, and
// triggers a reconcile when a result changes.
type Prober struct {
	// Reader reads the bundle Secret, in Namespace, for the probe key.
	Reader    client.Reader
	Namespace string
	// Do sends a probe; nil: over the network.
	Do func(ctx context.Context, pod ProbePod, t ProbeTarget, req *http.Request) (*http.Response, error)
	// Now is the clock; nil: time.Now.
	Now func() time.Time
	// Key returns the probe key engines have; nil: the bundle's.
	Key func(ctx context.Context) ([]byte, error)

	mu      sync.Mutex
	jobs    map[string][]ProbeJob
	results map[string]probeResult
	// pending are the probes waiting for their receipt, by result key.
	pending map[string]pendingReceipt
	events  chan event.GenericEvent
	once    sync.Once
	current bundle.Current
	key     []byte
}

type probeResult struct {
	ok     bool
	detail string
	at     time.Time
}

// pendingReceipt is a probe sent to a Receipt job's pod: the receipt its
// engine must report, and when it was sent.
type pendingReceipt struct {
	receipt string
	pod     string
	sent    time.Time
	job     ProbeJob
	t       ProbeTarget
	prev    probeResult
	had     bool
}

func (p *Prober) init() {
	p.once.Do(func() {
		p.results = map[string]probeResult{}
		p.pending = map[string]pendingReceipt{}
		p.jobs = map[string][]ProbeJob{}
		p.events = make(chan event.GenericEvent, 1)
	})
}

// Events triggers the wiring controller when a result changes.
func (p *Prober) Events() <-chan event.GenericEvent {
	p.init()
	return p.events
}

// Set replaces the routes to probe.
// Set replaces the routes an integration ("haproxy", "istio", ...) has
// to probe; the other integrations' stay.
func (p *Prober) Set(integration string, jobs []ProbeJob) {
	p.init()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.jobs[integration] = jobs
}

func (p *Prober) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// resultKey identifies a result: the route, its wiring and target, the pod
// and the probe key; any change makes it pending again.
func resultKey(job ProbeJob, pod ProbePod, t ProbeTarget, key []byte) string {
	sum := sha256.Sum256([]byte(job.Fingerprint + "\x00" + string(key)))
	return strings.Join([]string{job.Route.Kind, job.Route.Key.String(), strconv.FormatBool(job.Receipt), string(pod.UID), pod.IP, t.Host, t.Path, strconv.FormatBool(t.TLS),
		strconv.Itoa(int(t.Port)), t.Method, t.Query, headersKey(t.Headers), hex.EncodeToString(sum[:8])}, "|")
}

// headersKey is a target's headers, in a stable order.
func headersKey(h map[string]string) string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(h)) {
		out = append(out, k+"="+h[k])
	}
	return strings.Join(out, ",")
}

// Unverified is why a route isn't proven on every pod, or "".
func (p *Prober) Unverified(job ProbeJob) string {
	p.init()
	p.mu.Lock()
	defer p.mu.Unlock()
	name := job.Route.String()
	switch {
	case len(p.key) == 0:
		return name + " is wired; the filter is unverified until the operator can probe it (no bundle with a probe key yet)"
	case len(job.Pods) == 0:
		return name + " is wired; the filter is unverified: no " + job.Proxy + " pod with the engine runs"
	case len(job.Targets) == 0:
		return name + " is wired; the filter is unverified: it has no path to probe"
	}
	var pending, failed []string
	for _, pod := range job.Pods {
		for _, t := range job.Targets {
			r, ok := p.results[resultKey(job, pod, t, p.key)]
			switch {
			case !ok:
				pending = append(pending, pod.Name)
			case !r.ok:
				failed = append(failed, fmt.Sprintf("pod %s, host %s: %s", pod.Name, t.Host, r.detail))
			}
		}
	}
	switch {
	case len(failed) > 0:
		return fmt.Sprintf("%s is wired, but the probe shows that %s doesn't run the filter for it, so its traffic isn't inspected there: %s",
			name, job.Proxy, strings.Join(failed, "; "))
	case len(pending) > 0:
		// Not the pods' names: each pod of a rollout would rewrite the
		// status (#373).
		return fmt.Sprintf("%s is wired; the filter is unverified until the operator's probe has reached it on every %s pod with the engine", name, job.Proxy)
	}
	return ""
}

// Start probes until ctx ends.
func (p *Prober) Start(ctx context.Context) error {
	p.init()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		p.Run(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// NeedLeaderElection implements manager.LeaderElectionRunnable.
func (*Prober) NeedLeaderElection() bool { return true }

// Run probes what is due once.
func (p *Prober) Run(ctx context.Context) {
	p.init()
	key, err := p.probeKey(ctx)
	if err != nil {
		log.FromContext(ctx).Error(err, "probe: reading the bundle")
		return
	}
	type task struct {
		key  string
		job  ProbeJob
		pod  ProbePod
		t    ProbeTarget
		prev probeResult
		had  bool
	}
	changed := p.collectReceipts(ctx)
	p.mu.Lock()
	changed = changed || string(p.key) != string(key)
	p.key = key
	var due []task
	now := p.now()
	live := map[string]bool{}
	// Probes waiting for a receipt, per pod.
	waiting := map[string]int{}
	for _, pr := range p.pending {
		waiting[pr.pod]++
	}
	if len(key) > 0 {
		for _, job := range slices.Concat(slices.Collect(maps.Values(p.jobs))...) {
			for _, pod := range job.Pods {
				for _, t := range job.Targets {
					k := resultKey(job, pod, t, key)
					live[k] = true
					if _, ok := p.pending[k]; ok {
						continue
					}
					r, had := p.results[k]
					wait := haproxyRetry
					if r.ok {
						wait = haproxyReprobe
					}
					if had && now.Sub(r.at) < wait {
						continue
					}
					if job.Receipt {
						if waiting[pod.Name] >= maxReceiptsPending {
							continue
						}
						waiting[pod.Name]++
					}
					due = append(due, task{key: k, job: job, pod: pod, t: t, prev: r, had: had})
				}
			}
		}
	}
	// A result outlives its job for the reprobe interval: a route that
	// leaves the jobs for a moment (its pods SidecarMissing in a rollout)
	// and comes back on the same pods is as proven as if it had stayed.
	for k, r := range p.results {
		if !live[k] && now.Sub(r.at) >= haproxyReprobe {
			delete(p.results, k)
		}
	}
	for k := range p.pending {
		if !live[k] {
			delete(p.pending, k)
		}
	}
	p.mu.Unlock()

	sem := make(chan struct{}, haproxyParallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, tk := range due {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			ok, detail, receipt := p.probe(ctx, key, tk.pod, tk.t, tk.job.Receipt)
			p.mu.Lock()
			if receipt != "" {
				// Proven once the pod's engine reports it (collectReceipts).
				p.pending[tk.key] = pendingReceipt{receipt: receipt, pod: tk.pod.Name, sent: p.now(), job: tk.job, t: tk.t, prev: tk.prev, had: tk.had}
				p.mu.Unlock()
				return
			}
			p.results[tk.key] = probeResult{ok: ok, detail: detail, at: p.now()}
			p.mu.Unlock()
			if p.logChange(ctx, tk.job, tk.pod.Name, tk.t, tk.prev, tk.had, ok, detail) {
				mu.Lock()
				changed = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if changed {
		select {
		case p.events <- event.GenericEvent{Object: &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "haproxy-probe"}}}:
		default:
		}
	}
}

// logChange reports whether a result differs from the previous one, and
// logs a new failure.
func (p *Prober) logChange(ctx context.Context, job ProbeJob, pod string, t ProbeTarget, prev probeResult, had, ok bool, detail string) bool {
	if had && prev.ok == ok && prev.detail == detail {
		return false
	}
	if !ok {
		log.FromContext(ctx).Info("probe failed", "proxy", job.Proxy, "route", job.Route.String(), "namespace", job.Route.Key.Namespace, "pod", pod, "host", t.Host, "detail", detail)
	}
	return true
}

// collectReceipts settles the probes waiting for a receipt (#475): proven
// once the probed pod's engine reports the receipt of that very probe,
// failed after receiptWait without it. It reports whether a result
// changed.
func (p *Prober) collectReceipts(ctx context.Context) bool {
	p.mu.Lock()
	n := len(p.pending)
	p.mu.Unlock()
	if n == 0 {
		return false
	}
	byPod, err := p.reportedReceipts(ctx)
	if err != nil {
		// Not proven, and not failed: they wait for the next round.
		log.FromContext(ctx).Error(err, "probe: reading the engine reports")
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	changed := false
	for k, pr := range p.pending {
		ok := byPod[pr.pod][pr.receipt]
		if !ok && now.Sub(pr.sent) < receiptWait {
			continue
		}
		detail := ""
		if !ok {
			detail = fmt.Sprintf("its engine reported no receipt of the probe within %s (the request didn't reach the engine)", receiptWait)
		}
		delete(p.pending, k)
		p.results[k] = probeResult{ok: ok, detail: detail, at: now}
		if p.logChange(ctx, pr.job, pr.pod, pr.t, pr.prev, pr.had, ok, detail) {
			changed = true
		}
	}
	return changed
}

// reportedReceipts are the probe receipts the engines report, by their
// pod ("namespace/name"), from the replicas' engine reports: the pod
// comes from the engine's authenticated stream, not from the receipt.
func (p *Prober) reportedReceipts(ctx context.Context) (map[string]map[string]bool, error) {
	if p.Reader == nil {
		return nil, nil
	}
	engines, _, err := enginereport.Read(ctx, p.Reader, p.Namespace, engineReportStale, p.now())
	if err != nil {
		return nil, err
	}
	byPod := map[string]map[string]bool{}
	for _, e := range engines {
		if len(e.ProbeReceipts) == 0 {
			continue
		}
		pod := e.PodNamespace + "/" + e.PodName
		if byPod[pod] == nil {
			byPod[pod] = map[string]bool{}
		}
		for _, r := range e.ProbeReceipts {
			byPod[pod][r] = true
		}
	}
	return byPod, nil
}

// probeKey is the key of the bundle in force: the one engines answer with.
func (p *Prober) probeKey(ctx context.Context) ([]byte, error) {
	if p.Key != nil {
		return p.Key(ctx)
	}
	b, _, err := p.current.Load(ctx, p.Reader, p.Namespace)
	return b.GetProbeKey(), err
}

// probe sends one probe, and reports whether the engine answered it; for a
// receipt probe that went out and wasn't answered, the receipt the pod's
// engine is to report instead.
func (p *Prober) probe(ctx context.Context, key []byte, pod ProbePod, t ProbeTarget, receipt bool) (ok bool, detail, wantReceipt string) {
	if pod.IP == "" {
		return false, "the pod has no IP yet", ""
	}
	nonce, err := haproxyprobe.NewNonce()
	if err != nil {
		return false, err.Error(), ""
	}
	uri := t.Path + "?inkwall-probe=" + nonce
	if t.Query != "" {
		uri = t.Path + "?" + t.Query + "&inkwall-probe=" + nonce
	}
	if t.Prefix {
		uri = haproxyprobe.PrefixPath(t.Path, nonce)
		if t.Query != "" {
			uri += "?" + t.Query
		}
	}
	method := cmp.Or(t.Method, http.MethodGet)
	scheme := "http"
	if t.TLS {
		scheme = "https"
	}
	ctx, cancel := context.WithTimeout(ctx, haproxyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, scheme+"://"+t.Host+uri, nil)
	if err != nil {
		return false, err.Error(), ""
	}
	for k, v := range t.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set(haproxyprobe.Header, haproxyprobe.Request(key, nonce, t.Host, uri))
	req.Header.Set("User-Agent", "inkwall-operator-probe")
	do := p.Do
	if do == nil {
		do = sendProbe
	}
	resp, err := do(ctx, pod, t, req)
	if err != nil {
		return false, "no answer: " + err.Error(), ""
	}
	_ = resp.Body.Close()
	answer := resp.Header.Get(haproxyprobe.Header)
	switch {
	case haproxyprobe.Verify(key, nonce, t.Host, uri, answer):
		// The MAC proves the engine answered: HAProxy's rules return it
		// with 299, Envoy's local reply with 200 (#372).
		return true, "", ""
	case receipt:
		// Envoy forwarded the probe (the app answered): the engine's
		// receipt proves it saw it on the way (#475).
		return false, "", haproxyprobe.ExpectedReceipt(key, nonce, t.Host, uri)
	case resp.StatusCode == haproxyprobe.Status:
		return false, "status 299 without the engine's answer", ""
	}
	return false, fmt.Sprintf("HTTP %d, not the engine's answer (the request reached past the filter)", resp.StatusCode), ""
}

// sendProbe sends a probe to a pod's HAProxy directly, over TLS for a TLS
// target. The certificate isn't checked: the answer's MAC proves who
// answered.
func sendProbe(ctx context.Context, pod ProbePod, t ProbeTarget, req *http.Request) (*http.Response, error) {
	port := pod.HTTPPort
	if t.TLS {
		port = pod.HTTPSPort
	}
	if t.Port != 0 {
		port = t.Port
	}
	addr := net.JoinHostPort(pod.IP, strconv.Itoa(int(port)))
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		// The gateway's certificate isn't checked (CodeQL
		// go/disabled-certificate-check): gateways serve certificates for
		// their hosts, not for a pod address, often from a CA the operator
		// doesn't know. Nothing here relies on it:
		//   - the answer is authenticated by its MAC (an HMAC under the
		//     bundle's probe key), not by the certificate: a party in the
		//     middle can't make a route look proven;
		//   - the request carries nothing secret: the host, a path the
		//     route's rule matches (or the reserved probe path), and the
		//     nonce and MAC of X-Inkwall-Probe, which proves only this one
		//     request; a route's header and query match values, which may
		//     be secrets, are never sent over TLS (sendsValues, overTLS, #507);
		//   - the probe path is answered by the engine, never by the app.
		// #nosec G402 -- see above
		TLSClientConfig:   &tls.Config{ServerName: t.Host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c.Do(req.WithContext(ctx))
}
