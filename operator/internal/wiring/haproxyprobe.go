// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
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
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/pkg/haproxyprobe"
)

// HAProxyProbe is what the prober proves for one wired Ingress: that each
// pod answers the probe on each of its targets.
type HAProxyProbe struct {
	Ingress types.NamespacedName
	// Fingerprint changes when the wiring does (the snippet): the route
	// is probed again.
	Fingerprint string
	Targets     []ProbeTarget
	Pods        []ProbePod
}

// ProbeTarget is a request that reaches one of the Ingress's backends: a
// host (any, for a rule without one), and a Prefix path, under which the
// probe takes its reserved path, or an Exact one, probed as itself with a
// query; over TLS when the Ingress has it for the host, as the controller
// then redirects plain HTTP.
type ProbeTarget struct {
	Host   string
	Path   string
	Prefix bool
	TLS    bool
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
)

// HAProxyProber probes the wired HAProxy routes (0002 §6.4): for each pod
// and route, a GET through the pod's HAProxy to the route, with a MAC
// under the bundle's probe key, which only the engine behind the route's
// filter answers (status 299 and its own MAC). It runs on the leader, and
// triggers a reconcile when a result changes.
type HAProxyProber struct {
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
	jobs    []HAProxyProbe
	results map[string]probeResult
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

func (p *HAProxyProber) init() {
	p.once.Do(func() {
		p.results = map[string]probeResult{}
		p.events = make(chan event.GenericEvent, 1)
	})
}

// Events triggers the wiring controller when a result changes.
func (p *HAProxyProber) Events() <-chan event.GenericEvent {
	p.init()
	return p.events
}

// Set replaces the routes to probe.
func (p *HAProxyProber) Set(jobs []HAProxyProbe) {
	p.init()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.jobs = jobs
}

func (p *HAProxyProber) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// resultKey identifies a result: the route, its wiring and target, the pod
// and the probe key; any change makes it pending again.
func resultKey(job HAProxyProbe, pod ProbePod, t ProbeTarget, key []byte) string {
	sum := sha256.Sum256([]byte(job.Fingerprint + "\x00" + string(key)))
	return strings.Join([]string{job.Ingress.String(), string(pod.UID), pod.IP, t.Host, t.Path, strconv.FormatBool(t.TLS), hex.EncodeToString(sum[:8])}, "|")
}

// Unverified is why a route isn't proven on every pod, or "".
func (p *HAProxyProber) Unverified(job HAProxyProbe) string {
	p.init()
	p.mu.Lock()
	defer p.mu.Unlock()
	name := "Ingress " + job.Ingress.Name
	switch {
	case len(p.key) == 0:
		return name + " is wired; the filter is unverified until the operator can probe it (no bundle with a probe key yet)"
	case len(job.Pods) == 0:
		return name + " is wired; the filter is unverified: no HAProxy pod with the engine runs"
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
		return fmt.Sprintf("Ingress %s is wired, but the probe shows that HAProxy doesn't run the filter for it, so its traffic isn't inspected there: %s",
			job.Ingress.Name, strings.Join(failed, "; "))
	case len(pending) > 0:
		// Not the pods' names: each pod of a rollout would rewrite the
		// status (#373).
		return fmt.Sprintf("Ingress %s is wired; the filter is unverified until the operator's probe has reached it on every HAProxy pod with the engine", job.Ingress.Name)
	}
	return ""
}

// Start probes until ctx ends.
func (p *HAProxyProber) Start(ctx context.Context) error {
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
func (*HAProxyProber) NeedLeaderElection() bool { return true }

// Run probes what is due once.
func (p *HAProxyProber) Run(ctx context.Context) {
	p.init()
	key, err := p.probeKey(ctx)
	if err != nil {
		log.FromContext(ctx).Error(err, "HAProxy probe: reading the bundle")
		return
	}
	type task struct {
		key  string
		job  HAProxyProbe
		pod  ProbePod
		t    ProbeTarget
		prev probeResult
		had  bool
	}
	p.mu.Lock()
	changed := string(p.key) != string(key)
	p.key = key
	var due []task
	now := p.now()
	live := map[string]bool{}
	if len(key) > 0 {
		for _, job := range p.jobs {
			for _, pod := range job.Pods {
				for _, t := range job.Targets {
					k := resultKey(job, pod, t, key)
					live[k] = true
					r, had := p.results[k]
					wait := haproxyRetry
					if r.ok {
						wait = haproxyReprobe
					}
					if !had || now.Sub(r.at) >= wait {
						due = append(due, task{key: k, job: job, pod: pod, t: t, prev: r, had: had})
					}
				}
			}
		}
	}
	for k := range p.results {
		if !live[k] {
			delete(p.results, k)
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
			ok, detail := p.probe(ctx, key, tk.pod, tk.t)
			p.mu.Lock()
			p.results[tk.key] = probeResult{ok: ok, detail: detail, at: p.now()}
			p.mu.Unlock()
			if !tk.had || tk.prev.ok != ok || tk.prev.detail != detail {
				mu.Lock()
				changed = true
				mu.Unlock()
				if !ok {
					log.FromContext(ctx).Info("HAProxy probe failed", "ingress", tk.job.Ingress, "pod", tk.pod.Name, "host", tk.t.Host, "detail", detail)
				}
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

// probeKey is the key of the bundle in force: the one engines answer with.
func (p *HAProxyProber) probeKey(ctx context.Context) ([]byte, error) {
	if p.Key != nil {
		return p.Key(ctx)
	}
	b, _, err := p.current.Load(ctx, p.Reader, p.Namespace)
	return b.GetProbeKey(), err
}

// probe sends one probe, and reports whether the engine answered it.
func (p *HAProxyProber) probe(ctx context.Context, key []byte, pod ProbePod, t ProbeTarget) (bool, string) {
	if pod.IP == "" {
		return false, "the pod has no IP yet"
	}
	nonce, err := haproxyprobe.NewNonce()
	if err != nil {
		return false, err.Error()
	}
	uri := t.Path + "?inkwall-probe=" + nonce
	if t.Prefix {
		uri = haproxyprobe.PrefixPath(t.Path, nonce)
	}
	scheme := "http"
	if t.TLS {
		scheme = "https"
	}
	ctx, cancel := context.WithTimeout(ctx, haproxyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+t.Host+uri, nil)
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set(haproxyprobe.Header, haproxyprobe.Request(key, nonce, t.Host, uri))
	req.Header.Set("User-Agent", "inkwall-operator-haproxy-probe")
	do := p.Do
	if do == nil {
		do = sendProbe
	}
	resp, err := do(ctx, pod, t, req)
	if err != nil {
		return false, "no answer: " + err.Error()
	}
	_ = resp.Body.Close()
	answer := resp.Header.Get(haproxyprobe.Header)
	switch {
	case resp.StatusCode == haproxyprobe.Status && haproxyprobe.Verify(key, nonce, t.Host, uri, answer):
		return true, ""
	case resp.StatusCode == haproxyprobe.Status:
		return false, "status 299 without the engine's answer"
	}
	return false, fmt.Sprintf("HTTP %d, not the engine's answer (the request reached past the filter)", resp.StatusCode)
}

// sendProbe sends a probe to a pod's HAProxy directly, over TLS for a TLS
// target. The certificate isn't checked: the answer's MAC proves who
// answered.
func sendProbe(ctx context.Context, pod ProbePod, t ProbeTarget, req *http.Request) (*http.Response, error) {
	port := pod.HTTPPort
	if t.TLS {
		port = pod.HTTPSPort
	}
	addr := net.JoinHostPort(pod.IP, strconv.Itoa(int(port)))
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		// #nosec G402 -- the probe's answer is authenticated by its MAC, not by the certificate
		TLSClientConfig:   &tls.Config{ServerName: t.Host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c.Do(req.WithContext(ctx))
}
