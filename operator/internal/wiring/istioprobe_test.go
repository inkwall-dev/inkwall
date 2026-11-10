// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/inkwall-dev/inkwall/operator/enginereport"
	"github.com/inkwall-dev/inkwall/pkg/haproxyprobe"
)

// An Istio HTTPRoute's probe (#372): per Gateway, a target per protected
// rule and listener the route attaches to, from the rule's first match the
// probe can make (exact or prefix path, exact headers and query
// parameters, the method), on the listener's port, with a host the route
// serves (a wildcard's made concrete), over TLS for an HTTPS listener; on
// each running pod of the Gateway. A rule whose matches the probe can't
// make (regular expressions) makes the route not probeable.
func TestIstioRouteProbe(t *testing.T) {
	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "gw"}, Spec: gatewayv1.GatewaySpec{
		Listeners: []gatewayv1.Listener{
			{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType, Hostname: ptr.To(gatewayv1.Hostname("*.example.com"))},
			{Name: "tcp", Port: 9000, Protocol: gatewayv1.TCPProtocolType},
		},
	}}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "gw-1", UID: "u1", Labels: map[string]string{istioGatewayLabel: "gw"}},
		Status: corev1.PodStatus{PodIP: "10.0.0.7", Phase: corev1.PodRunning}}
	st := &envoyState{gateways: map[types.NamespacedName]*gatewayv1.Gateway{{Namespace: "edge", Name: "gw"}: gw}, pods: []corev1.Pod{pod}}
	exact, prefix, regex := gatewayv1.PathMatchExact, gatewayv1.PathMatchPathPrefix, gatewayv1.PathMatchRegularExpression
	headerExact, headerRegex := gatewayv1.HeaderMatchExact, gatewayv1.HeaderMatchRegularExpression
	route := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web"}, Spec: gatewayv1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gw", Namespace: ptr.To(gatewayv1.Namespace("edge"))}}},
		Hostnames:       []gatewayv1.Hostname{"*.example.com"},
		Rules: []gatewayv1.HTTPRouteRule{
			{Name: ptr.To(gatewayv1.SectionName("api")), Matches: []gatewayv1.HTTPRouteMatch{
				{Path: &gatewayv1.HTTPPathMatch{Type: &regex, Value: ptr.To("/v[0-9]+")}},
				{Path: &gatewayv1.HTTPPathMatch{Type: &prefix, Value: ptr.To("/api")}, Method: ptr.To(gatewayv1.HTTPMethodPost)},
			}},
			{Name: ptr.To(gatewayv1.SectionName("health")), Matches: []gatewayv1.HTTPRouteMatch{
				{Path: &gatewayv1.HTTPPathMatch{Type: &exact, Value: ptr.To("/healthz")}}}},
		},
	}}
	jobs, why := st.istioRouteProbes(&istioRoute{route: route, gateways: []types.NamespacedName{{Namespace: "edge", Name: "gw"}}, sections: []string{""}})
	if why != "" || len(jobs) != 1 {
		t.Fatalf("jobs %+v, why %q", jobs, why)
	}
	j := jobs[0]
	if j.Route.String() != "HTTPRoute web" || j.Proxy != "Istio" || len(j.Pods) != 1 || j.Pods[0].IP != "10.0.0.7" {
		t.Errorf("job %+v", j)
	}
	got := map[string]ProbeTarget{}
	for _, tg := range j.Targets {
		got[tg.Path] = tg
	}
	if len(j.Targets) != 4 {
		t.Errorf("%d targets, want 2 rules × 2 HTTP listeners: %+v", len(j.Targets), j.Targets)
	}
	for _, tg := range j.Targets {
		if tg.Host != "inkwall-probe.example.com" || (tg.Port == 443) != tg.TLS || (tg.Port != 80 && tg.Port != 443) {
			t.Errorf("target %+v: want the concrete host, port 80 or 443 over TLS", tg)
		}
	}
	if api := got["/api"]; !api.Prefix || api.Method != "POST" {
		t.Errorf("api rule's target %+v", api)
	}
	if h := got["/healthz"]; h.Prefix {
		t.Errorf("health rule's target %+v", h)
	}

	// Header and query matches: their values go in the probe over plain
	// HTTP only. On an HTTPS listener the probe doesn't verify the
	// certificate, so it doesn't send them there: not probeable (#507).
	route.Spec.Rules[0].Matches[1].Headers = []gatewayv1.HTTPHeaderMatch{{Type: &headerExact, Name: "X-Api-Key", Value: "k"}}
	route.Spec.Rules[0].Matches[1].QueryParams = []gatewayv1.HTTPQueryParamMatch{{Name: "v", Value: "2"}}
	if _, why := st.istioRouteProbes(&istioRoute{route: route, gateways: []types.NamespacedName{{Namespace: "edge", Name: "gw"}}, sections: []string{"api"}}); !strings.Contains(why, "rule api") || !strings.Contains(why, "TLS") {
		t.Errorf("header match over TLS: why %q", why)
	}
	plain := gw.DeepCopy()
	plain.Spec.Listeners = plain.Spec.Listeners[:1]
	st.gateways[types.NamespacedName{Namespace: "edge", Name: "gw"}] = plain
	jobs, why = st.istioRouteProbes(&istioRoute{route: route, gateways: []types.NamespacedName{{Namespace: "edge", Name: "gw"}}, sections: []string{"api"}})
	if why != "" || len(jobs) != 1 || len(jobs[0].Targets) != 1 || jobs[0].Targets[0].Headers["X-Api-Key"] != "k" || jobs[0].Targets[0].Query != "v=2" || jobs[0].Targets[0].TLS {
		t.Errorf("header match over HTTP: jobs %+v, why %q", jobs, why)
	}
	st.gateways[types.NamespacedName{Namespace: "edge", Name: "gw"}] = gw

	// Only regular expressions: not probeable.
	route.Spec.Rules[1].Matches = []gatewayv1.HTTPRouteMatch{{Headers: []gatewayv1.HTTPHeaderMatch{{Type: &headerRegex, Name: "X-A", Value: ".*"}}}}
	if _, why := st.istioRouteProbes(&istioRoute{route: route, gateways: []types.NamespacedName{{Namespace: "edge", Name: "gw"}}, sections: []string{"health"}}); !strings.Contains(why, "rule health") || !strings.Contains(why, "regular expression") {
		t.Errorf("why %q", why)
	}
}

// A VirtualService's probe: per Gateway server whose hosts it serves, on
// the server's port, over TLS for a SIMPLE TLS server; a mutual TLS server
// can't be probed.
func TestIstioVSProbe(t *testing.T) {
	gwObj := newObject(IstioGatewayGVK, "istio-ingress", "edge")
	gwObj.Object["spec"] = map[string]any{"selector": map[string]any{"istio": "ingressgateway"}, "servers": []any{
		map[string]any{"port": map[string]any{"number": int64(80), "protocol": "HTTP"}, "hosts": []any{"*"}},
		map[string]any{"port": map[string]any{"number": int64(443), "protocol": "HTTPS"}, "hosts": []any{"*/shop.example.com"}, "tls": map[string]any{"mode": "SIMPLE"}},
	}}
	vs := testVS(t, "shop", "web", `
hosts: [shop.example.com]
gateways: [istio-ingress/edge]
http:
- name: api
  match: [{uri: {regex: "/v[0-9]+"}}, {uri: {prefix: /api/}}]
- name: web
`)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "istio-ingress", Name: "igw-1", UID: "u1"}, Status: corev1.PodStatus{PodIP: "10.0.0.9"}}
	st := &istioIngressState{gateways: map[types.NamespacedName]*unstructured.Unstructured{{Namespace: "istio-ingress", Name: "edge"}: gwObj}}
	r := &istioVSRoute{vs: vs, gateways: []types.NamespacedName{{Namespace: "istio-ingress", Name: "edge"}}, pods: map[string][]*corev1.Pod{"istio-ingress": {pod}}}
	jobs, why := st.vsProbes(r)
	if why != "" || len(jobs) != 1 || len(jobs[0].Targets) != 4 || jobs[0].Route.String() != "VirtualService web" {
		t.Fatalf("jobs %+v, why %q", jobs, why)
	}
	for _, tg := range jobs[0].Targets {
		if tg.Host != "shop.example.com" || (tg.Port == 443) != tg.TLS {
			t.Errorf("target %+v", tg)
		}
		if tg.Path == "/api/" && !tg.Prefix {
			t.Errorf("api target %+v", tg)
		}
	}
	// A header match on a TLS server: not probeable (#507).
	http0, _, _ := unstructured.NestedSlice(vs.Object, "spec", "http")
	http0[0].(map[string]any)["match"] = []any{map[string]any{"uri": map[string]any{"prefix": "/api/"}, "headers": map[string]any{"x-api-key": map[string]any{"exact": "k"}}}}
	_ = unstructured.SetNestedSlice(vs.Object, http0, "spec", "http")
	if _, why := st.vsProbes(r); !strings.Contains(why, "TLS") || !strings.Contains(why, "api") {
		t.Errorf("header match over TLS: why %q", why)
	}
	// A mutual TLS server can't be probed.
	servers, _, _ := unstructured.NestedSlice(gwObj.Object, "spec", "servers")
	servers[1].(map[string]any)["tls"] = map[string]any{"mode": "MUTUAL"}
	_ = unstructured.SetNestedSlice(gwObj.Object, servers, "spec", "servers")
	if _, why := st.vsProbes(r); !strings.Contains(why, "mutual TLS") {
		t.Errorf("why %q", why)
	}
}

// A wired Istio route is proven once the engine answered the probe on
// every target through every pod (Envoy's local reply: 200 and the MAC);
// an answer from past the filter (the app's) leaves it Unverified; a
// route the probe can't make is NotProbeable. (A detect-mode route is
// proven by the engine's receipt: TestProveDetectRouteByReceipt.)
func TestProveRoute(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{5}, haproxyprobe.KeySize)
	engine := true
	p := &Prober{
		Key: func(context.Context) ([]byte, error) { return key, nil },
		Do: func(_ context.Context, pod ProbePod, target ProbeTarget, req *http.Request) (*http.Response, error) {
			if target.Port == 0 || req.Header.Get("X-Tenant") != "a" {
				t.Errorf("probe %+v %v", target, req.Header)
			}
			h := http.Header{}
			if engine {
				answer, _ := haproxyprobe.Check(key, req.URL.RequestURI(), req.Host, req.Header.Get(haproxyprobe.Header))
				h.Set(haproxyprobe.Header, answer)
			}
			return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	}
	job := ProbeJob{Route: ProbeRoute{Kind: "HTTPRoute", Key: types.NamespacedName{Namespace: "shop", Name: "web"}}, Proxy: "Istio",
		Pods:    []ProbePod{{Name: "edge/gw-1", UID: "u1", IP: "10.0.0.7"}},
		Targets: []ProbeTarget{{Host: "shop.example.com", Path: "/api", Prefix: true, Port: 80, Headers: map[string]string{"X-Tenant": "a"}}}}
	jobs := func() ([]ProbeJob, string) { return []ProbeJob{job}, "" }
	p.Set("istio", []ProbeJob{job})
	if _, np, u := proveRoute(p, "HTTPRoute web", false, jobs); np != "" || !strings.Contains(u, "unverified until") {
		t.Errorf("before a probe: %q %q", np, u)
	}
	p.Run(ctx)
	if _, np, u := proveRoute(p, "HTTPRoute web", false, jobs); np != "" || u != "" {
		t.Errorf("proven: %q %q", np, u)
	}
	engine = false
	p2 := &Prober{Key: p.Key, Do: p.Do}
	p2.Set("istio", []ProbeJob{job})
	p2.Run(ctx)
	if _, _, u := proveRoute(p2, "HTTPRoute web", false, jobs); !strings.Contains(u, "doesn't run the filter") {
		t.Errorf("the app answered: %q", u)
	}
	if _, np, _ := proveRoute(p, "HTTPRoute web", false, func() ([]ProbeJob, string) { return nil, "a regular expression" }); np == "" {
		t.Error("not probeable: nothing said")
	}
}

// A route that leaves the probe's jobs for a moment (its pods SidecarMissing
// during a rollout) and comes back on the same pods is proven at once: its
// results are kept for the reprobe interval, so it doesn't go Unverified
// first and rewrite the status twice more (#372, the wiring scale test).
func TestProbeResultsOutliveAJobBriefly(t *testing.T) {
	key := bytes.Repeat([]byte{5}, haproxyprobe.KeySize)
	now := time.Unix(1_800_000_000, 0)
	p := &Prober{
		Key: func(context.Context) ([]byte, error) { return key, nil },
		Now: func() time.Time { return now },
		Do: func(_ context.Context, _ ProbePod, _ ProbeTarget, req *http.Request) (*http.Response, error) {
			answer, _ := haproxyprobe.Check(key, req.URL.RequestURI(), req.Host, req.Header.Get(haproxyprobe.Header))
			h := http.Header{}
			h.Set(haproxyprobe.Header, answer)
			return &http.Response{StatusCode: http.StatusOK, Header: h, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	}
	job := ProbeJob{Route: ProbeRoute{Kind: "VirtualService", Key: types.NamespacedName{Namespace: "shop", Name: "web"}}, Proxy: "Istio ingress gateway",
		Fingerprint: "1", Targets: []ProbeTarget{{Host: "web.example.com", Path: "/", Port: 80}},
		Pods: []ProbePod{{Name: "gw-0", UID: "u0", IP: "10.0.0.1"}}}
	ctx := context.Background()
	p.Set("istio-ingress", []ProbeJob{job})
	p.Run(ctx)
	if why := p.Unverified(job); why != "" {
		t.Fatalf("not proven: %s", why)
	}
	p.Set("istio-ingress", nil)
	now = now.Add(10 * time.Second)
	p.Run(ctx)
	p.Set("istio-ingress", []ProbeJob{job})
	if why := p.Unverified(job); why != "" {
		t.Errorf("back after 10 s: %s", why)
	}
	// Gone for longer than the reprobe interval: probed again.
	p.Set("istio-ingress", nil)
	now = now.Add(haproxyReprobe + time.Second)
	p.Run(ctx)
	p.Set("istio-ingress", []ProbeJob{job})
	if why := p.Unverified(job); why == "" {
		t.Error("back after the reprobe interval: proven by an old result")
	}
}

// The users' EnvoyFilters are in the probe's fingerprint: one added,
// changed or removed (say, removing Inkwall's filter from a listener)
// re-probes the Istio routes at once, rather than at the reprobe interval.
// The operator's own don't count: they change with the wiring, which is in
// the fingerprint already.
func TestUserFiltersKey(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	filter := func(ns, name string, managed bool) *unstructured.Unstructured {
		u := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{}}}
		u.SetGroupVersionKind(EnvoyFilterGVK)
		u.SetNamespace(ns)
		u.SetName(name)
		if managed {
			u.SetLabels(map[string]string{"app.kubernetes.io/managed-by": "inkwall-operator"})
		}
		return u
	}
	ours := filter("edge", "inkwall-istio-ingress-00", true)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(ours).Build()
	key := func() string {
		t.Helper()
		k, err := userFiltersKey(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	none := key()
	if err := c.Update(ctx, ours); err != nil {
		t.Fatal(err)
	}
	if key() != none {
		t.Error("the operator's own EnvoyFilter changed the key")
	}
	user := filter("istio-system", "remove-inkwall", false)
	if err := c.Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	added := key()
	if added == none {
		t.Error("a user's EnvoyFilter didn't change the key")
	}
	user.SetAnnotations(map[string]string{"edited": "yes"})
	if err := c.Update(ctx, user); err != nil {
		t.Fatal(err)
	}
	if key() == added {
		t.Error("an edit of a user's EnvoyFilter didn't change the key")
	}
	if err := c.Delete(ctx, user); err != nil {
		t.Fatal(err)
	}
	if key() != none {
		t.Error("the user's EnvoyFilter deleted: the key isn't back")
	}
}

// A Detect-mode route is proven by the engine's receipt (#475): Envoy
// forwards the probe to the app and discards the engine's answer, so the
// operator waits for the probed pod's engine to report the receipt of
// that very probe in the engine reports. Nothing else proves it: no
// receipt, a receipt under another key, one from another pod's engine, one
// of an earlier probe (replayed), a stale report, or the probe's own
// request or answer MAC passed off as a receipt; after receiptWait the
// route is Unverified with the reason. A receipt never proves a Block-mode
// route, whose answer must come back.
func TestProveDetectRouteByReceipt(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{5}, haproxyprobe.KeySize)
	other := bytes.Repeat([]byte{6}, haproxyprobe.KeySize)
	route := ProbeRoute{Kind: "HTTPRoute", Key: types.NamespacedName{Namespace: "shop", Name: "web"}}
	job := ProbeJob{Route: route, Proxy: "Istio", Fingerprint: "edge/gw/1/1",
		Pods:    []ProbePod{{Name: "edge/gw-1", UID: "u1", IP: "10.0.0.7"}},
		Targets: []ProbeTarget{{Host: "shop.example.com", Path: "/api", Prefix: true, Port: 80}}}
	jobsOf := func() ([]ProbeJob, string) { return []ProbeJob{job}, "" }

	type seen struct{ nonce, host, uri, header string }
	tests := []struct {
		name   string
		detect bool
		// report is what the engines report once the probe was sent: the
		// pod, its receipts; stale: an old report.
		report func(s seen) (pod string, receipts []string, stale bool)
		proven bool
		why    string
	}{
		{"the pod's engine reports its receipt", true, func(s seen) (string, []string, bool) {
			return "edge/gw-1", []string{haproxyprobe.ExpectedReceipt(key, s.nonce, s.host, s.uri)}, false
		}, true, ""},
		{"no receipt", true, func(seen) (string, []string, bool) { return "edge/gw-1", nil, false }, false, "reported no receipt"},
		{"a receipt under another key (forged)", true, func(s seen) (string, []string, bool) {
			return "edge/gw-1", []string{haproxyprobe.ExpectedReceipt(other, s.nonce, s.host, s.uri)}, false
		}, false, "reported no receipt"},
		{"another pod's engine reports it", true, func(s seen) (string, []string, bool) {
			return "edge/gw-2", []string{haproxyprobe.ExpectedReceipt(key, s.nonce, s.host, s.uri)}, false
		}, false, "reported no receipt"},
		{"a stale report", true, func(s seen) (string, []string, bool) {
			return "edge/gw-1", []string{haproxyprobe.ExpectedReceipt(key, s.nonce, s.host, s.uri)}, true
		}, false, "reported no receipt"},
		{"the request's MAC passed off as a receipt", true, func(s seen) (string, []string, bool) {
			_, mac, _ := strings.Cut(s.header, ".")
			return "edge/gw-1", []string{mac[:haproxyprobe.ReceiptSize]}, false
		}, false, "reported no receipt"},
		{"the answer passed off as a receipt", true, func(s seen) (string, []string, bool) {
			answer, _ := haproxyprobe.Check(key, s.uri, s.host, s.header)
			return "edge/gw-1", []string{answer[:haproxyprobe.ReceiptSize]}, false
		}, false, "reported no receipt"},
		{"block mode: a receipt is no answer", false, func(s seen) (string, []string, bool) {
			return "edge/gw-1", []string{haproxyprobe.ExpectedReceipt(key, s.nonce, s.host, s.uri)}, false
		}, false, "not the engine's answer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			var mu sync.Mutex
			var last seen
			c := fake.NewClientBuilder().Build()
			p := &Prober{
				Reader: c, Namespace: "inkwall-system",
				Key: func(context.Context) ([]byte, error) { return key, nil },
				Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now },
				// Envoy in observability mode: the app answers.
				Do: func(_ context.Context, _ ProbePod, _ ProbeTarget, req *http.Request) (*http.Response, error) {
					header := req.Header.Get(haproxyprobe.Header)
					nonce, _, _ := strings.Cut(header, ".")
					mu.Lock()
					last = seen{nonce: nonce, host: req.Host, uri: req.URL.RequestURI(), header: header}
					mu.Unlock()
					return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
				},
			}
			prove := func() (string, string) {
				_, np, u := proveRoute(p, "HTTPRoute web", tt.detect, jobsOf)
				return np, u
			}
			jobs, _, _ := proveRoute(p, "HTTPRoute web", tt.detect, jobsOf)
			p.Set("istio", jobs)
			p.Run(ctx)
			if np, u := prove(); np != "" || tt.detect && !strings.Contains(u, "unverified until") {
				t.Fatalf("probe sent: %q %q", np, u)
			}
			pod, receipts, stale := tt.report(last)
			writeReport(ctx, t, c, "inkwall-system", now, stale, pod, receipts)
			mu.Lock()
			now = now.Add(5 * time.Second)
			mu.Unlock()
			p.Run(ctx)
			_, u := prove()
			if tt.proven {
				if u != "" {
					t.Fatalf("not proven: %s", u)
				}
				return
			}
			if u == "" {
				t.Fatal("proven")
			}
			mu.Lock()
			now = now.Add(receiptWait)
			mu.Unlock()
			p.Run(ctx)
			if _, u := prove(); !strings.Contains(u, "doesn't run the filter") || !strings.Contains(u, tt.why) {
				t.Fatalf("after the wait: %q, want %q", u, tt.why)
			}
		})
	}
}

// A receipt proves one probe only: replayed for the next probe (after the
// route changed, or at the reprobe interval), it proves nothing.
func TestDetectReceiptReplayed(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{5}, haproxyprobe.KeySize)
	now := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	var receipt string
	c := fake.NewClientBuilder().Build()
	p := &Prober{
		Reader: c, Namespace: "inkwall-system",
		Key: func(context.Context) ([]byte, error) { return key, nil },
		Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now },
		Do: func(_ context.Context, _ ProbePod, _ ProbeTarget, req *http.Request) (*http.Response, error) {
			r, ok := haproxyprobe.Receipt(key, req.URL.RequestURI(), req.Host, req.Header.Get(haproxyprobe.Header))
			if !ok {
				t.Error("not a probe")
			}
			mu.Lock()
			receipt = r
			mu.Unlock()
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	}
	job := ProbeJob{Route: ProbeRoute{Kind: "VirtualService", Key: types.NamespacedName{Namespace: "shop", Name: "web"}}, Proxy: "Istio ingress gateway",
		Fingerprint: "1", Pods: []ProbePod{{Name: "edge/gw-1", UID: "u1", IP: "10.0.0.7"}},
		Targets: []ProbeTarget{{Host: "web.example.com", Path: "/", Prefix: true, Port: 80}}}
	jobsOf := func() ([]ProbeJob, string) { return []ProbeJob{job}, "" }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	set := func() { jobs, _, _ := proveRoute(p, "VirtualService web", true, jobsOf); p.Set("istio-ingress", jobs) }

	set()
	p.Run(ctx)
	first := receipt
	writeReport(ctx, t, c, "inkwall-system", now, false, "edge/gw-1", []string{first})
	advance(5 * time.Second)
	p.Run(ctx)
	if _, _, u := proveRoute(p, "VirtualService web", true, jobsOf); u != "" {
		t.Fatalf("not proven: %s", u)
	}
	// The route changes: probed again; the engine reports only the old
	// receipt.
	job.Fingerprint = "2"
	set()
	p.Run(ctx)
	if receipt == first {
		t.Fatal("the same receipt for a new probe")
	}
	advance(5 * time.Second)
	writeReport(ctx, t, c, "inkwall-system", now, false, "edge/gw-1", []string{first})
	p.Run(ctx)
	advance(receiptWait)
	writeReport(ctx, t, c, "inkwall-system", now, false, "edge/gw-1", []string{first})
	p.Run(ctx)
	if _, _, u := proveRoute(p, "VirtualService web", true, jobsOf); !strings.Contains(u, "reported no receipt") {
		t.Fatalf("proven by a replayed receipt: %q", u)
	}
}

// In Detect mode Envoy forwards the probe to the app: it is sent only as a
// GET or HEAD, so a rule that matches only another method can't be
// probed there.
func TestDetectProbeMethods(t *testing.T) {
	p := &Prober{Key: func(context.Context) ([]byte, error) { return nil, nil }}
	for method, probeable := range map[string]bool{"": true, "GET": true, "HEAD": true, "POST": false, "DELETE": false} {
		jobsOf := func() ([]ProbeJob, string) {
			return []ProbeJob{{Route: ProbeRoute{Kind: "HTTPRoute"}, Targets: []ProbeTarget{{Host: "a", Path: "/", Method: method}}}}, ""
		}
		_, np, _ := proveRoute(p, "HTTPRoute web", true, jobsOf)
		if (np == "") != probeable {
			t.Errorf("%q in Detect mode: not probeable %q", method, np)
		}
		if _, np, _ := proveRoute(p, "HTTPRoute web", false, jobsOf); np != "" {
			t.Errorf("%q in Block mode: not probeable %q", method, np)
		}
	}
}

// writeReport writes a replica's engine report with one engine, of pod
// (namespace/name), with receipts; stale: written long ago.
func writeReport(ctx context.Context, t *testing.T, c client.Client, namespace string, now time.Time, stale bool, pod string, receipts []string) {
	t.Helper()
	ns, name, _ := strings.Cut(pod, "/")
	data, _ := json.Marshal([]enginereport.Engine{{ID: name, PodNamespace: ns, PodName: name, Replica: "r", ProbeReceipts: receipts}})
	updated := now
	if stale {
		updated = now.Add(-time.Hour)
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: enginereport.NamePrefix + "r", Labels: map[string]string{enginereport.Label: "true"}},
		Data: map[string]string{enginereport.EnginesKey: string(data), enginereport.UpdatedAtKey: updated.UTC().Format(time.RFC3339Nano)}}
	if err := c.Update(ctx, cm); apierrors.IsNotFound(err) {
		err = c.Create(ctx, cm)
		if err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
}
