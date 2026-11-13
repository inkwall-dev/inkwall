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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/inkwall-dev/inkwall/operator/enginereport"
	"github.com/inkwall-dev/inkwall/pkg/haproxyprobe"
)

func probeAnswer(status int, header string) *http.Response {
	h := http.Header{}
	if header != "" {
		h.Set(haproxyprobe.Header, header)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(""))}
}

// writeEngine writes a replica's engine report with one engine, of pod
// (namespace/name), running version, with receipts.
func writeEngine(ctx context.Context, t *testing.T, c client.Client, now time.Time, pod, version string, receipts []string) {
	t.Helper()
	ns, name, _ := strings.Cut(pod, "/")
	data, _ := json.Marshal([]enginereport.Engine{{ID: name, PodNamespace: ns, PodName: name, EngineVersion: version, Replica: "r", ProbeReceipts: receipts}})
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "inkwall-system", Name: enginereport.NamePrefix + "r", Labels: map[string]string{enginereport.Label: "true"}},
		Data: map[string]string{enginereport.EnginesKey: string(data), enginereport.UpdatedAtKey: now.UTC().Format(time.RFC3339Nano)}}
	err := c.Update(ctx, cm)
	if apierrors.IsNotFound(err) {
		err = c.Create(ctx, cm)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// sentProbe is a probe as the engine sees it.
type sentProbe struct{ nonce, host, uri, header string }

func (s sentProbe) response() bool { return haproxyprobe.IsResponseURI(s.uri) }

// The probe's response leg (#595) proves a route's responses where the
// proxy waits for the engine (HAProxy; Envoy in Block mode): the engine's
// answer in its response phase, for that very probe, under the key.
// Nothing else does: the app's response, the request leg's answer (an
// engine that doesn't keep the route's responses, or predates the response
// leg: then its route keeps today's evidence, with a note), another key's
// answer, or another probe's. The request leg is proven as before, apart.
func TestResponseLegByAnswer(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{5}, haproxyprobe.KeySize)
	other := bytes.Repeat([]byte{6}, haproxyprobe.KeySize)
	job := ProbeJob{Route: ProbeRoute{Kind: "Ingress", Key: types.NamespacedName{Namespace: "shop", Name: "web"}}, Proxy: "HAProxy", Fingerprint: "1",
		Pods:    []ProbePod{{Name: "ingress/hap-1", UID: "u1", IP: "10.0.0.7"}},
		Targets: []ProbeTarget{{Host: "shop.example.com", Path: "/", Prefix: true}}}
	var earlier string
	tests := []struct {
		name string
		// version is the engine's, as it reports it.
		version string
		answer  func(s sentProbe) *http.Response
		// proven, failed (its detail), note (its detail)
		proven       bool
		failed, note string
	}{
		{"the engine answers the response", "0.6.0", func(s sentProbe) *http.Response {
			a, _, _ := haproxyprobe.ResponseLeg(key, s.uri, s.host, s.header)
			return probeAnswer(haproxyprobe.Status, a)
		}, true, "", ""},
		{"the app's response", "0.6.0", func(sentProbe) *http.Response { return probeAnswer(404, "") }, false, "HTTP 404, not the engine's answer to the response", ""},
		{"another key's answer", "0.6.0", func(s sentProbe) *http.Response {
			a, _, _ := haproxyprobe.ResponseLeg(other, s.uri, s.host, haproxyprobe.Request(other, s.nonce, s.host, s.uri))
			return probeAnswer(haproxyprobe.Status, a)
		}, false, "not the engine's answer to the response", ""},
		{"an earlier probe's answer", "0.6.0", func(s sentProbe) *http.Response {
			if earlier == "" {
				earlier, _, _ = haproxyprobe.ResponseLeg(key, s.uri, s.host, s.header)
				return probeAnswer(404, "")
			}
			return probeAnswer(haproxyprobe.Status, earlier)
		}, false, "not the engine's answer to the response", ""},
		{"the response receipt, not an answer", "0.6.0", func(s sentProbe) *http.Response {
			return probeAnswer(haproxyprobe.Status, haproxyprobe.ExpectedResponseReceipt(key, s.nonce, s.host, s.uri))
		}, false, "not the engine's answer to the response", ""},
		{"answered at the request phase", "0.6.0", func(s sentProbe) *http.Response {
			a, _ := haproxyprobe.Check(key, s.uri, s.host, s.header)
			return probeAnswer(haproxyprobe.Status, a)
		}, false, "answered the probe's response leg at the request phase", ""},
		{"answered at the request phase by a custom build", "unknown", func(s sentProbe) *http.Response {
			a, _ := haproxyprobe.Check(key, s.uri, s.host, s.header)
			return probeAnswer(haproxyprobe.Status, a)
		}, false, "answered the probe's response leg at the request phase", ""},
		{"an engine before the response leg", "v0.5.0", func(s sentProbe) *http.Response {
			a, _ := haproxyprobe.Check(key, s.uri, s.host, s.header)
			return probeAnswer(haproxyprobe.Status, a)
		}, true, "", "unproven on HAProxy pod ingress/hap-1: its engine predates the probe's response leg (0.6.0)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			c := fake.NewClientBuilder().Build()
			writeEngine(ctx, t, c, now, "ingress/hap-1", tt.version, nil)
			var mu sync.Mutex
			legs := map[bool]int{}
			p := &Prober{Reader: c, Namespace: "inkwall-system",
				Key: func(context.Context) ([]byte, error) { return key, nil },
				Now: func() time.Time { return now },
				Do: func(_ context.Context, _ ProbePod, _ ProbeTarget, req *http.Request) (*http.Response, error) {
					header := req.Header.Get(haproxyprobe.Header)
					nonce, _, _ := strings.Cut(header, ".")
					s := sentProbe{nonce: nonce, host: req.Host, uri: req.URL.RequestURI(), header: header}
					mu.Lock()
					defer mu.Unlock()
					legs[s.response()]++
					if !s.response() {
						a, _ := haproxyprobe.Check(key, s.uri, s.host, header)
						return probeAnswer(haproxyprobe.Status, a), nil
					}
					return tt.answer(s), nil
				}}
			earlier = ""
			jobs, proof := proveResponses(p, "Ingress web", true, []ProbeJob{job})
			if proof.Unverified != "" || !jobs[0].Responses {
				t.Fatalf("before the probe: %+v", proof)
			}
			p.Set("haproxy", jobs)
			_, proof = proveResponses(p, "Ingress web", true, []ProbeJob{job})
			p.Run(ctx)
			if tt.name == "an earlier probe's answer" {
				now = now.Add(haproxyRetry)
				p.Run(ctx)
			}
			_, proof = proveResponses(p, "Ingress web", true, []ProbeJob{job})
			if legs[false] == 0 || legs[true] == 0 {
				t.Fatalf("legs sent: %v", legs)
			}
			if u := p.Unverified(jobs[0]); u != "" {
				t.Errorf("the request leg: %s", u)
			}
			switch {
			case tt.proven:
				if proof.Failed != "" || proof.Unverified != "" {
					t.Errorf("not proven: %+v", proof)
				}
			case !strings.Contains(proof.Failed, tt.failed) || !strings.Contains(proof.Failed, "don't reach the engine"):
				t.Errorf("failed %q, want %q", proof.Failed, tt.failed)
			}
			if tt.note == "" && proof.Note != "" || !strings.Contains(proof.Note, tt.note) {
				t.Errorf("note %q, want %q", proof.Note, tt.note)
			}
		})
	}
}

// Where Envoy discards the engine's answers (a Detect-mode Istio route),
// the response leg is proven by the probed pod's engine reporting the
// receipt of its response; the request leg's receipt for the same probe,
// or another pod's, proves nothing.
func TestResponseLegByReceipt(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{5}, haproxyprobe.KeySize)
	job := ProbeJob{Route: ProbeRoute{Kind: "HTTPRoute", Key: types.NamespacedName{Namespace: "shop", Name: "web"}}, Proxy: "Istio", Fingerprint: "1", Receipt: true,
		Pods:    []ProbePod{{Name: "edge/gw-1", UID: "u1", IP: "10.0.0.7"}},
		Targets: []ProbeTarget{{Host: "shop.example.com", Path: "/", Prefix: true, Port: 80}}}
	for _, tt := range []struct {
		name   string
		report func(s sentProbe) (pod, receipt string)
		proven bool
	}{
		{"its response's receipt", func(s sentProbe) (string, string) {
			_, r, _ := haproxyprobe.ResponseLeg(key, s.uri, s.host, s.header)
			return "edge/gw-1", r
		}, true},
		{"the request receipt of the response leg", func(s sentProbe) (string, string) {
			r, _ := haproxyprobe.Receipt(key, s.uri, s.host, s.header)
			return "edge/gw-1", r
		}, false},
		{"another pod's engine", func(s sentProbe) (string, string) {
			_, r, _ := haproxyprobe.ResponseLeg(key, s.uri, s.host, s.header)
			return "edge/gw-2", r
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			var mu sync.Mutex
			sent := map[bool]sentProbe{}
			c := fake.NewClientBuilder().Build()
			p := &Prober{Reader: c, Namespace: "inkwall-system",
				Key: func(context.Context) ([]byte, error) { return key, nil },
				Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now },
				Do: func(_ context.Context, _ ProbePod, _ ProbeTarget, req *http.Request) (*http.Response, error) {
					header := req.Header.Get(haproxyprobe.Header)
					nonce, _, _ := strings.Cut(header, ".")
					s := sentProbe{nonce: nonce, host: req.Host, uri: req.URL.RequestURI(), header: header}
					mu.Lock()
					sent[s.response()] = s
					mu.Unlock()
					return probeAnswer(404, ""), nil
				}}
			jobs, _ := proveResponses(p, "HTTPRoute web", true, []ProbeJob{job})
			p.Set("istio", jobs)
			p.Run(ctx)
			req, _ := haproxyprobe.Receipt(key, sent[false].uri, sent[false].host, sent[false].header)
			pod, r := tt.report(sent[true])
			if pod == "edge/gw-1" {
				writeEngine(ctx, t, c, now, pod, "0.6.0", []string{req, r})
			} else {
				writeEngine(ctx, t, c, now, pod, "0.6.0", []string{r})
			}
			mu.Lock()
			now = now.Add(5 * time.Second)
			mu.Unlock()
			p.Run(ctx)
			_, proof := proveResponses(p, "HTTPRoute web", true, []ProbeJob{job})
			if tt.proven {
				if proof != (ResponsesProof{}) {
					t.Fatalf("not proven: %+v", proof)
				}
				return
			}
			if proof.Unverified == "" {
				t.Fatalf("proven: %+v", proof)
			}
			mu.Lock()
			now = now.Add(receiptWait)
			mu.Unlock()
			p.Run(ctx)
			// Failed, or Unverified when the request leg isn't proven
			// either (another pod's report holds neither receipt).
			if _, proof = proveResponses(p, "HTTPRoute web", true, []ProbeJob{job}); !strings.Contains(proof.Failed+proof.Unverified, "no receipt of the probe's response") ||
				tt.name != "another pod's engine" && proof.Failed == "" {
				t.Fatalf("after the wait: %+v", proof)
			}
		})
	}
}

// The response leg reaches the app, so it is sent only as a GET or HEAD:
// a rule that matches only another method can't have its responses
// probed. A route whose policies don't inspect responses gets no
// response leg.
func TestResponseLegMethods(t *testing.T) {
	p := &Prober{Key: func(context.Context) ([]byte, error) { return nil, nil }}
	for method, probeable := range map[string]bool{"": true, "GET": true, "HEAD": true, "POST": false} {
		jobs := []ProbeJob{{Route: ProbeRoute{Kind: "HTTPRoute"}, Targets: []ProbeTarget{{Host: "a", Path: "/", Method: method}}}}
		jobs, proof := proveResponses(p, "HTTPRoute web", true, jobs)
		if (proof.NotProbeable == "") != probeable || jobs[0].Responses != probeable {
			t.Errorf("%q: %+v, response leg %v", method, proof, jobs[0].Responses)
		}
	}
	jobs, proof := proveResponses(p, "HTTPRoute web", false, []ProbeJob{{Targets: []ProbeTarget{{Host: "a", Path: "/"}}}})
	if jobs[0].Responses || proof != (ResponsesProof{}) {
		t.Errorf("without responses: %+v, %v", proof, jobs[0].Responses)
	}
}

// A response leg that fails while the request leg isn't proven either (no
// address, no answer) leaves the route Unverified: it shows nothing about
// the responses.
func TestResponseLegUnprovenRequest(t *testing.T) {
	key := bytes.Repeat([]byte{5}, haproxyprobe.KeySize)
	p := &Prober{Key: func(context.Context) ([]byte, error) { return key, nil }}
	job := ProbeJob{Route: ProbeRoute{Kind: "Ingress", Key: types.NamespacedName{Namespace: "shop", Name: "web"}}, Proxy: "HAProxy", Fingerprint: "1",
		Pods: []ProbePod{{Name: "ingress/hap-1", UID: "u1"}}, Targets: []ProbeTarget{{Host: "shop.example.com", Path: "/", Prefix: true}}}
	jobs, _ := proveResponses(p, "Ingress web", true, []ProbeJob{job})
	p.Set("haproxy", jobs)
	p.Run(context.Background())
	_, proof := proveResponses(p, "Ingress web", true, []ProbeJob{job})
	if proof.Failed != "" || !strings.Contains(proof.Unverified, "the pod has no IP yet") {
		t.Fatalf("%+v", proof)
	}
}
