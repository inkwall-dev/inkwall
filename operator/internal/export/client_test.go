// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestRefusedClass(t *testing.T) {
	for addr, want := range map[string]string{
		"127.0.0.1":                "loopback",
		"127.5.6.7":                "loopback",
		"::1":                      "loopback",
		"0.0.0.0":                  "unspecified",
		"0.1.2.3":                  "unspecified",
		"::":                       "unspecified",
		"169.254.169.254":          "link-local",
		"169.254.1.1":              "link-local",
		"fe80::1":                  "link-local",
		"fe80::1%eth0":             "link-local",
		"fd00:ec2::254":            "metadata",
		"100.100.100.200":          "metadata",
		"::ffff:169.254.169.254":   "link-local",
		"::ffff:127.0.0.1":         "loopback",
		"64:ff9b::a9fe:a9fe":       "link-local",
		"64:ff9b::7f00:1":          "loopback",
		"64:ff9b::6464:64c8":       "metadata",
		"10.0.0.1":                 "",
		"172.16.5.4":               "",
		"192.168.1.1":              "",
		"100.100.100.201":          "",
		"fd00:ec2::253":            "",
		"203.0.113.7":              "",
		"2001:db8::1":              "",
		"64:ff9b::cb00:7107":       "",
		"::ffff:10.0.0.1":          "",
		"fd12:3456:789a:1::1":      "",
		"100.64.0.1":               "",
		"64:ff9b:1::a9fe:a9fe":     "link-local",
		"64:ff9b:1:a9fe:a9:fe00::": "link-local",
		"64:ff9b:1:7f00:0:1::":     "loopback",
		"64:ff9b:1::cb00:7107":     "",
		"64:ff9b:1::1":             "",
		"2600:1f18::1":             "",
		"169.253.255.255":          "",
		"169.255.0.1":              "",
		"fe7f:ffff:ffff:ffff::1":   "",
		"febf:ffff:ffff:ffff::1":   "link-local",
		"ff02::1":                  "link-local",
		"224.0.0.1":                "link-local",
		"::ffff:100.100.100.200":   "metadata",
		"64:ff9b::a9fe:1":          "link-local",
		"64:ff9b::ffff:a9fe:a9fe":  "",
	} {
		if got := refusedClass(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %q, want %q", addr, got, want)
		}
	}
}

// fakeDNS answers every A question with addr.
func fakeDNS(t *testing.T, addr [4]byte) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true})
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			if q.Type == dnsmessage.TypeA {
				_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: addr})
			}
			out, _ := b.Finish()
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", pc.LocalAddr().String())
	}}
}

// The check is on the resolved address, at connect time: a name that
// resolves to the metadata service is refused, whatever the name.
func TestDialerRefusesWhatANameResolvesTo(t *testing.T) {
	useResolver(t, fakeDNS(t, [4]byte{169, 254, 169, 254}))
	c := newHTTPClient(transportConfig{url: "http://metadata.attacker.example:8080/latest/meta-data/"})
	r := c.send(context.Background(), payload{body: []byte("x"), contentType: "text/plain"}, nil)
	if r.refused != "link-local" || r.verdict != retry || r.kind != kindNetwork || strings.Contains(r.detail, "169.254") {
		t.Errorf("result %+v, want refused as link-local, without the address", r)
	}
	g, err := newGRPCClient(transportConfig{grpc: true, insecure: true, url: "metadata.attacker.example:4317"})
	if err != nil {
		t.Fatal(err)
	}
	defer g.close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r = g.send(ctx, payload{otlp: &collogspb.ExportLogsServiceRequest{}}, nil)
	if r.refused != "link-local" {
		t.Errorf("gRPC result %+v, want refused as link-local", r)
	}
}

func TestDialerRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the loopback was reached")
	}))
	defer srv.Close()
	r := newHTTPClient(transportConfig{url: srv.URL}).send(context.Background(), payload{body: []byte("x")}, nil)
	if r.refused != "loopback" {
		t.Errorf("result %+v, want refused as loopback", r)
	}
}

// HTTPS_PROXY and HTTP_PROXY are ignored: the dialer would check the
// proxy's address instead of the sink's.
func TestProxyFromEnvironmentIgnored(t *testing.T) {
	allowLoopback(t)
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	var direct atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		direct.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()
	// A name, so a proxy (which skips localhost addresses) would be used.
	u := strings.Replace(sink.URL, "127.0.0.1", "sink.example", 1)
	useResolver(t, fakeDNS(t, [4]byte{127, 0, 0, 1}))
	r := newHTTPClient(transportConfig{url: u}).send(context.Background(), payload{body: []byte("x")}, nil)
	if r.verdict != sent || direct.Load() != 1 || proxied.Load() != 0 {
		t.Errorf("result %+v, direct %d, proxied %d", r, direct.Load(), proxied.Load())
	}
}

func TestNoRedirectFollowed(t *testing.T) {
	allowLoopback(t)
	var followed atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Add(1) }))
	defer target.Close()
	srv := httptest.NewServer(http.RedirectHandler(target.URL+"/internal", http.StatusTemporaryRedirect))
	defer srv.Close()
	r := newHTTPClient(transportConfig{url: srv.URL}).send(context.Background(), payload{body: []byte("x")}, nil)
	if r.verdict != drop || followed.Load() != 0 || !strings.HasPrefix(r.detail, "307") {
		t.Errorf("result %+v, redirect followed %d times", r, followed.Load())
	}
}

// Responses are read up to 4 KiB, and at most 128 bytes, escaped, reach
// status and logs.
func TestResponseReadCapped(t *testing.T) {
	allowLoopback(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "secret\x1b[31m\n"+strings.Repeat("A", 1<<20))
	}))
	defer srv.Close()
	r := newHTTPClient(transportConfig{url: srv.URL}).send(context.Background(), payload{body: []byte("x")}, nil)
	if r.verdict != drop || r.kind != kindClient || len(r.detail) > 4+maxDetail*4+2 || strings.ContainsAny(r.detail, "\n\x1b") {
		t.Errorf("result %+v (%d bytes of detail)", r.verdict, len(r.detail))
	}
}

func TestClassifyHTTP(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		code    int
		otlp    bool
		verdict verdict
		kind    string
	}{
		{200, true, sent, ""}, {202, false, sent, ""}, {204, false, sent, ""},
		{429, true, retry, kindThrottled}, {429, false, retry, kindThrottled},
		{502, true, retry, kindServer}, {503, true, retry, kindServer}, {504, true, retry, kindServer},
		{502, false, retry, kindServer}, {503, false, retry, kindServer}, {504, false, retry, kindServer},
		// Plain HTTP intakes use 408 and 500 for passing faults; OTLP's
		// spec doesn't retry them.
		{408, false, retry, kindTimeout}, {500, false, retry, kindServer},
		{408, true, drop, kindClient}, {500, true, drop, kindServer},
		// The one deviation from the spec: retried slowly.
		{401, true, retrySlow, kindAuth}, {403, false, retrySlow, kindAuth},
		{413, true, split, kindClient}, {413, false, split, kindClient},
		{400, true, drop, kindClient}, {404, false, drop, kindClient}, {422, false, drop, kindClient},
		{501, true, drop, kindServer}, {505, false, drop, kindServer},
		{301, false, drop, kindClient}, {302, true, drop, kindClient}, {308, false, drop, kindClient},
	} {
		r := classifyHTTP(tc.code, tc.otlp, "", now)
		if r.verdict != tc.verdict || r.kind != tc.kind {
			t.Errorf("%d (otlp %t): %v %q, want %v %q", tc.code, tc.otlp, r.verdict, r.kind, tc.verdict, tc.kind)
		}
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	for v, want := range map[string]time.Duration{
		"":                              0,
		"7":                             7 * time.Second,
		"0":                             0,
		"-3":                            0,
		"86400":                         maxRetryAfter,
		"Fri, 20 Nov 2026 10:00:30 GMT": 30 * time.Second,
		"Fri, 20 Nov 2026 09:00:00 GMT": 0,
		"Sat, 21 Nov 2026 10:00:00 GMT": maxRetryAfter,
		"soon":                          0,
	} {
		if got := parseRetryAfter(v, now); got != want {
			t.Errorf("Retry-After %q: %v, want %v", v, got, want)
		}
	}
	if r := classifyHTTP(429, true, "12", now); r.after != 12*time.Second {
		t.Errorf("429 with Retry-After 12: wait %v", r.after)
	}
	if r := classifyHTTP(503, false, "3", now); r.after != 3*time.Second {
		t.Errorf("503 with Retry-After 3: wait %v", r.after)
	}
}

func withRetryInfo(t *testing.T, c codes.Code, d time.Duration) *status.Status {
	t.Helper()
	st, err := status.New(c, "slow down").WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(d)})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestClassifyGRPC(t *testing.T) {
	for _, tc := range []struct {
		code    codes.Code
		size    int
		verdict verdict
		kind    string
	}{
		{codes.Unavailable, 10, retry, kindNetwork},
		{codes.DeadlineExceeded, 10, retry, kindTimeout},
		{codes.Aborted, 10, retry, kindServer}, {codes.Canceled, 10, retry, kindServer},
		{codes.OutOfRange, 10, retry, kindServer}, {codes.DataLoss, 10, retry, kindServer},
		// Without RetryInfo: a message over the server's limit, or a quota.
		{codes.ResourceExhausted, splitOver + 1, split, kindClient},
		{codes.ResourceExhausted, splitOver, retry, kindThrottled},
		{codes.Unauthenticated, 10, retrySlow, kindAuth}, {codes.PermissionDenied, 10, retrySlow, kindAuth},
		{codes.InvalidArgument, 10, drop, kindClient}, {codes.Unimplemented, 10, drop, kindClient},
		{codes.NotFound, 10, drop, kindClient}, {codes.FailedPrecondition, 10, drop, kindClient},
		{codes.AlreadyExists, 10, drop, kindClient}, {codes.Internal, 10, drop, kindServer}, {codes.Unknown, 10, drop, kindServer},
	} {
		r := classifyGRPC(status.New(tc.code, "x"), tc.size)
		if r.verdict != tc.verdict || r.kind != tc.kind {
			t.Errorf("%v (%d bytes): %v %q, want %v %q", tc.code, tc.size, r.verdict, r.kind, tc.verdict, tc.kind)
		}
	}
	r := classifyGRPC(withRetryInfo(t, codes.ResourceExhausted, 9*time.Second), splitOver+1)
	if r.verdict != retry || r.kind != kindThrottled || r.after != 9*time.Second {
		t.Errorf("RESOURCE_EXHAUSTED with RetryInfo: %+v, want a retry in 9s", r)
	}
	if r := classifyGRPC(withRetryInfo(t, codes.Unavailable, time.Hour), 10); r.after != maxRetryAfter {
		t.Errorf("RetryInfo of an hour: wait %v, want the cap", r.after)
	}
	if r := classifyGRPC(status.New(codes.Unavailable, "connection error: desc = \"transport: authentication handshake failed: tls: bad certificate\""), 10); r.kind != kindTLS {
		t.Errorf("a TLS failure: kind %q", r.kind)
	}
	if r := classifyGRPC(status.New(codes.Unavailable, "dial: the sink's address is refused: metadata"), 10); r.refused != "metadata" {
		t.Errorf("a refused address: %+v", r)
	}
	if r := classifyGRPC(status.New(codes.InvalidArgument, strings.Repeat("x", 1000)), 10); len(r.detail) > len("InvalidArgument ")+maxDetail+2 {
		t.Errorf("detail of %d bytes", len(r.detail))
	}
}

func TestPartialSuccessOverHTTP(t *testing.T) {
	allowLoopback(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-protobuf" || r.Header.Get("Content-Encoding") != "gzip" {
			t.Errorf("headers %v", r.Header)
		}
		raw, _ := proto.Marshal(&collogspb.ExportLogsServiceResponse{PartialSuccess: &collogspb.ExportLogsPartialSuccess{RejectedLogRecords: 2, ErrorMessage: "two too old"}})
		_, _ = w.Write(raw)
	}))
	defer srv.Close()
	p := encode(formatOTLPHTTP, &testView, items(fullEvent(), oldEvent(), rateLimited()))
	r := newHTTPClient(transportConfig{url: srv.URL, gzip: true, otlp: true}).send(context.Background(), p, nil)
	if r.verdict != sent || r.rejected != 2 || !strings.Contains(r.detail, "two too old") {
		t.Errorf("result %+v", r)
	}
}
