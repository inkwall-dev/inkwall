// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/inkwall-dev/inkwall/pkg/adapters/forwardauth"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

// BenchmarkAdapters compares ext_proc with forward-auth on the same rules,
// each over a Unix socket as in a proxy's pod: a gRPC stream per request
// against an HTTP subrequest on a kept-alive connection.
func BenchmarkAdapters(b *testing.B) {
	p := newPipeline(b, pipeline.ModeBlock)
	const maxBody = 64 << 10
	cases := []struct{ name, method, target, body string }{
		{"benign_get", "GET", "/products?id=42&sort=price", ""},
		{"benign_form", "POST", "/login", "user=alice&password=correct-horse"},
		{"attack_sqli", "GET", "/products?id=1%27%20OR%20%271%27%3D%271", ""},
	}

	b.Run("extproc", func(b *testing.B) {
		s, err := New(p, Config{MaxBodyBytes: maxBody, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
		if err != nil {
			b.Fatal(err)
		}
		sock := filepath.Join(b.TempDir(), "extproc.sock")
		ln, err := net.Listen("unix", sock)
		if err != nil {
			b.Fatal(err)
		}
		e := startServer(b, s, ln, func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		})
		for _, c := range cases {
			msgs := []*extprocv3.ProcessingRequest{withMode(headers(c.method, c.target, c.body == ""), filterv3.ProcessingMode_BUFFERED)}
			if c.body != "" {
				msgs[0] = withMode(headers(c.method, c.target, false, "content-type", "application/x-www-form-urlencoded",
					"content-length", strconv.Itoa(len(c.body))), filterv3.ProcessingMode_BUFFERED)
				msgs = append(msgs, body(c.body, true))
			}
			b.Run(c.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if resps := e.exchange(b, msgs...); len(resps) == 0 {
						b.Fatal("no answer")
					}
				}
			})
		}
	})

	b.Run("forwardauth", func(b *testing.B) {
		h, err := forwardauth.New(p, forwardauth.Config{MaxBodyBytes: maxBody, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
		if err != nil {
			b.Fatal(err)
		}
		sock := filepath.Join(b.TempDir(), "forwardauth.sock")
		ln, err := net.Listen("unix", sock)
		if err != nil {
			b.Fatal(err)
		}
		srv := &http.Server{Handler: h}
		go func() { _ = srv.Serve(ln) }()
		b.Cleanup(func() { _ = srv.Close() })
		client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}
		for _, c := range cases {
			b.Run(c.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					req, _ := http.NewRequest(http.MethodGet, "http://engine"+forwardauth.Path, strings.NewReader(c.body))
					req.Header.Set("X-Forwarded-Method", c.method)
					req.Header.Set("X-Forwarded-Uri", c.target)
					req.Header.Set("X-Forwarded-Host", "shop.example.com")
					req.Header.Set("X-Forwarded-Proto", "https")
					req.Header.Set("User-Agent", "Mozilla/5.0 inkwall-test")
					req.Header.Set("Accept", "text/html")
					req.Header.Set("X-Request-Id", "envoy-id-1")
					if c.body != "" {
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					}
					resp, err := client.Do(req)
					if err != nil {
						b.Fatal(err)
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
			})
		}
	})
}

// BenchmarkResponses (#369): ext_proc inspecting a response body, as Envoy
// sends it with buffered bodies: the request, then the upstream's response
// headers and body, on one stream. The bodies: a page with a leaked SQL
// error (denied), a benign 15 KiB page, and JSON.
func BenchmarkResponses(b *testing.B) {
	const limit = 64 << 10
	e := newEnvoy(b, newResponsePipeline(b, pipeline.ModeBlock, limit, pipeline.OversizeAuto), limit, io.Discard)
	page := "<html><body>" + strings.Repeat("<p>Our products are made to last.</p>", 400) + "</body></html>"
	cases := []struct{ name, contentType, body string }{
		{"sql_error", "text/html", sqlError},
		{"html_15k", "text/html", page},
		{"json_8k", "application/json", `{"items":[` + strings.Repeat(`{"id":1,"name":"widget","price":9.99},`, 210) + `{"id":0}]}`},
	}
	for _, c := range cases {
		msgs := []*extprocv3.ProcessingRequest{
			withModes(headers("GET", "/products?id=42", true), filterv3.ProcessingMode_BUFFERED, filterv3.ProcessingMode_BUFFERED),
			respHeaders(200, false, "content-type", c.contentType, "content-length", strconv.Itoa(len(c.body))),
			respBody(c.body, true),
		}
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(c.body)))
			for b.Loop() {
				if resps := e.exchange(b, msgs...); len(resps) == 0 {
					b.Fatal("no answer")
				}
			}
		})
	}
}
