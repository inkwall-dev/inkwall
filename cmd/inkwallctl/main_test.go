// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	"github.com/inkwall-dev/inkwall/pkg/adapters/httpcheck"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

const sqli = "/?id=1%27%20OR%20%271%27%3D%271"

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSplitURL(t *testing.T) {
	for _, tc := range []struct{ in, scheme, authority, uri string }{
		{"http://a.example", "http", "a.example", "/"},
		{"HTTPS://a.example:8443/x/y?q=1", "https", "a.example:8443", "/x/y?q=1"},
		{"http://a.example?q=1", "http", "a.example", "/?q=1"},
		// Kept byte for byte: no decoding or re-encoding of the payload.
		{"http://a" + sqli, "http", "a", sqli},
		{"http://a/%zz/../etc/passwd", "http", "a", "/%zz/../etc/passwd"},
		{"http://a/p#frag", "http", "a", "/p"},
	} {
		scheme, authority, uri, err := splitURL(tc.in)
		if err != nil || scheme != tc.scheme || authority != tc.authority || uri != tc.uri {
			t.Errorf("splitURL(%q) = %q %q %q %v, want %q %q %q", tc.in, scheme, authority, uri, err, tc.scheme, tc.authority, tc.uri)
		}
	}
	for _, in := range []string{"a.example/x", "ftp://a/x", "http:///x"} {
		if _, _, _, err := splitURL(in); err == nil {
			t.Errorf("splitURL(%q) accepted", in)
		}
	}
}

func TestCommandLineRequest(t *testing.T) {
	body := writeFile(t, "body.json", `{"a":1}`)
	cfg, err := parseTestFlags([]string{"-X", "PUT", "-H", "Content-Type: application/json", "-H", "Host: shop.example.com",
		"-d", "@" + body, "http://localhost/api"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	in, err := fromCommandLine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if in.GetMethod() != "PUT" || in.GetAuthority() != "shop.example.com" || string(in.GetBody()) != `{"a":1}` {
		t.Fatalf("request: %v", in)
	}
	got := map[string]string{}
	for _, h := range in.GetHeaders() {
		got[h.GetName()] = h.GetValue()
	}
	if got["Content-Type"] != "application/json" || got["Content-Length"] != "7" || got["User-Agent"] == "" || got["Host"] != "" {
		t.Fatalf("headers: %v", got)
	}

	cfg, _ = parseTestFlags([]string{"-d", "a=1", "http://localhost/"}, io.Discard)
	if in, _ := fromCommandLine(cfg); in.GetMethod() != "POST" {
		t.Fatalf("-d without -X: method %s, want POST", in.GetMethod())
	}
}

func TestRawHTTPRequests(t *testing.T) {
	raw := "GET /search?q=shoes HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: test\r\n\r\n" +
		"\r\n" +
		"POST http://api.example.com/upload HTTP/1.1\r\nHost: ignored\r\nTransfer-Encoding: chunked\r\n" +
		"Content-Type: text/plain\r\nX-Bin: caf\xe9\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
	reqs, err := fromRawHTTP(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 {
		t.Fatalf("got %d requests, want 2", len(reqs))
	}
	if r := reqs[0]; r.GetMethod() != "GET" || r.GetAuthority() != "shop.example.com" || r.GetRawUri() != "/search?q=shoes" || r.GetBody() != nil {
		t.Errorf("first request: %v", r)
	}
	r := reqs[1]
	if r.GetAuthority() != "api.example.com" || r.GetRawUri() != "/upload" || string(r.GetBody()) != "hello" {
		t.Errorf("second request: %v", r)
	}
	var te, bin *enginev1.Header
	for _, h := range r.GetHeaders() {
		switch h.GetName() {
		case "Transfer-Encoding":
			te = h
		case "X-Bin":
			bin = h
		}
	}
	if te.GetValue() != "chunked" {
		t.Errorf("Transfer-Encoding not restored: %v", te)
	}
	if string(bin.GetRawValue()) != "caf\xe9" {
		t.Errorf("non-UTF-8 header not sent as raw_value: %v", bin)
	}

	if _, err := fromRawHTTP(strings.NewReader("\r\n")); err == nil {
		t.Error("empty file accepted")
	}
	if _, err := fromRawHTTP(strings.NewReader("not http\r\n\r\n")); err == nil {
		t.Error("garbage accepted")
	}
}

const harDoc = `{"log":{"entries":[
 {"request":{"method":"GET","url":"https://shop.example.com/p?id=1","httpVersion":"h2",
   "headers":[{"name":":authority","value":"shop.example.com"},{"name":"user-agent","value":"Mozilla/5.0"},{"name":"accept","value":"*/*"}]}},
 {"request":{"method":"POST","url":"https://shop.example.com/api/notes","httpVersion":"HTTP/1.1",
   "headers":[{"name":"Content-Type","value":"application/json"},{"name":"User-Agent","value":"Mozilla/5.0"},{"name":"Accept","value":"*/*"}],
   "postData":{"mimeType":"application/json","text":"eyJub3RlIjoiPHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0PiJ9","encoding":"base64"}}}
]}}`

func TestHAR(t *testing.T) {
	reqs, err := fromHAR([]byte(harDoc))
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 {
		t.Fatalf("got %d requests, want 2", len(reqs))
	}
	if r := reqs[0]; r.GetProtocol() != "HTTP/2.0" || r.GetScheme() != "https" || len(r.GetHeaders()) != 2 {
		t.Errorf("first entry: %v", r)
	}
	if got := string(reqs[1].GetBody()); got != `{"note":"<script>alert(1)</script>"}` {
		t.Errorf("base64 body decoded to %q", got)
	}
	if _, err := fromHAR([]byte(`{"log":{"entries":[]}}`)); err == nil {
		t.Error("empty HAR accepted")
	}
}

func TestRunInProcess(t *testing.T) {
	code, out, _ := runCLI(t, "test", "http://shop.example.com"+sqli)
	if code != 0 || !strings.HasPrefix(out, "deny  403  GET "+sqli) || !strings.Contains(out, "942100") {
		t.Fatalf("sqli: exit %d, output %q", code, out)
	}

	code, out, _ = runCLI(t, "test", "--mode", "detect", "http://shop.example.com"+sqli)
	if code != 0 || !strings.HasPrefix(out, "log ") {
		t.Fatalf("detect mode: exit %d, output %q", code, out)
	}

	code, out, _ = runCLI(t, "test", "--json", "http://shop.example.com/")
	if code != 0 || !strings.Contains(out, `"action":"ACTION_ALLOW"`) {
		t.Fatalf("--json: exit %d, output %q", code, out)
	}

	// A rule file is loaded like the engine's --rules.
	rules := writeFile(t, "rules.conf", `SecRule REQUEST_HEADERS:X-Debug "@streq on" "id:100001,phase:1,deny,status:418"`)
	code, out, _ = runCLI(t, "test", "--rules", rules, "-H", "X-Debug: on", "http://shop.example.com/")
	if code != 0 || !strings.HasPrefix(out, "deny  418") || !strings.Contains(out, "interrupting=100001") {
		t.Fatalf("--rules: exit %d, output %q", code, out)
	}
}

func TestRunFilesAndExpect(t *testing.T) {
	har := writeFile(t, "traffic.har", harDoc)
	code, out, errOut := runCLI(t, "test", "--expect", "allow", "--har", har)
	if code != 1 || strings.Count(out, "\n") != 2 || !strings.Contains(errOut, "1 of 2") {
		t.Fatalf("--expect allow on one attack: exit %d, output %q %q", code, out, errOut)
	}

	raw := writeFile(t, "req.http", "GET "+sqli+" HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: t\r\nAccept: */*\r\n\r\n")
	if code, out, _ := runCLI(t, "test", "--expect", "deny", "--request", raw); code != 0 {
		t.Fatalf("--expect deny on an attack: exit %d, output %q", code, out)
	}
}

func TestRunUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"lint"},
		{"test"},
		{"test", "http://a/", "http://b/"},
		{"test", "--har", "x.har", "http://a/"},
		{"test", "-H", "X: y", "--har", "x.har"},
		{"test", "--mode", "off", "http://a/"},
		{"test", "--expect", "log", "http://a/"},
		{"test", "--disable-rule-groups", "cobol", "http://a/"},
		{"test", "--engine", "localhost:9002", "http://a/"},
		{"test", "--request", "/nonexistent", "http://a/"},
		{"test", "-H", "no colon", "http://a/"},
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

// engineHandler is what inkwall-engine check serves.
func engineHandler(t *testing.T) http.Handler {
	t.Helper()
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	h, err := httpcheck.New(
		pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 5 * time.Second}),
		httpcheck.Config{MaxBodyBytes: 64 << 10, Logger: slog.New(slog.DiscardHandler)},
	)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestRunAgainstEngine(t *testing.T) {
	srv := httptest.NewServer(engineHandler(t))
	t.Cleanup(srv.Close)
	code, out, errOut := runCLI(t, "test", "--engine", srv.URL, "--expect", "deny", "http://shop.example.com"+sqli)
	if code != 0 || !strings.HasPrefix(out, "deny  403") {
		t.Fatalf("TCP engine: exit %d, output %q %q", code, out, errOut)
	}

	sock := filepath.Join(t.TempDir(), "e.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	unixSrv := &http.Server{Handler: engineHandler(t), ReadHeaderTimeout: time.Second}
	go func() { _ = unixSrv.Serve(ln) }()
	t.Cleanup(func() { _ = unixSrv.Close() })
	code, out, errOut = runCLI(t, "test", "--engine", "unix:"+sock, "http://shop.example.com/")
	if code != 0 || !strings.HasPrefix(out, "allow") {
		t.Fatalf("unix engine: exit %d, output %q %q", code, out, errOut)
	}

	// An engine that is not there is an error, not a verdict.
	srv.Close()
	if code, _, _ := runCLI(t, "test", "--engine", srv.URL, "http://shop.example.com/"); code != 2 {
		t.Fatalf("unreachable engine: exit %d, want 2", code)
	}
}
