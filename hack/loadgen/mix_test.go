// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const cleanHTTP = `GET /products?id=42 HTTP/1.1
Host: shop.example.com
User-Agent: Mozilla/5.0

POST /login HTTP/1.1
Host: shop.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

user=alice&password=pw
`

const attacksHTTP = `GET /?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1
Host: shop.example.com

GET /leak?file=..%2F..%2Fetc%2Fpasswd HTTP/1.1
Host: shop.example.com

`

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestMix runs the mix against a stand-in for a proxy and its app: the
// "WAF" denies the SQL injection and the login, the "app" answers the rest,
// the path traversal too (an attack through).
func TestMix(t *testing.T) {
	var hosts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hosts = append(hosts, r.Host)
		switch {
		case strings.Contains(r.URL.RawQuery, "OR"), r.URL.Path == "/login" && string(body) == "user=alice&password=pw":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.Header().Set("X-App", "1")
			_, _ = io.WriteString(w, "ok")
		}
	}))
	defer srv.Close()
	cfg := mixConfig{base: srv.URL, host: "soak.example.com", appHeader: "X-App", rate: 200, attackEvery: 2, conc: 1,
		report: 150 * time.Millisecond, timeout: time.Second}
	var err error
	if cfg.clean, err = readMix(writeFile(t, "clean.http", cleanHTTP), false); err != nil {
		t.Fatal(err)
	}
	if cfg.attacks, err = readMix(writeFile(t, "attacks.http", attacksHTTP), true); err != nil {
		t.Fatal(err)
	}
	if len(cfg.clean) != 2 || len(cfg.attacks) != 2 {
		t.Fatalf("read %d clean requests and %d attacks, want 2 and 2", len(cfg.clean), len(cfg.attacks))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var out bytes.Buffer
	if err := runMix(ctx, cfg, &out); err != nil {
		t.Fatal(err)
	}

	var total mixReport
	lines := 0
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		var r mixReport
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		lines++
		total.Clean.Sent += r.Clean.Sent
		total.Clean.App += r.Clean.App
		total.Clean.Denied += r.Clean.Denied
		total.Attack.Sent += r.Attack.Sent
		total.Attack.App += r.Attack.App
		total.Attack.Denied += r.Attack.Denied
		total.Clean.Examples = append(total.Clean.Examples, r.Clean.Examples...)
		total.Attack.Examples = append(total.Attack.Examples, r.Attack.Examples...)
		if r.Time == 0 || r.Seconds <= 0 {
			t.Errorf("line %q: no time or length", sc.Text())
		}
	}
	if lines < 3 {
		t.Errorf("%d report lines in 500 ms every 150 ms, want at least 3 (the last one partial)", lines)
	}
	if total.Clean.Sent < 4 || total.Attack.Sent < 4 {
		t.Fatalf("sent %d clean requests and %d attacks, want both", total.Clean.Sent, total.Attack.Sent)
	}
	// Half the clean requests are the login, which the stand-in denies;
	// half the attacks, the traversal, which it lets through.
	if total.Clean.Denied == 0 || total.Clean.App == 0 || total.Clean.Denied+total.Clean.App != total.Clean.Sent {
		t.Errorf("clean: %+v, want both denied (false denials) and answered", total.Clean)
	}
	if total.Attack.App == 0 || total.Attack.Denied == 0 || total.Attack.Denied+total.Attack.App != total.Attack.Sent {
		t.Errorf("attacks: %+v, want both through and denied", total.Attack)
	}
	if !strings.HasPrefix(total.Attack.Examples[0], "GET /leak?") || !strings.HasPrefix(total.Clean.Examples[0], "POST /login") {
		t.Errorf("examples: attacks through %v, clean denied %v", total.Attack.Examples, total.Clean.Examples)
	}
	for _, h := range hosts {
		if h != "soak.example.com" {
			t.Fatalf("Host %q, want -host's", h)
		}
	}
}

// TestMixNoAnswer: a proxy that's down is neither a denial nor an
// attack through.
func TestMixNoAnswer(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()
	cfg := mixConfig{base: base, appHeader: "X-App", rate: 100, attackEvery: 2, conc: 2, report: time.Hour, timeout: time.Second}
	cfg.clean, _ = readMix(writeFile(t, "clean.http", cleanHTTP), false)
	cfg.attacks, _ = readMix(writeFile(t, "attacks.http", attacksHTTP), true)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	var out bytes.Buffer
	if err := runMix(ctx, cfg, &out); err != nil {
		t.Fatal(err)
	}
	var r mixReport
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Attack.App != 0 || r.Clean.Denied != 0 || r.Clean.Other["error"] == 0 || r.Attack.Other["error"] == 0 {
		t.Errorf("report %+v: want only errors", r)
	}
}
