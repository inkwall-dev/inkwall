// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// fakeShop answers what a session needs (a login with a token and a
// basket, IDs of created objects) and 200 {} to the rest, and keeps the
// requests it got.
func fakeShop(t *testing.T) (*httptest.Server, *[]*http.Request) {
	t.Helper()
	var (
		mu  sync.Mutex
		got []*http.Request
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		got = append(got, r)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<link rel="stylesheet" href="styles.css"><script src="main.js"></script><script src="https://cdn.example/x.js"></script>`)
		case r.URL.Path == "/rest/user/login":
			_, _ = io.WriteString(w, `{"authentication":{"token":"tok.en.x","bid":7}}`)
		case r.URL.Path == "/rest/user/whoami":
			_, _ = io.WriteString(w, `{"user":{"id":3,"email":"a@example.com"}}`)
		case r.URL.Path == "/rest/captcha/":
			_, _ = io.WriteString(w, `{"captchaId":1,"captcha":"1+1","answer":"2"}`)
		case strings.HasSuffix(r.URL.Path, "/checkout"):
			_, _ = io.WriteString(w, `{"orderConfirmation":"abcd-1234"}`)
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"status":"success","data":{"id":5}}`)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestSession(t *testing.T) {
	srv, got := fakeShop(t)
	r, err := newRecorder(srv.URL, "https://shop.example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.session(0); err != nil {
		t.Fatal(err)
	}
	entries := r.har.Log.Entries
	if len(entries) != len(*got) || len(entries) < 50 {
		t.Fatalf("%d entries for %d requests sent, want the same, at least 50", len(entries), len(*got))
	}
	sawAuth, sawUpload, sawCSS := false, false, false
	for i, e := range entries {
		q := e.Request
		if !strings.HasPrefix(q.URL, "https://shop.example.com/") {
			t.Errorf("entry %d: URL %q, want the public origin", i, q.URL)
		}
		if q.URL == "https://cdn.example/x.js" || strings.Contains(q.URL, "cdn.example") {
			t.Errorf("entry %d: an asset of another origin was fetched", i)
		}
		if e.Response.Status == 0 {
			t.Errorf("entry %d: no status", i)
		}
		h := map[string]string{}
		for _, nv := range q.Headers {
			h[nv.Name] = nv.Value
		}
		if h["User-Agent"] == "" || h["Accept"] == "" || h["Accept-Language"] == "" {
			t.Errorf("entry %d: %s %s lacks a browser's headers: %v", i, q.Method, q.URL, h)
		}
		if strings.Contains(h["Referer"], "#") {
			t.Errorf("entry %d: Referer %q has a fragment, which browsers leave out", i, h["Referer"])
		}
		if (q.PostData != nil) != (q.BodySize > 0) {
			t.Errorf("entry %d: postData %v, bodySize %d", i, q.PostData, q.BodySize)
		}
		if q.Method != http.MethodGet && q.Method != http.MethodHead && h["Origin"] != "https://shop.example.com" {
			t.Errorf("entry %d: %s without the Origin header", i, q.Method)
		}
		sawAuth = sawAuth || h["Authorization"] == "Bearer tok.en.x"
		sawUpload = sawUpload || strings.HasPrefix(h["Content-Type"], "multipart/form-data; boundary=")
		sawCSS = sawCSS || strings.HasSuffix(q.URL, "/styles.css")
	}
	if !sawAuth || !sawUpload || !sawCSS {
		t.Errorf("authorized API call %v, upload %v, the page's stylesheet %v: want all", sawAuth, sawUpload, sawCSS)
	}
}

// TestRecordedHAR checks the HAR in the repository: requests only, every
// one with an absolute URL and its status.
func TestRecordedHAR(t *testing.T) {
	f, err := os.Open("juice-shop.har.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var doc harFile
	if err := json.NewDecoder(zr).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if n := len(doc.Log.Entries); n < 400 {
		t.Fatalf("%d requests, want the recording's (over 400)", n)
	}
	methods := map[string]int{}
	for i, e := range doc.Log.Entries {
		methods[e.Request.Method]++
		if !strings.HasPrefix(e.Request.URL, "https://shop.example.com/") || e.Response.Status == 0 {
			t.Errorf("entry %d: %s, status %d", i, e.Request.URL, e.Response.Status)
		}
	}
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
		if methods[m] == 0 {
			t.Errorf("no %s request: %v", m, methods)
		}
	}
}

func TestI18nFile(t *testing.T) {
	for lang, want := range map[string]string{
		"en-US,en;q=0.9": "en.json", "de-DE,de;q=0.8": "de_DE.json", "pt-BR,pt;q=0.9": "pt_BR.json",
	} {
		if got := i18nFile(lang); got != want {
			t.Errorf("i18nFile(%q) = %q, want %q", lang, got, want)
		}
	}
}
