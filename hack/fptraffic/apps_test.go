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
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeApps answers what the sessions of gitea, wordpress and directus
// need (a page with the nonces and IDs they read, a login that redirects,
// tokens), and 200 {} to the rest.
func fakeApps(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	var (
		mu  sync.Mutex
		got int
	)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		got++
		mu.Unlock()
		p := r.URL.Path
		reply := func(status int, body string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
		switch {
		case strings.HasSuffix(p, "/tokens"):
			reply(http.StatusCreated, `{"sha1":"0123456789abcdef"}`)
		case p == "/wp-login.php" && r.Method == http.MethodPost:
			http.SetCookie(w, &http.Cookie{Name: "wordpress_logged_in_x", Value: "alice|1795228364|tok|hash"})
			w.Header().Set("Location", srv.URL+"/wp-admin/")
			w.WriteHeader(http.StatusFound)
		case p == "/auth/login":
			reply(http.StatusOK, `{"data":{"access_token":"access.tok.en","refresh_token":"refresh"}}`)
		case p == "/wp-json/wp/v2/posts" || strings.HasPrefix(p, "/wp-json/wp/v2/categories"):
			reply(http.StatusOK, `[{"id":3,"link":"`+srv.URL+`/hello/"}]`)
		case strings.HasPrefix(p, "/wp-json/wp/v2/media"):
			reply(http.StatusCreated, `{"id":12,"source_url":"`+srv.URL+`/wp-content/uploads/a.png"}`)
		case strings.HasPrefix(p, "/wp-json/"), strings.HasPrefix(p, "/api/"), strings.HasPrefix(p, "/items/"),
			strings.HasPrefix(p, "/files"), p == "/graphql", strings.HasPrefix(p, "/policies"), strings.HasPrefix(p, "/roles"):
			reply(http.StatusOK, `{"id":5,"number":1,"sha":"abc","data":{"id":5}}`)
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<link rel="stylesheet" href="/style.css?ver=1"><script src="`+srv.URL+`/app.js"></script>
<input name="uid" value="1"><input name="_wpnonce" value="abc123"><input name="_wpnonce_create-user" value="abc123">
<input name="post_ID" value="4"><script>heartbeatSettings = {"nonce":"abc123"}; wp.apiFetch.createNonceMiddleware( "abc123" );
wp.editPost.initializeEditor( 'editor', "post", 4, {});</script><a href="/wp-login.php?action=logout&#038;_wpnonce=abc123">Log Out</a>
<input name="_ajax_nonce-replyto-comment" value="abc123"><a href="comment.php?action=approvecomment&#038;c=5&#038;_wpnonce=abc123">Approve</a>`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestApps(t *testing.T) {
	for _, name := range []string{"gitea", "wordpress", "directus"} {
		t.Run(name, func(t *testing.T) {
			srv, got := fakeApps(t)
			a := apps[name]
			r, err := newRecorder(srv.URL, a.public, 1)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.play(a, a.sessions); err != nil {
				t.Fatal(err)
			}
			entries := r.har.Log.Entries
			setup := 0
			if a.setup != nil {
				setup = 2 // wordpress's installation: sent, not recorded
			}
			if len(entries)+setup != *got || len(entries) < 100 {
				t.Fatalf("%d entries for %d requests sent (%d of them the setup's), want them all, at least 100", len(entries), *got, setup)
			}
			b, err := json.Marshal(r.har)
			if err != nil {
				t.Fatal(err)
			}
			host := strings.TrimPrefix(srv.URL, "http://")
			if strings.Contains(string(b), host) {
				t.Errorf("the HAR has the target's address %s: want the public one's only", host)
			}
			methods := map[string]bool{}
			for i, e := range entries {
				q := e.Request
				methods[q.Method] = true
				if !strings.HasPrefix(q.URL, a.public+"/") {
					t.Errorf("entry %d: URL %q, want the public origin", i, q.URL)
				}
				h := map[string]string{}
				for _, nv := range q.Headers {
					h[nv.Name] = nv.Value
				}
				if h["User-Agent"] == "" || h["Accept"] == "" {
					t.Errorf("entry %d: %s %s lacks a User-Agent or Accept: %v", i, q.Method, q.URL, h)
				}
				if (q.PostData != nil) != (q.BodySize > 0) {
					t.Errorf("entry %d: postData %v, bodySize %d", i, q.PostData, q.BodySize)
				}
			}
			if !methods[http.MethodGet] || !methods[http.MethodPost] {
				t.Errorf("methods %v: want GET and POST", methods)
			}
		})
	}
}

// TestRecordedHAR checks the HARs in the repository: requests only, every
// one with an absolute URL of the application's public origin and its
// status, nothing of the address the recording was made at.
func TestRecordedHAR(t *testing.T) {
	for name, want := range map[string]struct {
		min     int
		methods []string
	}{
		"juice-shop": {400, []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete}},
		"gitea":      {300, []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}},
		"wordpress":  {600, []string{http.MethodGet, http.MethodPost}},
		"directus":   {140, []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete}},
	} {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(name + ".har.gz")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			zr, err := gzip.NewReader(f)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(zr)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "127.0.0.1") {
				t.Error("the HAR has the recording's address, 127.0.0.1")
			}
			var doc harFile
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			if n := len(doc.Log.Entries); n < want.min {
				t.Fatalf("%d requests, want the recording's (over %d)", n, want.min)
			}
			methods := map[string]int{}
			for i, e := range doc.Log.Entries {
				methods[e.Request.Method]++
				if !strings.HasPrefix(e.Request.URL, apps[name].public+"/") || e.Response.Status == 0 {
					t.Errorf("entry %d: %s, status %d", i, e.Request.URL, e.Response.Status)
				}
			}
			for _, m := range want.methods {
				if methods[m] == 0 {
					t.Errorf("no %s request: %v", m, methods)
				}
			}
			for m := range methods {
				if !slices.Contains(want.methods, m) {
					t.Errorf("%d %s requests: want only %v", methods[m], m, want.methods)
				}
			}
		})
	}
}
