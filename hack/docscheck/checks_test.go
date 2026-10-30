// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"
)

func file(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }

func check(t *testing.T, fsys fstest.MapFS, cfg config) []string {
	t.Helper()
	var files []string
	for p := range fsys {
		if isMarkdown(p) && !strings.Contains(p, "testdata/") {
			files = append(files, p)
		}
	}
	if cfg.index == "" {
		cfg.index = "docs/README.md"
	}
	var out, log bytes.Buffer
	sort.Strings(files)
	run(fsys, files, cfg, &out, &log)
	if out.Len() == 0 {
		return nil
	}
	return strings.Split(strings.TrimSpace(out.String()), "\n")
}

func TestLinks(t *testing.T) {
	fsys := fstest.MapFS{
		"README.md": file(`# Inkwall
[ok](docs/guide.md) [ok anchor](docs/guide.md#set-it-up) [ok dir](pkg)
[missing](docs/nope.md) [bad anchor](docs/guide.md#nope)
[root](/docs/guide.md#explicit) [code line](pkg/a.go#L10-L20) [code anchor](pkg/a.go#main)
[escape](../outside.md) [same](#inkwall) [same bad](#inkwal) [top](#top)
[web](https://example.org) [mail](mailto:a@example.org)
[undefined][nowhere]
`),
		"docs/guide.md": file(`# Guide
## Set it up
<a name="explicit"></a>
[back](../README.md#inkwall) [encoded](../README.md#%69nkwall)
`),
		"pkg/a.go": file("package a\n"),
	}
	got := check(t, fsys, config{})
	want := []string{
		`README.md:3: broken link "docs/nope.md": docs/nope.md does not exist`,
		`README.md:3: broken anchor "docs/guide.md#nope": docs/guide.md has no heading or id "nope"`,
		`README.md:4: broken anchor "pkg/a.go#main": only Markdown files have anchors, and other files line ones (#L10, #L10-L20)`,
		`README.md:5: link "../outside.md" points outside the repository`,
		`README.md:5: broken anchor "#inkwal": README.md has no heading or id "inkwal"`,
		`README.md:7: reference link [nowhere] has no definition ([nowhere]: url)`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

const longDoc = `# Doc

Intro.

## Contents

- [B](#b)
- [A](#a)
  - [A one](#a-one)
- [A](#a)
- [Deep](#deep)
- [Elsewhere](other.md)
- [Anchor](#custom)

## A
### A one
#### Deep
## B
<a id="custom"></a>
## C
`

func TestContents(t *testing.T) {
	got := check(t, fstest.MapFS{"doc.md": file(longDoc), "other.md": file("# Other\n")}, config{})
	want := []string{
		`doc.md:5: Contents does not list section "C" (#c, line 20)`,
		`doc.md:8: Contents lists #a after #b, but the doc has it before`,
		`doc.md:10: Contents lists #a twice`,
		`doc.md:11: Contents links to #deep, which is not a ## or ### section after Contents`,
		`doc.md:12: Contents links to "other.md"; it should only link to sections of this doc`,
		`doc.md:13: Contents links to #custom, which is not a ## or ### section after Contents`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestContentsGood(t *testing.T) {
	doc := "# Doc\n\nIntro.\n\n## Contents\n\n- [A](#a)\n  - [A one](#a-one)\n- [B](#b)\n\n## A\n### A one\n### A two\n## B\n"
	if got := check(t, fstest.MapFS{"doc.md": file(doc)}, config{}); got != nil {
		t.Errorf("problems: %q", got)
	}
}

func TestContentsStrict(t *testing.T) {
	fsys := fstest.MapFS{
		"long.md":   file("# Long\n" + strings.Repeat("text\n", 10)),
		"exempt.md": file("# Exempt\n" + strings.Repeat("text\n", 10)),
		"short.md":  file("# Short\ntext\n"),
		"late.md":   file("# Late\n\n## Intro\n\n## Contents\n\n- [B](#b)\n\n## B\n"),
	}
	cfg := config{contentsMinLines: 5, contentsExempt: map[string]bool{"exempt.md": true}}
	want := []string{
		`late.md:3: section "Intro" comes before ## Contents; Contents should be the first section`,
		`long.md: 11 lines long but has no ## Contents section (required above 5 lines)`,
	}
	if got := check(t, fsys, cfg); !reflect.DeepEqual(got, want) {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	cfg.contentsMinLines = 0
	if got := check(t, fsys, cfg); len(got) != 1 {
		t.Errorf("without -contents-min-lines: %q, want only the late Contents", got)
	}
}

func TestIndex(t *testing.T) {
	fsys := fstest.MapFS{
		"README.md":             file("# R\n"),
		"CLAUDE.md":             file("# C\n"),
		"docs/a.md":             file("# A\n"),
		"docs/b.md":             file("# B\n"),
		"docs/design/README.md": file("# D\n"),
		"pkg/testdata/x.md":     file("# X\n"),
	}
	cfg := config{indexExempt: map[string]bool{"CLAUDE.md": true}}
	if got := check(t, fsys, cfg); got != nil {
		t.Errorf("no index: %q, want no problems", got)
	}
	cfg.requireIndex = true
	if got := check(t, fsys, cfg); !reflect.DeepEqual(got, []string{"docs/README.md: the docs index does not exist"}) {
		t.Errorf("required index missing: %q", got)
	}
	fsys["docs/README.md"] = file("# Docs\n- [Readme](../README.md)\n- [A](a.md#a)\n- [Design](design/)\n")
	want := []string{"docs/README.md: the docs index does not list docs/b.md"}
	if got := check(t, fsys, cfg); !reflect.DeepEqual(got, want) {
		t.Errorf("problems: %q, want %q", got, want)
	}
}

func TestSkipHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost": true, "127.0.0.1": true, "10.1.2.3": true, "::1": true,
		"app": true, "shop.example.com": true, "example.org": true, "x.test": true,
		"svc.ns.svc.cluster.local": true, "github.com": false, "helm.sh": false, "8.8.8.8": false,
	} {
		if got := skipHost(host); got != want {
			t.Errorf("skipHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestExternal(t *testing.T) {
	var flaky, limited atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
		case "/get-only":
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		case "/flaky":
			if flaky.Add(1) <= 2 {
				w.WriteHeader(http.StatusBadGateway)
			}
		case "/limited":
			limited.Add(1)
			w.WriteHeader(http.StatusTooManyRequests)
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	// httptest listens on 127.0.0.1, which the check skips: use a public
	// looking name and dial the server whatever the name.
	addr := srv.Listener.Addr().String()
	base := "http://links.docscheck.dev"
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}

	d := parse("doc.md", fmt.Sprintf(`# Doc
[ok](%[1]s/ok#frag) %[1]s/ok and [again](%[1]s/ok)
[get](%[1]s/get-only) [flaky](%[1]s/flaky) [redirect](%[1]s/redirect)
[gone](%[1]s/gone) [limited](%[1]s/limited) [ignored](%[1]s/ignored/x)
[local](http://localhost:8080/x) [svc](http://app:80/)
`, base))
	cfg := externalConfig{retries: 2, concurrency: 4, backoff: time.Millisecond, client: client,
		ignore: []*regexp.Regexp{regexp.MustCompile(`/ignored/`)}}
	var log bytes.Buffer
	probs, n := checkExternal([]*doc{d}, cfg, &log)
	if n != 6 {
		t.Errorf("checked %d URLs, want 6", n)
	}
	if len(probs) != 1 || probs[0].line != 4 || !strings.Contains(probs[0].msg, "/gone: HTTP 404") {
		t.Errorf("problems = %v, want the 404 on line 4", probs)
	}
	if !strings.Contains(log.String(), "/limited: HTTP 429") || limited.Load() != 6 {
		t.Errorf("rate limited: log %q after %d requests, want a warning after 3 HEAD+GET tries", log.String(), limited.Load())
	}
}
