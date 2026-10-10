// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
)

// corpusEntry is one kind of request in the benchmark corpus.
type corpusEntry struct {
	// class names the entry in the report.
	class string
	// weight is how often the entry is sent relative to the others.
	weight int
	// expect is the verdict a correct engine in block mode gives: "allow",
	// "deny", or "" when unknown (user-supplied corpora).
	expect string
	req    *enginev1.CheckRequest
}

// defaultCorpus is the fixed request mix of 0001 §8: mostly benign traffic of
// the shapes that dominate inspection cost (header-only, form and JSON
// bodies by argument count), plus CRS attack payloads. Changing it changes
// every number measured with it, so it is versioned with the code.
func defaultCorpus() []corpusEntry {
	browser := func(method, uri string) *enginev1.CheckRequest {
		return &enginev1.CheckRequest{
			Method:    method,
			Scheme:    "https",
			Authority: "shop.example.com",
			RawUri:    uri,
			ClientIp:  "203.0.113.7",
			Protocol:  "HTTP/1.1",
			Headers: []*enginev1.Header{
				{Name: "User-Agent", Value: "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"},
				{Name: "Accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
				{Name: "Accept-Language", Value: "en-US,en;q=0.5"},
				{Name: "Accept-Encoding", Value: "gzip, deflate, br"},
				{Name: "Cookie", Value: "session=8f14e45fceea167a5a36dedd4bea2543; theme=dark"},
			},
		}
	}
	withBody := func(r *enginev1.CheckRequest, contentType, body string) *enginev1.CheckRequest {
		r.Body = []byte(body)
		r.Headers = append(r.Headers,
			&enginev1.Header{Name: "Content-Type", Value: contentType},
			&enginev1.Header{Name: "Content-Length", Value: strconv.Itoa(len(body))},
		)
		return r
	}
	form := func(n int) string {
		v := url.Values{}
		for i := range n {
			v.Set(fmt.Sprintf("field%d", i), fmt.Sprintf("value number %d", i))
		}
		return v.Encode()
	}
	jsonObject := func(n int) string {
		var b strings.Builder
		b.WriteByte('{')
		for i := range n {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"field%d":"value number %d"`, i, i)
		}
		b.WriteByte('}')
		return b.String()
	}
	const formType, jsonType = "application/x-www-form-urlencoded", "application/json"

	return []corpusEntry{
		{"benign-get", 40, "allow", browser("GET", "/products/42")},
		{"benign-get-query", 20, "allow", browser("GET", "/search?q=running+shoes&size=42&sort=price&page=2")},
		{"benign-form-2", 10, "allow", withBody(browser("POST", "/login"), formType, "user=alice&password=correct+horse")},
		{"benign-form-10", 5, "allow", withBody(browser("POST", "/checkout"), formType, form(10))},
		{"benign-json-10", 8, "allow", withBody(browser("POST", "/api/cart"), jsonType, jsonObject(10))},
		{"benign-json-50", 2, "allow", withBody(browser("POST", "/api/profile"), jsonType, jsonObject(50))},
		{"attack-sqli", 3, "deny", browser("GET", "/products?id=1%27%20OR%20%271%27%3D%271")},
		{"attack-xss", 3, "deny", browser("GET", "/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E")},
		{"attack-traversal", 3, "deny", browser("GET", "/download?file=../../../../etc/passwd")},
		{"attack-rce-form", 3, "deny", withBody(browser("POST", "/ping"), formType, "host=127.0.0.1%3Bcat+%2Fetc%2Fpasswd")},
		{"attack-xss-json", 3, "deny", withBody(browser("POST", "/api/notes"), jsonType, `{"note":"<img src=x onerror=alert(1)>"}`)},
	}
}

// userCorpus wraps requests loaded from --request or --har.
func userCorpus(reqs []*enginev1.CheckRequest) []corpusEntry {
	out := make([]corpusEntry, len(reqs))
	for i, r := range reqs {
		out[i] = corpusEntry{class: fmt.Sprintf("%d %s %s", i+1, r.GetMethod(), truncate(r.GetRawUri(), 40)), weight: 1, req: r}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
