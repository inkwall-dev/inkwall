// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type externalConfig struct {
	timeout     time.Duration
	retries     int
	concurrency int
	backoff     time.Duration // before the first retry, doubled after each
	ignore      []*regexp.Regexp
	client      *http.Client // nil: a client with timeout
}

const userAgent = "Mozilla/5.0 (compatible; inkwall-docscheck; +https://github.com/inkwall-dev/inkwall)"

// readIgnore reads the external check's ignore file: one regular expression
// per line, matched against the URL; blank lines and # comments are skipped.
func readIgnore(file string) ([]*regexp.Regexp, error) {
	f, err := os.Open(filepath.Clean(file))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var res []*regexp.Regexp
	s := bufio.NewScanner(f)
	for n := 1; s.Scan(); n++ {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		re, err := regexp.Compile(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", file, n, err)
		}
		res = append(res, re)
	}
	return res, s.Err()
}

// skipHost reports whether a host can't be checked from CI: local and
// private addresses, single-label names (in-cluster services) and the
// reserved example and test domains (RFC 2606, RFC 6761).
func skipHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()
	}
	if !strings.Contains(host, ".") {
		return true
	}
	for _, d := range []string{"example.com", "example.net", "example.org", "example", "test", "invalid", "localhost", "local", "internal", "svc", "cluster.local"} {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// checkExternal checks the http(s) links of the docs, each URL (without its
// fragment) once. It returns a problem for each place a broken URL is used,
// and the number of URLs checked. URLs still rate limited after the retries
// are logged, not reported: they are not known to be broken.
func checkExternal(docs []*doc, cfg externalConfig, log io.Writer) ([]problem, int) {
	uses := map[string][]problem{}
	for _, d := range docs {
		for _, l := range append(append([]link(nil), d.links...), d.urls...) {
			u, err := url.Parse(l.dest)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || skipHost(u.Hostname()) {
				continue
			}
			u.Fragment, u.RawFragment = "", ""
			key := u.String()
			if ignored(key, cfg.ignore) {
				continue
			}
			p := problem{d.path, l.line, ""}
			if ps := uses[key]; len(ps) > 0 && ps[len(ps)-1].file == p.file && ps[len(ps)-1].line == p.line {
				continue // an inline link's URL is also matched as a bare URL
			}
			uses[key] = append(uses[key], p)
		}
	}
	keys := make([]string, 0, len(uses))
	for k := range uses {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	client := cfg.client
	if client == nil {
		client = &http.Client{Timeout: cfg.timeout}
	}
	type result struct {
		err         error
		rateLimited bool
	}
	results := make([]result, len(keys))
	sem := make(chan struct{}, max(cfg.concurrency, 1))
	var wg sync.WaitGroup
	for i, k := range keys {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			limited, err := checkURL(client, k, cfg)
			results[i] = result{err, limited}
		}()
	}
	wg.Wait()

	var probs []problem
	for i, k := range keys {
		switch r := results[i]; {
		case r.err == nil:
		case r.rateLimited:
			fmt.Fprintf(log, "docscheck: warning: %s: %v\n", k, r.err)
		default:
			for _, p := range uses[k] {
				p.msg = fmt.Sprintf("broken external link %s: %v", k, r.err)
				probs = append(probs, p)
			}
		}
	}
	return probs, len(keys)
}

func ignored(u string, ignore []*regexp.Regexp) bool {
	for _, re := range ignore {
		if re.MatchString(u) {
			return true
		}
	}
	return false
}

// checkURL fetches a URL until it answers 2xx or fails for good. HEAD is
// tried first, then GET if HEAD got an answer other than 2xx, since some
// servers mishandle HEAD. Network errors, 429 and 5xx are retried with
// exponential backoff (429 honouring Retry-After up to a minute); other
// statuses fail at once. limited says the last failure was a 429.
func checkURL(client *http.Client, u string, cfg externalConfig) (limited bool, err error) {
	wait := cfg.backoff
	for attempt := 0; ; attempt++ {
		var status int
		var retryAfter time.Duration
		for _, method := range []string{http.MethodHead, http.MethodGet} {
			status, retryAfter, err = fetch(client, method, u)
			if err != nil {
				break // GET won't reach a host HEAD can't
			}
			if status >= 200 && status < 300 {
				return false, nil
			}
		}
		retryable := err != nil || status == http.StatusTooManyRequests || status >= 500
		if err == nil {
			err = fmt.Errorf("HTTP %d %s", status, http.StatusText(status))
		}
		limited = status == http.StatusTooManyRequests
		if !retryable || attempt >= cfg.retries {
			return limited, err
		}
		d := wait
		if retryAfter > d {
			d = min(retryAfter, time.Minute)
		}
		time.Sleep(d)
		wait *= 2
	}
}

func fetch(client *http.Client, method, u string) (status int, retryAfter time.Duration, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout+time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u, http.NoBody)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
		retryAfter = time.Duration(s) * time.Second
	}
	return resp.StatusCode, retryAfter, nil
}
