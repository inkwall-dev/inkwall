// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// The mix mode (#600, the soak test): clean requests and attacks, read from
// files of raw HTTP requests (as inkwallctl test --request reads them), sent
// at a steady rate, open loop, for a while or until stopped. Each answer is
// sorted by who gave it: the app (it carries -app-header), the WAF (403
// without it), or something else (another status, or no answer). Every
// -report, it prints one JSON line of the window's counts: an attack the app
// answered got through; a clean request the WAF denied is a false denial.

// mixRequest is one request of a mix file.
type mixRequest struct {
	attack bool
	method string
	uri    string
	header http.Header
	body   []byte
}

func (m mixRequest) name() string { return m.method + " " + m.uri }

// readMix reads raw HTTP/1.x requests, separated by blank lines.
func readMix(path string, attack bool) ([]mixRequest, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the request file the caller names
	if err != nil {
		return nil, err
	}
	br := bufio.NewReader(bytes.NewReader(b))
	var out []mixRequest
	for {
		for {
			c, err := br.Peek(1)
			if err != nil || (c[0] != '\r' && c[0] != '\n') {
				break
			}
			_, _ = br.ReadByte()
		}
		if _, err := br.Peek(1); errors.Is(err, io.EOF) {
			break
		}
		req, err := http.ReadRequest(br)
		if err != nil {
			return nil, fmt.Errorf("%s: request %d: %w", path, len(out)+1, err)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("%s: request %d body: %w", path, len(out)+1, err)
		}
		out = append(out, mixRequest{attack: attack, method: req.Method, uri: req.RequestURI, header: req.Header, body: body})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no request", path)
	}
	return out, nil
}

// classCounts are a window's answers to one class of requests.
type classCounts struct {
	Sent int `json:"sent"`
	// App: the app answered (an attack that got through).
	App int `json:"app"`
	// Denied: 403 without the app's header, the WAF's.
	Denied int `json:"denied"`
	// Other answers, by status ("error": no answer).
	Other map[string]int `json:"other,omitempty"`
	// Examples of requests the app answered (attacks) or the WAF denied
	// (clean), up to 5.
	Examples []string `json:"examples,omitempty"`
}

// mixReport is one window's line.
type mixReport struct {
	// Time is the end of the window, in Unix seconds.
	Time    int64       `json:"time"`
	Seconds float64     `json:"seconds"`
	Clean   classCounts `json:"clean"`
	Attack  classCounts `json:"attack"`
	// Skipped: sends due while -c requests were already in flight.
	Skipped int `json:"skipped"`
	// The latency of the clean requests the app answered.
	P50ms float64 `json:"p50ms"`
	P99ms float64 `json:"p99ms"`
}

type mixConfig struct {
	base, host, appHeader string
	clean, attacks        []mixRequest
	rate                  float64
	attackEvery           int
	conc                  int
	report                time.Duration
	timeout               time.Duration
}

// window collects the answers of one report window.
type window struct {
	mu    sync.Mutex
	start time.Time
	rep   mixReport
	lat   []time.Duration
}

func (w *window) add(r mixRequest, code int, app bool, d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	c := &w.rep.Clean
	if r.attack {
		c = &w.rep.Attack
	}
	c.Sent++
	switch {
	case app:
		c.App++
		if r.attack && len(c.Examples) < 5 {
			c.Examples = append(c.Examples, r.name())
		}
		if !r.attack {
			w.lat = append(w.lat, d)
		}
	case code == http.StatusForbidden:
		c.Denied++
		if !r.attack && len(c.Examples) < 5 {
			c.Examples = append(c.Examples, r.name())
		}
	default:
		if c.Other == nil {
			c.Other = map[string]int{}
		}
		k := "error"
		if code != 0 {
			k = fmt.Sprint(code)
		}
		c.Other[k]++
	}
}

func (w *window) skip() {
	w.mu.Lock()
	w.rep.Skipped++
	w.mu.Unlock()
}

// flush returns the window's report and starts the next one.
func (w *window) flush(now time.Time) mixReport {
	w.mu.Lock()
	defer w.mu.Unlock()
	rep := w.rep
	rep.Time = now.Unix()
	rep.Seconds = now.Sub(w.start).Seconds()
	slices.Sort(w.lat)
	rep.P50ms, rep.P99ms = percentile(w.lat, 0.50), percentile(w.lat, 0.99)
	w.rep, w.lat, w.start = mixReport{}, nil, now
	return rep
}

func percentile(lat []time.Duration, p float64) float64 {
	if len(lat) == 0 {
		return 0
	}
	i := min(len(lat)-1, int(p*float64(len(lat))))
	return float64(lat[i].Microseconds()) / 1000
}

// runMix sends the mix until ctx ends, printing a report line to out every
// cfg.report, and the last (partial) window's at the end.
func runMix(ctx context.Context, cfg mixConfig, out io.Writer) error {
	client := &http.Client{Timeout: cfg.timeout, Transport: &http.Transport{
		MaxIdleConnsPerHost: cfg.conc, DisableCompression: true,
	}}
	// One attack every attackEvery requests, the clean ones in between.
	var seq []mixRequest
	ci, ai := 0, 0
	for len(seq) < max(len(cfg.clean)*cfg.attackEvery, len(cfg.attacks)*cfg.attackEvery) {
		if len(seq)%cfg.attackEvery == cfg.attackEvery-1 && len(cfg.attacks) > 0 {
			seq = append(seq, cfg.attacks[ai%len(cfg.attacks)])
			ai++
		} else {
			seq = append(seq, cfg.clean[ci%len(cfg.clean)])
			ci++
		}
	}

	enc := json.NewEncoder(out)
	w := &window{start: time.Now()}
	slots := make(chan struct{}, cfg.conc)
	var wg sync.WaitGroup
	send := func(r mixRequest) {
		defer wg.Done()
		defer func() { <-slots }()
		var body io.Reader
		if len(r.body) > 0 {
			body = bytes.NewReader(r.body)
		}
		req, err := http.NewRequest(r.method, cfg.base+r.uri, body)
		if err != nil {
			w.add(r, 0, false, 0)
			return
		}
		req.Header = r.header.Clone()
		req.Host = cfg.host
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			w.add(r, 0, false, 0)
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		w.add(r, resp.StatusCode, resp.Header.Get(cfg.appHeader) != "", time.Since(start))
	}

	tick := time.NewTicker(time.Duration(float64(time.Second) / cfg.rate))
	defer tick.Stop()
	report := time.NewTicker(cfg.report)
	defer report.Stop()
	i := 0
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return enc.Encode(w.flush(time.Now()))
		case now := <-report.C:
			if err := enc.Encode(w.flush(now)); err != nil {
				return err
			}
		case <-tick.C:
			select {
			case slots <- struct{}{}:
				wg.Add(1)
				go send(seq[i%len(seq)])
				i++
			default:
				w.skip()
			}
		}
	}
}

// mixFlags parses the mix mode's flags into a config.
func mixMain(ctx context.Context, cleanFile, attackFile, base, host, appHeader string, rate float64, attackEvery, conc int,
	report, timeout time.Duration, out io.Writer) error {
	if base == "" || cleanFile == "" {
		return errors.New("the mix mode needs -url and -clean")
	}
	if rate <= 0 || conc <= 0 || attackEvery < 2 || report <= 0 {
		return errors.New("-rate and -c must be positive, -attack-every at least 2, -report positive")
	}
	if appHeader == "" {
		return errors.New("-app-header is required: without it, an attack the app answers can't be told from a WAF's answer")
	}
	cfg := mixConfig{base: strings.TrimSuffix(base, "/"), host: host, appHeader: appHeader, rate: rate,
		attackEvery: attackEvery, conc: conc, report: report, timeout: timeout}
	var err error
	if cfg.clean, err = readMix(cleanFile, false); err != nil {
		return err
	}
	if attackFile != "" {
		if cfg.attacks, err = readMix(attackFile, true); err != nil {
			return err
		}
	}
	return runMix(ctx, cfg, out)
}
