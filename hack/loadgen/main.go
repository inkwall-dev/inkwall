// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command loadgen sends GET requests to one URL from a few concurrent
// clients for a while, and prints the latency percentiles and the status
// codes as one JSON line: a small, closed-loop load test for the kind
// measurements (hack/kind/response-load.sh), not a benchmark tool.
//
// With -clean (and -attacks), it sends a mix of clean requests and attacks
// instead, at a steady rate, and reports every -report which got through
// and which were denied (mix.go): the soak test's traffic
// (hack/kind/soak.sh).
//
//	loadgen -url http://127.0.0.1:30080 -host shop.example.com -clean clean.http \
//	  -attacks attacks.http -app-header X-Soak-App -rate 20 -d 24h -report 10s
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

type headers []string

func (h *headers) String() string     { return strings.Join(*h, ", ") }
func (h *headers) Set(v string) error { *h = append(*h, v); return nil }

// Result is what loadgen prints.
type Result struct {
	URL         string         `json:"url"`
	Concurrency int            `json:"concurrency"`
	Seconds     float64        `json:"seconds"`
	Requests    int            `json:"requests"`
	RPS         float64        `json:"rps"`
	P50ms       float64        `json:"p50ms"`
	P90ms       float64        `json:"p90ms"`
	P99ms       float64        `json:"p99ms"`
	MaxMs       float64        `json:"maxms"`
	Status      map[string]int `json:"status"`
	BodyBytes   int64          `json:"bodyBytes"`
}

func main() {
	url := flag.String("url", "", "URL to GET")
	host := flag.String("host", "", "Host header")
	conc := flag.Int("c", 8, "concurrent clients")
	dur := flag.Duration("d", 20*time.Second, "how long to measure")
	warm := flag.Duration("warmup", 3*time.Second, "how long to send before measuring")
	var hs headers
	flag.Var(&hs, "H", "extra header, \"Name: value\" (repeatable)")
	cleanFile := flag.String("clean", "", "mix mode: file of raw HTTP requests every one of which the app must answer")
	attackFile := flag.String("attacks", "", "mix mode: file of raw HTTP requests the WAF must deny")
	appHeader := flag.String("app-header", "", "mix mode: response header only the app sets")
	rate := flag.Float64("rate", 10, "mix mode: requests per second")
	attackEvery := flag.Int("attack-every", 5, "mix mode: one request in this many is an attack")
	report := flag.Duration("report", 10*time.Second, "mix mode: how often to print the counts")
	flag.Parse()
	if *cleanFile != "" {
		// Until -d, or until stopped (SIGINT, SIGTERM) if -d is 0.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if *dur > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, *dur)
			defer cancel()
		}
		if err := mixMain(ctx, *cleanFile, *attackFile, *url, *host, *appHeader, *rate, *attackEvery, *conc,
			*report, 10*time.Second, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "loadgen:", err)
			os.Exit(2)
		}
		return
	}
	if *url == "" {
		fmt.Fprintln(os.Stderr, "loadgen: -url is required")
		os.Exit(2)
	}
	req, err := http.NewRequest(http.MethodGet, *url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loadgen:", err)
		os.Exit(2)
	}
	if *host != "" {
		req.Host = *host
	}
	for _, h := range hs {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			fmt.Fprintf(os.Stderr, "loadgen: -H %q: want \"Name: value\"\n", h)
			os.Exit(2)
		}
		req.Header.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		MaxIdleConnsPerHost: *conc, DisableCompression: true,
	}}

	ctx, cancel := context.WithTimeout(context.Background(), *warm+*dur)
	defer cancel()
	measureFrom := time.Now().Add(*warm)
	var (
		mu     sync.Mutex
		lat    []time.Duration
		status = map[string]int{}
		bytes  int64
		wg     sync.WaitGroup
	)
	for range *conc {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				start := time.Now()
				resp, err := client.Do(req.Clone(ctx))
				code := "error"
				var n int64
				if err == nil {
					n, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					code = fmt.Sprint(resp.StatusCode)
				} else if ctx.Err() != nil {
					return
				}
				d := time.Since(start)
				if start.Before(measureFrom) {
					continue
				}
				mu.Lock()
				lat = append(lat, d)
				status[code]++
				bytes += n
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	slices.Sort(lat)
	ms := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		i := min(len(lat)-1, int(p*float64(len(lat))))
		return float64(lat[i].Microseconds()) / 1000
	}
	r := Result{URL: *url, Concurrency: *conc, Seconds: dur.Seconds(), Requests: len(lat), RPS: float64(len(lat)) / dur.Seconds(),
		P50ms: ms(0.50), P90ms: ms(0.90), P99ms: ms(0.99), MaxMs: ms(1), Status: status}
	if len(lat) > 0 {
		r.BodyBytes = bytes / int64(len(lat))
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
}
