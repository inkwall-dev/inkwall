// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

func parseBenchFlags(args []string, stderr io.Writer) (config, error) {
	// The engine's own deadline, so timeouts show up as they would in
	// production instead of being hidden by a generous test deadline.
	cfg := config{timeout: pipeline.DefaultTimeout}
	fs := newFlagSet("bench", &cfg, stderr, " used as the corpus instead of the built-in one")
	fs.DurationVar(&cfg.duration, "duration", 10*time.Second, "how long to measure")
	fs.DurationVar(&cfg.warmup, "warmup", 2*time.Second, "how long to send requests before measuring")
	fs.IntVar(&cfg.concurrency, "concurrency", runtime.GOMAXPROCS(0), "requests in flight at once (with --rate: at most)")
	fs.Float64Var(&cfg.rate, "rate", 0, "send this many requests per second, measuring latency from each request's scheduled time (0 = as fast as possible)")
	fs.BoolVar(&cfg.json, "json", false, "print the report as JSON")
	fs.DurationVar(&cfg.timeout, "timeout", pipeline.DefaultTimeout, "per-request inspection deadline, in-process (as the engine's --timeout)")
	if err := fs.finish(args, false); err != nil {
		return cfg, err
	}
	if cfg.duration <= 0 {
		return cfg, errors.New("--duration must be positive")
	}
	if cfg.warmup < 0 {
		return cfg, errors.New("--warmup must not be negative")
	}
	if cfg.concurrency < 1 {
		return cfg, errors.New("--concurrency must be at least 1")
	}
	if cfg.rate < 0 {
		return cfg, errors.New("--rate must not be negative")
	}
	return cfg, nil
}

// sample is one measured request.
type sample struct {
	entry   int
	latency time.Duration
	// wrong reports a verdict other than the corpus expects, or a request
	// the engine could not inspect (timeout, overload, error).
	wrong bool
}

// classReport summarizes the samples of one corpus entry, or of all.
type classReport struct {
	Class    string  `json:"class"`
	Requests int     `json:"requests"`
	Wrong    int     `json:"wrong_verdicts"`
	P50      float64 `json:"p50_us"`
	P99      float64 `json:"p99_us"`
	P999     float64 `json:"p999_us"`
	Max      float64 `json:"max_us"`
}

type benchReport struct {
	Target      string `json:"target"`
	Concurrency int    `json:"concurrency"`
	// Rate is the target arrival rate, 0 for closed-loop runs.
	Rate     float64 `json:"target_rps,omitempty"`
	Duration float64 `json:"duration_s"`
	Errors   int     `json:"errors"`
	RPS      float64 `json:"rps"`
	// Cores is how many CPUs the engine could use: the lower of the
	// concurrency and GOMAXPROCS. It is only known in-process.
	Cores      int           `json:"cores,omitempty"`
	RPSPerCore float64       `json:"rps_per_core,omitempty"`
	Total      classReport   `json:"total"`
	Classes    []classReport `json:"classes"`
}

func runBench(cfg config, stdout, stderr io.Writer) int {
	corpus := defaultCorpus()
	if cfg.url != "" || cfg.requestFile != "" || cfg.harFile != "" {
		reqs, err := loadRequests(cfg)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		corpus = userCorpus(reqs)
	}
	check, err := newChecker(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	schedule := weighted(corpus)

	// One check up front, so a wrong --engine fails fast instead of
	// producing a report full of errors.
	if _, err := check(corpus[0].req); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	if cfg.warmup > 0 {
		load(cfg.concurrency, cfg.rate, cfg.warmup, schedule, corpus, check)
	}
	samples, errs, elapsed := load(cfg.concurrency, cfg.rate, cfg.duration, schedule, corpus, check)
	if len(samples) == 0 {
		fmt.Fprintf(stderr, "error: no request succeeded (%d errors)\n", errs)
		return 2
	}

	target := "in-process"
	if cfg.engine != "" {
		target = cfg.engine
	}
	rep := benchReport{
		Target:      target,
		Concurrency: cfg.concurrency,
		Rate:        cfg.rate,
		Duration:    elapsed.Seconds(),
		Errors:      errs,
		RPS:         float64(len(samples)) / elapsed.Seconds(),
		Total:       summarize("total", samples),
	}
	if cfg.engine == "" {
		rep.Cores = min(cfg.concurrency, runtime.GOMAXPROCS(0))
		rep.RPSPerCore = rep.RPS / float64(rep.Cores)
	}
	for i, e := range corpus {
		var own []sample
		for _, s := range samples {
			if s.entry == i {
				own = append(own, s)
			}
		}
		if len(own) > 0 {
			rep.Classes = append(rep.Classes, summarize(e.class, own))
		}
	}

	if cfg.json {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
	} else {
		printReport(stdout, rep)
	}
	// Numbers measured with wrong verdicts or failed requests describe a
	// different engine than the one deployed; they must not pass as valid.
	if rep.Total.Wrong > 0 || errs > 0 {
		fmt.Fprintf(stderr, "%d wrong verdict(s), %d error(s): the numbers above are not valid\n", rep.Total.Wrong, errs)
		return 1
	}
	return 0
}

// weighted expands the corpus into a shuffled schedule in which each entry
// appears weight times, so every stretch of the run sees the same mix.
func weighted(corpus []corpusEntry) []int {
	var schedule []int
	for i, e := range corpus {
		for range e.weight {
			schedule = append(schedule, i)
		}
	}
	// A fixed seed keeps runs comparable.
	r := rand.New(rand.NewPCG(1, 2)) // #nosec G404 -- request order, not security
	r.Shuffle(len(schedule), func(i, j int) { schedule[i], schedule[j] = schedule[j], schedule[i] })
	return schedule
}

// load sends requests from schedule for d and returns the samples, the
// number of failed requests and the time taken.
//
// With rate 0 it is closed-loop: concurrency workers send back to back,
// which measures throughput. With a rate, request k is due at start + k/rate
// and its latency counts from then, not from when a worker got to it: when
// the engine falls behind, the queueing delay shows up in the latencies
// instead of silently lowering the load (coordinated omission).
func load(concurrency int, rate float64, d time.Duration, schedule []int, corpus []corpusEntry, check checker) ([]sample, int, time.Duration) {
	var (
		next     atomic.Uint64
		errCount atomic.Int64
		mu       sync.Mutex
		all      []sample
		wg       sync.WaitGroup
	)
	start := time.Now()
	deadline := start.Add(d)
	for range concurrency {
		wg.Go(func() {
			var own []sample
			for {
				k := next.Add(1) - 1
				due := time.Now()
				if rate > 0 {
					due = start.Add(time.Duration(float64(k) / rate * float64(time.Second)))
					time.Sleep(time.Until(due))
				}
				if !due.Before(deadline) {
					break
				}
				i := schedule[k%uint64(len(schedule))]
				e := corpus[i]
				out, err := check(e.req)
				lat := time.Since(due)
				if err != nil {
					errCount.Add(1)
					continue
				}
				own = append(own, sample{entry: i, latency: lat, wrong: wrongVerdict(e.expect, out)})
			}
			mu.Lock()
			all = append(all, own...)
			mu.Unlock()
		})
	}
	wg.Wait()
	return all, int(errCount.Load()), time.Since(start)
}

func wrongVerdict(expect string, out *enginev1.CheckResponse) bool {
	switch out.GetReason() {
	case enginev1.Reason_REASON_TIMEOUT, enginev1.Reason_REASON_OVERLOAD, enginev1.Reason_REASON_ERROR:
		return true
	default:
	}
	switch expect {
	case "allow":
		return out.GetAction() == enginev1.Action_ACTION_DENY
	case "deny":
		// Detect mode logs instead of denying; both mean the rules caught it.
		return out.GetAction() == enginev1.Action_ACTION_ALLOW
	default:
		return false
	}
}

func summarize(class string, samples []sample) classReport {
	lat := make([]time.Duration, len(samples))
	wrong := 0
	for i, s := range samples {
		lat[i] = s.latency
		if s.wrong {
			wrong++
		}
	}
	slices.Sort(lat)
	return classReport{
		Class:    class,
		Requests: len(samples),
		Wrong:    wrong,
		P50:      micros(percentile(lat, 0.50)),
		P99:      micros(percentile(lat, 0.99)),
		P999:     micros(percentile(lat, 0.999)),
		Max:      micros(lat[len(lat)-1]),
	}
}

// percentile returns the nearest-rank percentile of sorted latencies.
func percentile(sorted []time.Duration, p float64) time.Duration {
	rank := int(math.Ceil(p*float64(len(sorted)))) - 1
	return sorted[max(rank, 0)]
}

func micros(d time.Duration) float64 {
	return math.Round(float64(d)/float64(time.Microsecond)*10) / 10
}

func printReport(w io.Writer, rep benchReport) {
	fmt.Fprintf(w, "target %s, concurrency %d, %.1fs", rep.Target, rep.Concurrency, rep.Duration)
	if rep.Rate > 0 {
		fmt.Fprintf(w, ", target rate %.0f req/s", rep.Rate)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%d requests, %.0f req/s", rep.Total.Requests, rep.RPS)
	if rep.RPSPerCore > 0 {
		fmt.Fprintf(w, " (%.0f per core, %d cores)", rep.RPSPerCore, rep.Cores)
	}
	if rep.Errors > 0 {
		fmt.Fprintf(w, ", %d errors", rep.Errors)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(tw, "class\trequests\tp50 µs\tp99 µs\tp99.9 µs\tmax µs\twrong\t")
	for _, c := range append(rep.Classes, rep.Total) {
		fmt.Fprintf(tw, "%s\t%d\t%.1f\t%.1f\t%.1f\t%.1f\t%d\t\n", c.Class, c.Requests, c.P50, c.P99, c.P999, c.Max, c.Wrong)
	}
	_ = tw.Flush()
}
