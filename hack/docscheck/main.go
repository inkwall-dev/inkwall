// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command docscheck keeps the Markdown docs from rotting. Run from the
// repository root (make docs-check), it checks every Markdown file Git knows
// of, tracked or untracked but not ignored, outside test data:
//
//   - internal links: the file exists, and an #anchor names a heading (by
//     GitHub's slug rules, duplicates numbered -1, -2, ...) or an HTML
//     id/name in the doc it points to; full reference links have a
//     definition;
//   - the ## Contents section, in docs that have one: it lists every ##
//     section, and only ## and ### sections, in order;
//   - the docs index (-index, docs/README.md), if it exists: it links to
//     every doc.
//
// -contents-min-lines and -require-index make the last two strict: every
// doc over that many lines needs a Contents section, and the index must
// exist. With -external it also checks the http(s) links, with retries;
// hosts that fail for reasons other than a broken link are listed in
// -external-ignore.
//
// Problems are printed one per line as file:line: message; the exit status
// is 1 if there are any, 2 if the check could not run.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type config struct {
	exclude          map[string]bool // path elements whose files are not checked
	index            string
	requireIndex     bool
	indexExempt      map[string]bool
	contentsMinLines int
	contentsExempt   map[string]bool
	external         bool
	ext              externalConfig
}

func main() {
	var (
		cfg            config
		exclude        = flag.String("exclude", "testdata,vendor,node_modules", "comma-separated directory names whose Markdown files are not checked")
		indexExempt    = flag.String("index-exempt", "CLAUDE.md", "comma-separated docs the index need not list")
		contentsExempt = flag.String("contents-exempt", "", "comma-separated docs that need no Contents section, whatever their length")
		ignoreFile     = flag.String("external-ignore", "hack/docscheck/external-ignore.txt", "file of regular expressions, one per line, for URLs the external check skips")
	)
	flag.StringVar(&cfg.index, "index", "docs/README.md", "the docs index, which must link to every doc")
	flag.BoolVar(&cfg.requireIndex, "require-index", false, "fail if the docs index does not exist")
	flag.IntVar(&cfg.contentsMinLines, "contents-min-lines", 0, "require a ## Contents section in docs longer than this many lines (0: only check the ones that have it)")
	flag.BoolVar(&cfg.external, "external", false, "also check http(s) links")
	flag.DurationVar(&cfg.ext.timeout, "timeout", 20*time.Second, "external check: timeout of one request")
	flag.IntVar(&cfg.ext.retries, "retries", 2, "external check: retries of a URL that fails with a network error, 429 or 5xx")
	flag.IntVar(&cfg.ext.concurrency, "concurrency", 8, "external check: URLs checked at once")
	flag.Parse()
	cfg.exclude = set(*exclude)
	cfg.indexExempt = set(*indexExempt)
	cfg.contentsExempt = set(*contentsExempt)
	if cfg.external {
		var err error
		if cfg.ext.ignore, err = readIgnore(*ignoreFile); err != nil {
			fmt.Fprintln(os.Stderr, "docscheck:", err)
			os.Exit(2)
		}
		cfg.ext.backoff = time.Second
	}

	files, err := markdownFiles(cfg.exclude)
	if err != nil {
		fmt.Fprintln(os.Stderr, "docscheck:", err)
		os.Exit(2)
	}
	if n := run(os.DirFS("."), files, cfg, os.Stdout, os.Stderr); n > 0 {
		os.Exit(1)
	}
}

func set(list string) map[string]bool {
	s := map[string]bool{}
	for _, v := range strings.Split(list, ",") {
		if v = strings.TrimSpace(v); v != "" {
			s[v] = true
		}
	}
	return s
}

// markdownFiles lists the Markdown files Git tracks or would track, except
// those under an excluded directory, as sorted slash paths.
func markdownFiles(exclude map[string]bool) ([]string, error) {
	var stderr bytes.Buffer
	cmd := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.md", "*.markdown")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	seen := map[string]bool{}
	var files []string
next:
	for _, p := range strings.Split(string(out), "\x00") {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		for _, elem := range strings.Split(path.Dir(p), "/") {
			if exclude[elem] {
				continue next
			}
		}
		if _, err := os.Stat(filepath.FromSlash(p)); errors.Is(err, fs.ErrNotExist) {
			continue // deleted but not yet staged
		}
		files = append(files, p)
	}
	sort.Strings(files)
	return files, nil
}

// run checks the files and prints the problems found to out and a summary
// to log. It returns the number of problems.
func run(fsys fs.FS, files []string, cfg config, out, log io.Writer) int {
	start := time.Now()
	r := &repo{fsys: fsys, docs: map[string]*doc{}}
	var probs []problem
	links := 0
	for _, p := range files {
		d := r.load(p)
		if d == nil {
			probs = append(probs, problem{p, 0, "cannot read it"})
			continue
		}
		links += len(d.links)
		probs = append(probs, r.checkLinks(d)...)
		minLines := cfg.contentsMinLines
		if cfg.contentsExempt[p] {
			minLines = 0
		}
		probs = append(probs, checkContents(d, minLines)...)
	}
	if _, err := fs.Stat(fsys, cfg.index); err == nil || cfg.requireIndex {
		probs = append(probs, r.checkIndex(cfg.index, files, cfg.indexExempt)...)
	}
	urls := 0
	if cfg.external {
		var docs []*doc
		for _, p := range files {
			if d := r.docs[p]; d != nil {
				docs = append(docs, d)
			}
		}
		var extProbs []problem
		extProbs, urls = checkExternal(docs, cfg.ext, log)
		probs = append(probs, extProbs...)
	}
	sort.SliceStable(probs, func(i, j int) bool {
		if probs[i].file != probs[j].file {
			return probs[i].file < probs[j].file
		}
		return probs[i].line < probs[j].line
	})
	for _, p := range probs {
		fmt.Fprintln(out, p)
	}
	summary := fmt.Sprintf("docscheck: %d docs, %d links", len(files), links)
	if cfg.external {
		summary += fmt.Sprintf(", %d external URLs", urls)
	}
	fmt.Fprintf(log, "%s, %d problems (%s)\n", summary, len(probs), time.Since(start).Round(time.Millisecond))
	return len(probs)
}
