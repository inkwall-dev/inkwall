// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// problem is one finding, reported as "file:line: msg".
type problem struct {
	file string
	line int
	msg  string
}

func (p problem) String() string {
	if p.line == 0 {
		return p.file + ": " + p.msg
	}
	return fmt.Sprintf("%s:%d: %s", p.file, p.line, p.msg)
}

// repo is the set of docs to check, and the files their links may point to.
type repo struct {
	fsys fs.FS           // the repository root
	docs map[string]*doc // parsed Markdown, by slash path; filled on demand
}

// load parses a Markdown file, or returns nil if it can't be read.
func (r *repo) load(p string) *doc {
	if d, ok := r.docs[p]; ok {
		return d
	}
	src, err := fs.ReadFile(r.fsys, p)
	if err != nil {
		r.docs[p] = nil
		return nil
	}
	d := parse(p, string(src))
	r.docs[p] = d
	return d
}

var (
	schemeRE     = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)
	lineAnchorRE = regexp.MustCompile(`^L\d+(C\d+)?(-L\d+(C\d+)?)?$`)
)

// isMarkdown reports whether a path is a Markdown file.
func isMarkdown(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	return ext == ".md" || ext == ".markdown"
}

// resolve turns an internal link in doc d into a repository path and a
// fragment. ok is false for external links (with a scheme, or
// protocol-relative), which checkLinks leaves to the external check.
func resolve(d *doc, dest string) (target, fragment string, ok bool, err error) {
	if schemeRE.MatchString(dest) || strings.HasPrefix(dest, "//") {
		return "", "", false, nil
	}
	p, frag, _ := strings.Cut(dest, "#")
	p, _, _ = strings.Cut(p, "?")
	if fragment, err = url.PathUnescape(frag); err != nil {
		return "", "", true, fmt.Errorf("bad escape in %q", dest)
	}
	if p == "" {
		return d.path, fragment, true, nil
	}
	if p, err = url.PathUnescape(p); err != nil {
		return "", "", true, fmt.Errorf("bad escape in %q", dest)
	}
	if strings.HasPrefix(p, "/") {
		target = path.Clean(strings.TrimPrefix(p, "/"))
	} else {
		target = path.Join(path.Dir(d.path), p)
	}
	if target == ".." || strings.HasPrefix(target, "../") {
		return "", "", true, fmt.Errorf("link %q points outside the repository", dest)
	}
	return target, fragment, true, nil
}

// checkLinks checks a doc's internal links: that each file exists and each
// #anchor names a heading or an HTML id in the doc it points to. It also
// checks that full reference links ([text][label]) have a definition.
func (r *repo) checkLinks(d *doc) []problem {
	var probs []problem
	add := func(line int, format string, args ...any) {
		probs = append(probs, problem{d.path, line, fmt.Sprintf(format, args...)})
	}
	for _, l := range d.links {
		target, frag, internal, err := resolve(d, l.dest)
		if err != nil {
			add(l.line, "%v", err)
			continue
		}
		if !internal {
			continue
		}
		info, err := fs.Stat(r.fsys, target)
		if err != nil {
			add(l.line, "broken link %q: %s does not exist", l.dest, target)
			continue
		}
		if frag == "" || frag == "top" {
			continue
		}
		switch {
		case info.IsDir():
			// GitHub shows the directory's README; its anchors are not
			// worth guessing.
		case isMarkdown(target):
			if t := r.load(target); t != nil && !t.anchors[frag] {
				add(l.line, "broken anchor %q: %s has no heading or id %q", l.dest, target, frag)
			}
		case !lineAnchorRE.MatchString(frag):
			add(l.line, "broken anchor %q: only Markdown files have anchors, and other files line ones (#L10, #L10-L20)", l.dest)
		}
	}
	for _, u := range d.refUses {
		if !d.refDefs[normLabel(u.dest)] {
			add(u.line, "reference link [%s] has no definition ([%s]: url)", u.dest, u.dest)
		}
	}
	return probs
}

// checkContents checks a doc's ## Contents section against its headings:
// it comes before the other ## sections, lists every one of them, lists
// only ## and ### headings of this doc, once each, in the doc's order.
// minLines > 0 also requires a Contents section in docs longer than that.
func checkContents(d *doc, minLines int) []problem {
	var probs []problem
	add := func(line int, format string, args ...any) {
		probs = append(probs, problem{d.path, line, fmt.Sprintf(format, args...)})
	}
	if d.contents == nil {
		if minLines > 0 && d.lines > minLines {
			add(0, "%d lines long but has no ## Contents section (required above %d lines)", d.lines, minLines)
		}
		return probs
	}
	c := d.contents
	ch := d.headings[c.heading]
	for _, h := range d.headings[:c.heading] {
		if h.level == 2 {
			add(h.line, "section %q comes before ## Contents; Contents should be the first section", h.text)
		}
	}
	// The sections Contents may list, by anchor.
	index := map[string]int{}
	for i, h := range d.headings[c.heading+1:] {
		if h.level == 2 || h.level == 3 {
			index[h.slug] = i
		}
	}
	listed := map[string]bool{}
	last, lastDest := -1, ""
	for _, e := range c.entries {
		frag, isAnchor := strings.CutPrefix(e.dest, "#")
		if !isAnchor {
			add(e.line, "Contents links to %q; it should only link to sections of this doc", e.dest)
			continue
		}
		if f, err := url.PathUnescape(frag); err == nil {
			frag = f
		}
		i, ok := index[frag]
		if !ok {
			if d.anchors[frag] {
				add(e.line, "Contents links to #%s, which is not a ## or ### section after Contents", frag)
			}
			// A missing anchor is reported by checkLinks.
			continue
		}
		if listed[frag] {
			add(e.line, "Contents lists #%s twice", frag)
			continue
		}
		listed[frag] = true
		if i < last {
			add(e.line, "Contents lists #%s after %s, but the doc has it before", frag, lastDest)
		}
		last, lastDest = i, e.dest
	}
	for _, h := range d.headings[c.heading+1:] {
		if h.level == 2 && !listed[h.slug] {
			add(ch.line, "Contents does not list section %q (#%s, line %d)", h.text, h.slug, h.line)
		}
	}
	return probs
}

// checkIndex checks that the index doc links to every doc in docs, except
// itself and the exempt ones. A link to a directory lists its README.md.
func (r *repo) checkIndex(index string, docs []string, exempt map[string]bool) []problem {
	idx := r.load(index)
	if idx == nil {
		return []problem{{index, 0, "the docs index does not exist"}}
	}
	listed := map[string]bool{}
	for _, l := range idx.links {
		target, _, internal, err := resolve(idx, l.dest)
		if err != nil || !internal {
			continue
		}
		listed[target] = true
		listed[path.Join(target, "README.md")] = true
	}
	var probs []problem
	for _, p := range docs {
		if p != index && !exempt[p] && !listed[p] {
			probs = append(probs, problem{index, 0, fmt.Sprintf("the docs index does not list %s", p)})
		}
	}
	return probs
}
