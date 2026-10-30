// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"testing"
)

func TestSlugify(t *testing.T) {
	for in, want := range map[string]string{
		"Prerequisites": "prerequisites",
		"What's new":    "whats-new",
		"What the control plane does and doesn't do": "what-the-control-plane-does-and-doesnt-do",
		"1. Overview":               "1-overview",
		"§8 Benchmarks & gates":     "8-benchmarks--gates",
		"Foo -- bar":                "foo----bar",
		"snake_case and kebab-case": "snake_case-and-kebab-case",
		"Ünïcödé Straße":            "ünïcödé-straße",
		"Rocket 🚀 launch":           "rocket--launch",
		"WAFPolicy.spec.rules (v1)": "wafpolicyspecrules-v1",
		"  ":                        "--",
	} {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSluggerDuplicates(t *testing.T) {
	s := slugger{}
	var got []string
	for _, h := range []string{"Usage", "Usage", "Usage-1", "Usage", "Notes"} {
		got = append(got, s.slug(h))
	}
	// As github-slugger: the third heading's own slug "usage-1" is taken,
	// so it becomes "usage-1-1", and the fourth "Usage" skips to "usage-2".
	want := []string{"usage", "usage-1", "usage-1-1", "usage-2", "notes"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("slugs = %q, want %q", got, want)
	}
}

func TestPlainText(t *testing.T) {
	for in, want := range map[string]string{
		"`make docs-check`":              "make docs-check",
		"The `WAFPolicy` *spec*":         "The WAFPolicy spec",
		"**Bold** and _emphasis_":        "Bold and emphasis",
		"`snake_case` and snake_case":    "snake_case and snake_case",
		"`*` matches":                    "* matches",
		"[Helm](https://helm.sh) charts": "Helm charts",
		"![logo](logo.svg) Inkwall":      "logo Inkwall",
		"<code>x</code> & <b>y</b>":      "x & y",
		"Tom &amp; Jerry":                "Tom & Jerry",
		`Escaped \*star\* and \_under\_`: "Escaped *star* and _under_",
		"~~old~~ new":                    "old new",
		"`` code with ` tick ``":         "code with ` tick",
	} {
		if got := plainText(in); got != want {
			t.Errorf("plainText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInlineDests(t *testing.T) {
	for in, want := range map[string][]string{
		"See [a](a.md) and [b](b.md#x).":               {"a.md", "b.md#x"},
		`[t](a.md "Title") ![i](img.svg)`:              {"a.md", "img.svg"},
		"[w](https://en.wikipedia.org/wiki/Foo_(bar))": {"https://en.wikipedia.org/wiki/Foo_(bar)"},
		"[s](<with space.md>)":                         {"with space.md"},
		"[e]() none":                                   nil,
		"plain text (not a link)":                      nil,
	} {
		if got := inlineDests(in); !reflect.DeepEqual(got, want) {
			t.Errorf("inlineDests(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStripCodeSpans(t *testing.T) {
	for in, want := range map[string]string{
		"a `[x](y.md)` b":       "a   b",
		"a ``x ` y`` b":         "a   b",
		"unmatched ` [x](y.md)": "unmatched ` [x](y.md)",
	} {
		if got := stripCodeSpans(in); got != want {
			t.Errorf("stripCodeSpans(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTrimURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://a.io/x.":                     "https://a.io/x",
		"https://a.io/x),":                    "https://a.io/x",
		"https://en.wikipedia.org/wiki/A_(b)": "https://en.wikipedia.org/wiki/A_(b)",
	} {
		if got := trimURL(in); got != want {
			t.Errorf("trimURL(%q) = %q, want %q", in, got, want)
		}
	}
}

const sample = `---
title: [front](matter.md)
---
# Title

Intro with [a link](other.md), https://example.org/page and [https://example.org/text][docs].

## Contents

- [First](#first)
  - [Sub](#sub)
- [Second](#second)

## First

<a id="custom"></a>
<span name="named">x</span>

### Sub

` + "```" + `md
[not a link](missing.md)
## Not a heading
` + "```" + `

<!-- [commented](missing.md)
## Not a heading either -->

Second
------

` + "`[code](missing.md)`" + ` and [ref link][Docs] and [collapsed][].

[docs]: https://example.org/docs
[collapsed]: other.md

## First
`

func TestParse(t *testing.T) {
	d := parse("dir/sample.md", sample)
	var slugs []string
	for _, h := range d.headings {
		slugs = append(slugs, h.slug)
	}
	if want := []string{"title", "contents", "first", "sub", "second", "first-1"}; !reflect.DeepEqual(slugs, want) {
		t.Errorf("heading slugs = %q, want %q", slugs, want)
	}
	if d.headings[4].line != 29 || d.headings[4].level != 2 {
		t.Errorf("setext heading = %+v, want level 2 on line 29", d.headings[4])
	}
	for _, a := range []string{"custom", "named", "first-1"} {
		if !d.anchors[a] {
			t.Errorf("anchor %q missing", a)
		}
	}
	var dests []string
	for _, l := range d.links {
		dests = append(dests, l.dest)
	}
	want := []string{"other.md", "#first", "#sub", "#second", "https://example.org/docs", "other.md"}
	if !reflect.DeepEqual(dests, want) {
		t.Errorf("links = %q, want %q", dests, want)
	}
	if d.contents == nil || len(d.contents.entries) != 3 {
		t.Fatalf("contents = %+v, want 3 entries", d.contents)
	}
	if len(d.refUses) != 3 || d.refUses[1].dest != "Docs" || d.refUses[2].dest != "collapsed" {
		t.Errorf("reference uses = %+v", d.refUses)
	}
	if !d.refDefs["docs"] || !d.refDefs["collapsed"] {
		t.Errorf("reference definitions = %v", d.refDefs)
	}
	var urls []string
	for _, u := range d.urls {
		urls = append(urls, u.dest)
	}
	if want := []string{"https://example.org/page", "https://example.org/text", "https://example.org/docs"}; !reflect.DeepEqual(urls, want) {
		t.Errorf("urls = %q, want %q", urls, want)
	}
}
