// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"html"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// doc is what the checks need from one Markdown file. The parser is a line
// scanner, not a full CommonMark one: it knows enough to skip code blocks,
// code spans and HTML comments, and to find headings, links and anchors the
// way GitHub renders them. Indented code blocks are not recognised, since
// list continuations are indented the same way and far more common here.
type doc struct {
	path     string // slash-separated, relative to the repository root
	lines    int
	headings []heading
	anchors  map[string]bool // heading slugs and explicit HTML ids
	links    []link          // inline, reference and HTML links, in order
	urls     []link          // every http(s) URL, including bare ones
	refDefs  map[string]bool // normalised reference labels
	refUses  []link          // full reference links, dest is the label
	contents *contents       // the ## Contents section, if the doc has one
}

type heading struct {
	level int
	text  string // as written, Markdown included
	slug  string // GitHub's anchor, with -1, -2, ... for duplicates
	line  int
}

type link struct {
	dest string
	line int
}

// contents is a doc's ## Contents section: the heading's index in
// doc.headings and the links listed under it.
type contents struct {
	heading int
	entries []link
}

var (
	fenceRE     = regexp.MustCompile("^\\s*(`{3,}|~{3,})(.*)$")
	atxRE       = regexp.MustCompile(`^ {0,3}(#{1,6})(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*$`)
	setextRE    = regexp.MustCompile(`^ {0,3}(=+|-+)[ \t]*$`)
	blockRE     = regexp.MustCompile(`^\s*([-*+]|\d+[.)]|>|\|)(\s|$)`)
	refDefRE    = regexp.MustCompile(`^ {0,3}\[([^\]]+)\]:[ \t]*(<[^>]*>|\S+)`)
	refUseRE    = regexp.MustCompile(`\[([^\]]+)\]\[([^\]]*)\]`)
	htmlLinkRE  = regexp.MustCompile(`(?i)<[a-z][^>]*?\s(?:href|src)\s*=\s*["']([^"']*)["']`)
	htmlIDRE    = regexp.MustCompile(`(?i)<[a-z][^>]*?\s(?:id|name)\s*=\s*["']([^"']+)["']`)
	bareURLRE   = regexp.MustCompile("https?://[^\\s<>\"'`\\[\\]]+")
	htmlTagRE   = regexp.MustCompile(`</?[a-zA-Z][^>]*>`)
	imageTextRE = regexp.MustCompile(`!\[([^\]]*)\]\([^)]*\)`)
	linkTextRE  = regexp.MustCompile(`\[([^\]]*)\](?:\([^)]*\)|\[[^\]]*\])`)
)

// parse reads one Markdown file.
func parse(path string, src string) *doc {
	d := &doc{path: path, anchors: map[string]bool{}, refDefs: map[string]bool{}}
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	d.lines = len(lines)
	slugs := slugger{}

	var (
		fence     string // the open fence's characters, "" outside one
		inComment bool
		frontEnd  = -1
		prev      string // the previous line, if it can be a setext heading's text
		prevLine  int
	)
	if len(lines) > 0 && strings.TrimSpace(lines[0]) == "---" {
		for i := 1; i < len(lines); i++ {
			if t := strings.TrimSpace(lines[i]); t == "---" || t == "..." {
				frontEnd = i
				break
			}
		}
	}

	inContents := false // reading the ## Contents section's list
	addHeading := func(level int, text string, line int) {
		h := heading{level: level, text: text, slug: slugs.slug(plainText(text)), line: line}
		d.anchors[h.slug] = true
		d.headings = append(d.headings, h)
		inContents = false
		if level == 2 && d.contents == nil && strings.EqualFold(plainText(text), "Contents") {
			d.contents = &contents{heading: len(d.headings) - 1}
			inContents = true
		}
	}

	for i := 0; i <= frontEnd; i++ {
		lines[i] = ""
	}
	for i, raw := range lines {
		n := i + 1
		if fence != "" {
			if m := fenceRE.FindStringSubmatch(raw); m != nil && m[1][0] == fence[0] &&
				len(m[1]) >= len(fence) && strings.TrimSpace(m[2]) == "" {
				fence = ""
			}
			prev = ""
			continue
		}
		if m := fenceRE.FindStringSubmatch(raw); m != nil && (m[1][0] != '`' || !strings.Contains(m[2], "`")) {
			fence = m[1]
			prev = ""
			continue
		}
		var line string
		line, inComment = stripComments(raw, inComment)
		text := stripCodeSpans(line) // where links are looked for

		if m := atxRE.FindStringSubmatch(line); m != nil {
			addHeading(len(m[1]), strings.TrimSpace(m[2]), n)
			collectLinks(d, text, n, false)
			prev = ""
			continue
		}
		if m := setextRE.FindStringSubmatch(line); m != nil && prev != "" {
			level := 1
			if m[1][0] == '-' {
				level = 2
			}
			addHeading(level, strings.TrimSpace(prev), prevLine)
			prev = ""
			continue
		}
		collectLinks(d, text, n, inContents)
		if strings.TrimSpace(line) == "" || blockRE.MatchString(line) || refDefRE.MatchString(line) {
			prev = ""
		} else {
			prev, prevLine = line, n
		}
	}
	return d
}

// collectLinks adds the links, URLs, references and anchors on one line,
// already stripped of code spans and comments.
func collectLinks(d *doc, line string, n int, inContents bool) {
	if m := refDefRE.FindStringSubmatch(line); m != nil {
		d.refDefs[normLabel(m[1])] = true
		d.links = append(d.links, link{dest: strings.Trim(m[2], "<>"), line: n})
	}
	for _, dest := range inlineDests(line) {
		d.links = append(d.links, link{dest: dest, line: n})
		if inContents {
			d.contents.entries = append(d.contents.entries, link{dest: dest, line: n})
		}
	}
	for _, m := range refUseRE.FindAllStringSubmatch(line, -1) {
		label := m[2]
		if label == "" {
			label = m[1]
		}
		d.refUses = append(d.refUses, link{dest: label, line: n})
	}
	for _, m := range htmlLinkRE.FindAllStringSubmatch(line, -1) {
		d.links = append(d.links, link{dest: html.UnescapeString(m[1]), line: n})
	}
	for _, m := range htmlIDRE.FindAllStringSubmatch(line, -1) {
		d.anchors[m[1]] = true
	}
	for _, u := range bareURLRE.FindAllString(line, -1) {
		d.urls = append(d.urls, link{dest: trimURL(u), line: n})
	}
}

// inlineDests returns the destinations of the inline links and images on a
// line: the part in parentheses after "](", without its title.
func inlineDests(line string) []string {
	var dests []string
	for i := 0; i+1 < len(line); i++ {
		if line[i] != ']' || line[i+1] != '(' {
			continue
		}
		j := i + 2
		for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
			j++
		}
		var dest string
		if j < len(line) && line[j] == '<' {
			end := strings.IndexByte(line[j:], '>')
			if end < 0 {
				continue
			}
			dest = line[j+1 : j+end]
		} else {
			depth, k := 0, j
		scan:
			for ; k < len(line); k++ {
				switch line[k] {
				case '\\':
					k++
				case ' ', '\t':
					break scan
				case '(':
					depth++
				case ')':
					if depth == 0 {
						break scan
					}
					depth--
				}
			}
			if k > len(line) {
				k = len(line)
			}
			dest = line[j:k]
		}
		if dest != "" {
			dests = append(dests, dest)
		}
	}
	return dests
}

// trimURL drops what GitHub's autolinker leaves out of a bare URL: trailing
// punctuation, and a closing parenthesis with no opening one in the URL.
func trimURL(u string) string {
	for {
		t := strings.TrimRight(u, ".,:;!?*_~'\"")
		if strings.HasSuffix(t, ")") && strings.Count(t, "(") < strings.Count(t, ")") {
			t = t[:len(t)-1]
		}
		if t == u {
			return u
		}
		u = t
	}
}

// stripComments removes HTML comments from a line; inComment says whether a
// comment opened on an earlier line is still open, before and after it.
func stripComments(line string, inComment bool) (string, bool) {
	var b strings.Builder
	for line != "" {
		if inComment {
			end := strings.Index(line, "-->")
			if end < 0 {
				return b.String(), true
			}
			line, inComment = line[end+3:], false
			continue
		}
		start := strings.Index(line, "<!--")
		if start < 0 {
			b.WriteString(line)
			break
		}
		b.WriteString(line[:start])
		line, inComment = line[start+4:], true
	}
	return b.String(), inComment
}

// stripCodeSpans blanks out the code spans on a line, so that links and URLs
// in them are not checked. An unmatched backtick run is kept as text.
func stripCodeSpans(line string) string {
	var b strings.Builder
	for i := 0; i < len(line); {
		if line[i] != '`' {
			b.WriteByte(line[i])
			i++
			continue
		}
		run := backtickRun(line, i)
		end := closingRun(line, i+run, run)
		if end < 0 {
			b.WriteString(line[i : i+run])
			i += run
			continue
		}
		b.WriteString(" ")
		i = end + run
	}
	return b.String()
}

func backtickRun(s string, i int) int {
	j := i
	for j < len(s) && s[j] == '`' {
		j++
	}
	return j - i
}

// closingRun returns where a run of exactly n backticks starts at or after
// i, or -1.
func closingRun(s string, i, n int) int {
	for i < len(s) {
		if s[i] != '`' {
			i++
			continue
		}
		run := backtickRun(s, i)
		if run == n {
			return i
		}
		i += run
	}
	return -1
}

// plainText renders a heading's Markdown to the text GitHub slugs: code
// spans keep their content verbatim, links and images keep their text,
// HTML tags, emphasis markers and backslash escapes go.
func plainText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '`' {
			j := i
			for j < len(s) && s[j] != '`' {
				j++
			}
			b.WriteString(inlineText(s[i:j]))
			i = j
			continue
		}
		run := backtickRun(s, i)
		end := closingRun(s, i+run, run)
		if end < 0 {
			b.WriteString(s[i : i+run])
			i += run
			continue
		}
		code := s[i+run : end]
		if len(code) > 1 && code[0] == ' ' && code[len(code)-1] == ' ' && strings.Trim(code, " ") != "" {
			code = code[1 : len(code)-1]
		}
		b.WriteString(code)
		i = end + run
	}
	return strings.TrimSpace(b.String())
}

// inlineText renders Markdown outside code spans.
func inlineText(s string) string {
	s = htmlTagRE.ReplaceAllString(s, "")
	s = imageTextRE.ReplaceAllString(s, "$1")
	s = linkTextRE.ReplaceAllString(s, "$1")
	r := []rune(s)
	var b strings.Builder
	for i := 0; i < len(r); i++ {
		c := r[i]
		switch {
		case c == '\\' && i+1 < len(r) && (unicode.IsPunct(r[i+1]) || unicode.IsSymbol(r[i+1])):
			i++
			b.WriteRune(r[i])
		case c == '*' || c == '~':
		case c == '_':
			// Intraword underscores are literal (snake_case); others
			// delimit emphasis.
			if i > 0 && i+1 < len(r) && isWord(r[i-1]) && isWord(r[i+1]) {
				b.WriteRune(c)
			}
		default:
			b.WriteRune(c)
		}
	}
	return html.UnescapeString(b.String())
}

func isWord(r rune) bool { return unicode.IsLetter(r) || unicode.IsNumber(r) }

// slugger makes GitHub's heading anchors, as github-slugger does: lower
// case, punctuation and symbols removed, spaces turned into hyphens, and
// "-1", "-2", ... appended to repeats.
type slugger map[string]int

func (s slugger) slug(text string) string {
	base := slugify(text)
	slug := base
	for {
		if _, taken := s[slug]; !taken {
			break
		}
		s[base]++
		slug = base + "-" + strconv.Itoa(s[base])
	}
	s[slug] = 0
	return slug
}

func slugify(text string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(text) {
		switch {
		case r == ' ':
			b.WriteByte('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// normLabel normalises a reference label: case-insensitive, with runs of
// whitespace collapsed.
func normLabel(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}
