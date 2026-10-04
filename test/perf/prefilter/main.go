// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command prefilter measures how much CRS rule evaluation a required-literal
// prefilter could skip for rules that run per request argument, and checks
// that the literal extraction is sound: whenever a rule's regex matches an
// input (benign corpus plus every CRS regression-test payload), the literal
// check must not have said "skip".
//
// Analysis tool for docs/design/0001 §5.2, not product code. Run with
// `go run .` from this directory. Transformations are approximated; the
// soundness check stays consistent because the regex and the literal check
// see the same transformed input.
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"html"
	"io/fs"
	"net/url"
	"regexp"
	"regexp/syntax"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	crstests "github.com/corazawaf/coraza-coreruleset/v4/tests"
	libinjection "github.com/corazawaf/libinjection-go"
	"gopkg.in/yaml.v3"
)

type rule struct {
	id        string
	file      string
	vars      string
	op        string // rx, pm, pmFromFile, contains, ..., detectSQLi, detectXSS
	arg       string
	negated   bool
	transf    []string
	paranoia  int
	re        *regexp.Regexp
	lits      []string // required literals (lowercased); nil = no constraint
	filterOK  bool
	unfilterW string // why not filterable
}

// ---------- SecLang parsing (enough for CRS) ----------

func statements(src string) []string {
	var out []string
	var cur strings.Builder
	sc := bufio.NewScanner(strings.NewReader(src))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := sc.Text()
		t := strings.TrimSpace(line)
		if cur.Len() == 0 && (t == "" || strings.HasPrefix(t, "#")) {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(strings.TrimSuffix(line, "\\"))
			continue
		}
		cur.WriteString(line)
		out = append(out, strings.TrimSpace(cur.String()))
		cur.Reset()
	}
	return out
}

// tokens splits a statement into whitespace-separated tokens, honouring
// double quotes with \" escapes.
func tokens(s string) []string {
	var out []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '"' {
			i++
			var b strings.Builder
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) && s[i+1] == '"' {
					b.WriteByte('"')
					i += 2
					continue
				}
				if s[i] == '"' {
					i++
					break
				}
				b.WriteByte(s[i])
				i++
			}
			out = append(out, b.String())
			continue
		}
		j := i
		for j < len(s) && s[j] != ' ' && s[j] != '\t' {
			j++
		}
		out = append(out, s[i:j])
		i = j
	}
	return out
}

func actionValues(actions, name string) []string {
	var out []string
	for _, a := range splitActions(actions) {
		k, v, _ := strings.Cut(a, ":")
		if strings.TrimSpace(k) == name {
			out = append(out, strings.Trim(strings.TrimSpace(v), "'"))
		}
	}
	return out
}

func splitActions(s string) []string {
	var out []string
	depth := false
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			depth = !depth
		case ',':
			if !depth {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

func hasAction(actions, name string) bool {
	for _, a := range splitActions(actions) {
		if strings.TrimSpace(a) == name {
			return true
		}
	}
	return false
}

func argLike(vars string) bool {
	for _, v := range strings.Split(vars, "|") {
		if strings.HasPrefix(v, "!") || strings.HasPrefix(v, "&") {
			continue
		}
		name, _, _ := strings.Cut(v, ":")
		switch name {
		case "ARGS", "ARGS_NAMES", "ARGS_GET", "ARGS_POST", "ARGS_GET_NAMES", "ARGS_POST_NAMES",
			"REQUEST_COOKIES", "REQUEST_COOKIES_NAMES", "XML":
			return true
		}
	}
	return false
}

// ---------- sound required-literal extraction ----------

type lset struct {
	ok   bool
	lits []string
}

func score(l lset) (int, int) {
	if !l.ok || len(l.lits) == 0 {
		return -1, 0
	}
	min := 1 << 30
	for _, s := range l.lits {
		if len(s) < min {
			min = len(s)
		}
	}
	return min, -len(l.lits)
}

func better(a, b lset) bool {
	am, an := score(a)
	bm, bn := score(b)
	if am != bm {
		return am > bm
	}
	return an > bn
}

func dedupe(in []string) []string {
	slices.Sort(in)
	return slices.Compact(in)
}

func required(re *syntax.Regexp) lset {
	switch re.Op {
	case syntax.OpLiteral:
		return lset{ok: true, lits: []string{strings.ToLower(string(re.Rune))}}
	case syntax.OpCharClass:
		n := 0
		var lits []string
		for i := 0; i+1 < len(re.Rune); i += 2 {
			n += int(re.Rune[i+1]-re.Rune[i]) + 1
			if n > 8 {
				return lset{}
			}
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				lits = append(lits, strings.ToLower(string(r)))
			}
		}
		if len(lits) == 0 {
			return lset{}
		}
		return lset{ok: true, lits: dedupe(lits)}
	case syntax.OpCapture, syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
		return lset{}
	case syntax.OpConcat:
		best := lset{}
		var run strings.Builder
		flush := func() {
			if run.Len() > 0 {
				c := lset{ok: true, lits: []string{strings.ToLower(run.String())}}
				if better(c, best) {
					best = c
				}
				run.Reset()
			}
		}
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral {
				run.WriteString(string(sub.Rune))
				continue
			}
			flush()
			if c := required(sub); better(c, best) {
				best = c
			}
		}
		flush()
		return best
	case syntax.OpAlternate:
		var all []string
		for _, sub := range re.Sub {
			c := required(sub)
			if !c.ok {
				return lset{}
			}
			all = append(all, c.lits...)
		}
		return lset{ok: true, lits: dedupe(all)}
	default:
		return lset{}
	}
}

// ---------- transformations (subset; identity for the rest) ----------

var reComment = regexp.MustCompile(`(?s)/\*.*?\*/`)

func transform(s string, ts []string) string {
	for _, t := range ts {
		switch t {
		case "lowercase":
			s = strings.ToLower(s)
		case "removeWhitespace":
			s = strings.Map(func(r rune) rune {
				if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f' || r == '\v' {
					return -1
				}
				return r
			}, s)
		case "compressWhitespace":
			s = strings.Join(strings.Fields(s), " ")
		case "removeNulls":
			s = strings.ReplaceAll(s, "\x00", "")
		case "urlDecode", "urlDecodeUni":
			if d, err := url.QueryUnescape(s); err == nil {
				s = d
			}
		case "htmlEntityDecode":
			s = html.UnescapeString(s)
		case "replaceComments":
			s = reComment.ReplaceAllString(s, " ")
		case "removeComments":
			s = reComment.ReplaceAllString(s, "")
		case "base64Decode":
			if d, err := base64.StdEncoding.DecodeString(s); err == nil {
				s = string(d)
			}
		case "cmdLine":
			var b strings.Builder
			for _, r := range s {
				switch r {
				case '\\', '"', '\'', '^':
					continue
				case ',', ';':
					b.WriteRune(' ')
				default:
					b.WriteRune(r)
				}
			}
			s = strings.ToLower(strings.Join(strings.Fields(b.String()), " "))
			s = strings.ReplaceAll(strings.ReplaceAll(s, " /", "/"), " (", "(")
		}
	}
	return s
}

func candidate(r *rule, transformed string) bool {
	v := strings.ToLower(transformed)
	for _, l := range r.lits {
		if strings.Contains(v, l) {
			return true
		}
	}
	return false
}

func matches(r *rule, transformed string) bool {
	switch r.op {
	case "rx":
		return r.re.MatchString(transformed)
	case "detectSQLi":
		ok, _ := libinjection.IsSQLi(transformed)
		return ok
	case "detectXSS":
		return libinjection.IsXSS(transformed)
	default:
		return candidate(r, transformed) // literal operators: the check is the operator
	}
}

// ---------- corpora ----------

var benign = []string{
	"alice", "Bob Smith", "john.doe@example.com", "jane_doe+news@mail.example.org", "42", "3.14159", "-17",
	"0", "1", "true", "false", "null", "2026-10-04", "2026-10-04T12:34:56Z", "10/04/2026", "12:30",
	"550e8400-e29b-41d4-a716-446655440000", "usr_42", "order-1001", "SKU-AB-1234", "book", "red shoes size 42",
	"how to cook pasta", "New York", "Cairo", "123 Main Street, Springfield, IL 62701", "+1 (555) 012-3456",
	"Quarterly report Q1 2025", "Please gift wrap this order.", "Thanks for the quick delivery!",
	"The quick brown fox jumps over the lazy dog", "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
	"value 7", "value 123", "price", "desc", "asc", "created_at", "page", "limit", "sort", "en-US", "fr",
	"https://shop.example.com/products/42", "https://www.google.com/search?q=shoes", "/account/profile",
	"image/png", "application/json", "text/html", "report.pdf", "avatar.jpg", "Mozilla/5.0",
	"correct-horse-battery-staple", "Tr0ub4dor&3", "P@ssw0rd!2026", "hunter2", "s3cr3t_Key-9",
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
	"dGhpcyBpcyBhIHRlc3Q=", "a1b2c3d4e5f6", "deadbeef", "0xFF", "#ff8800", "rgb(255, 136, 0)",
	"50%", "$19.99", "€25,00", "1,234,567", "5kg", "10x20 cm", "N/A", "-", "_", "...", "?",
	"Hello, world!", "I'm happy with it", "It's great — 5 stars", "\"quoted\" text", "C'est la vie",
	"Müller", "José García", "東京", "Привет", "مرحبا", "😀 great", "ok", "yes", "no", "maybe later",
	"first_name", "last_name", "email", "phone", "address", "city", "state", "zip", "country",
	"items.0.sku", "items.0.qty", "variables.id", "query", "operationName", "csrf_token", "session",
	"utm_source", "utm_medium", "google", "newsletter", "fbclid", "gclid", "ref", "lang", "theme", "dark",
	"query GetUser($id: ID!) { user(id: $id) { name email } }", "{\"a\":1}", "[1,2,3]",
	"Select a size", "Update your profile", "Delete my account", "Drop-off point", "Union Station",
	"from 9 to 5", "where are you?", "or else", "and then", "exec summary", "script writer",
	"alert colleague", "onload balance", "eval period", "system design", "cat food", "ls -1", "cd player",
	"C:\\Users\\alice\\Documents", "/home/alice/notes.txt", "../images/logo.png", "file.tar.gz",
	"SELECT a size from the menu", "<b>bold</b> text", "a < b and c > d", "x=1&y=2", "50/50", "A+B",
}

// attackStrings extracts candidate argument values and raw payloads from
// the CRS regression tests.
func attackStrings() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] && len(s) < 4096 {
			seen[s] = true
			out = append(out, s)
		}
	}
	addPairs := func(s string) {
		add(s)
		for _, kv := range strings.Split(s, "&") {
			k, v, _ := strings.Cut(kv, "=")
			for _, x := range []string{k, v} {
				add(x)
				if d, err := url.QueryUnescape(x); err == nil {
					add(d)
				}
			}
		}
	}
	_ = fs.WalkDir(crstests.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return nil
		}
		b, _ := fs.ReadFile(crstests.FS, p)
		var doc struct {
			Tests []struct {
				Stages []struct {
					Input struct {
						URI     string            `yaml:"uri"`
						Data    any               `yaml:"data"`
						Headers map[string]string `yaml:"headers"`
					} `yaml:"input"`
				} `yaml:"stages"`
			} `yaml:"tests"`
		}
		if yaml.Unmarshal(b, &doc) != nil {
			return nil
		}
		for _, t := range doc.Tests {
			for _, st := range t.Stages {
				if _, q, ok := strings.Cut(st.Input.URI, "?"); ok {
					addPairs(q)
				}
				add(st.Input.URI)
				switch d := st.Input.Data.(type) {
				case string:
					addPairs(strings.TrimSpace(d))
				case []any:
					var parts []string
					for _, x := range d {
						parts = append(parts, fmt.Sprint(x))
					}
					addPairs(strings.Join(parts, "\n"))
				}
				for _, v := range st.Input.Headers {
					add(v)
				}
			}
		}
		return nil
	})
	return out
}

// ---------- main ----------

func main() {
	files, _ := fs.Glob(coreruleset.FS, "@owasp_crs/REQUEST-9*.conf")
	var rules []*rule
	totalSecRules := 0
	for _, f := range files {
		b, _ := fs.ReadFile(coreruleset.FS, f)
		inChain := false
		for _, st := range statements(string(b)) {
			tok := tokens(st)
			if len(tok) < 3 || tok[0] != "SecRule" {
				continue
			}
			totalSecRules++
			actions := ""
			if len(tok) >= 4 {
				actions = tok[3]
			}
			if inChain { // chained child: only runs when the parent matched
				inChain = hasAction(actions, "chain")
				continue
			}
			inChain = hasAction(actions, "chain")
			ids := actionValues(actions, "id")
			if len(ids) == 0 || !argLike(tok[1]) {
				continue
			}
			r := &rule{id: ids[0], file: f, vars: tok[1], transf: actionValues(actions, "t"), paranoia: 1}
			for _, tag := range actionValues(actions, "tag") {
				if strings.HasPrefix(tag, "paranoia-level/") {
					if n, err := strconv.Atoi(strings.TrimPrefix(tag, "paranoia-level/")); err == nil {
						r.paranoia = n
					}
				}
			}
			op := tok[2]
			if strings.HasPrefix(op, "!") {
				r.negated = true
				op = op[1:]
			}
			if !strings.HasPrefix(op, "@") {
				op = "@rx " + op
			}
			name, arg, _ := strings.Cut(op[1:], " ")
			r.op, r.arg = name, arg
			switch {
			case r.negated:
				r.unfilterW = "negated operator"
			case name == "rx":
				re, err := regexp.Compile("(?sm)" + arg)
				if err != nil {
					r.unfilterW = "regex does not compile in Go: " + err.Error()
					break
				}
				r.re = re
				if !utf8.ValidString(arg) || strings.Contains(arg, `\x8`) || strings.Contains(arg, `\x9`) ||
					strings.Contains(arg, `\xa`) || strings.Contains(arg, `\xc`) || strings.Contains(arg, `\xe`) || strings.Contains(arg, `\xf`) {
					r.unfilterW = "binary regex"
					break
				}
				parsed, err := syntax.Parse(arg, syntax.Perl)
				if err != nil {
					r.unfilterW = "parse: " + err.Error()
					break
				}
				l := required(parsed.Simplify())
				if l.ok && len(l.lits) > 0 && len(l.lits) <= 256 {
					r.lits, r.filterOK = l.lits, true
				} else {
					r.unfilterW = "regex has no required literal"
				}
			case name == "pm":
				r.lits = dedupe(strings.Fields(strings.ToLower(arg)))
				r.filterOK = true
			case name == "pmFromFile":
				data, err := fs.ReadFile(coreruleset.FS, "@owasp_crs/"+strings.TrimSpace(arg))
				if err != nil {
					r.unfilterW = "pmFromFile unreadable"
					break
				}
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						r.lits = append(r.lits, strings.ToLower(line))
					}
				}
				r.lits, r.filterOK = dedupe(r.lits), true
			case name == "contains" || name == "beginsWith" || name == "endsWith" || name == "streq":
				r.lits, r.filterOK = []string{strings.ToLower(arg)}, true
			case name == "detectSQLi" || name == "detectXSS":
				r.unfilterW = "libinjection operator"
			default:
				r.unfilterW = "operator " + name
			}
			rules = append(rules, r)
		}
	}

	attacks := attackStrings()
	fmt.Printf("CRS request SecRules: %d; per-argument rules (chain heads): %d\n", totalSecRules, len(rules))
	fmt.Printf("benign corpus: %d values; CRS attack strings: %d\n\n", len(benign), len(attacks))

	for _, pl := range []int{1, 4} {
		var active []*rule
		for _, r := range rules {
			if r.paranoia <= pl {
				active = append(active, r)
			}
		}
		why := map[string]int{}
		filterable := 0
		for _, r := range active {
			if r.filterOK {
				filterable++
			} else {
				w := r.unfilterW
				if strings.HasPrefix(w, "operator ") {
					w = "other operator (" + r.op + ")"
				}
				why[w]++
			}
		}
		fmt.Printf("=== paranoia level %d: %d per-argument rules, %d filterable by literals\n", pl, len(active), filterable)
		keys := make([]string, 0, len(why))
		for k := range why {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("    not filterable: %-40s %d\n", k, why[k])
		}

		// Count and cost-weighted skip rates over the benign corpus.
		var evals, skipped int
		var costAll, costKept time.Duration
		const reps = 30
		for _, r := range active {
			for _, v := range benign {
				tv := transform(v, r.transf)
				start := time.Now()
				for range reps {
					matches(r, tv)
				}
				c := time.Since(start) / reps
				evals++
				costAll += c
				if r.filterOK && !candidate(r, tv) {
					skipped++
				} else {
					costKept += c
				}
			}
		}
		fmt.Printf("    benign: %d of %d rule-value evaluations skippable (%.1f%%)\n",
			skipped, evals, 100*float64(skipped)/float64(evals))
		fmt.Printf("    benign, weighted by measured operator cost: %.1f%% of operator time skippable -> operator time / %.1f\n",
			100*(1-float64(costKept)/float64(costAll)), float64(costAll)/float64(costKept))

		// Soundness: whenever the operator matches, the literal check must pass.
		violations := map[string][]string{}
		checked := 0
		for _, r := range active {
			if !r.filterOK || r.op != "rx" {
				continue
			}
			for _, s := range append(slices.Clone(benign), attacks...) {
				tv := transform(s, r.transf)
				checked++
				if r.re.MatchString(tv) && !candidate(r, tv) {
					violations[r.id] = append(violations[r.id], s)
				}
			}
		}
		fmt.Printf("    soundness: %d regex evaluations checked, %d rules with violations\n", checked, len(violations))
		for id, ex := range violations {
			fmt.Printf("      VIOLATION rule %s: %d inputs, e.g. %q\n", id, len(ex), ex[0])
		}
		fmt.Println()
	}

	// The most expensive unfilterable rules, to know what remains.
	type rc struct {
		id, why string
		cost    time.Duration
	}
	var unf []rc
	for _, r := range rules {
		if r.filterOK || r.paranoia > 1 {
			continue
		}
		var c time.Duration
		for _, v := range benign {
			tv := transform(v, r.transf)
			s := time.Now()
			for range 30 {
				matches(r, tv)
			}
			c += time.Since(s) / 30
		}
		unf = append(unf, rc{r.id, r.unfilterW, c})
	}
	sort.Slice(unf, func(i, j int) bool { return unf[i].cost > unf[j].cost })
	fmt.Println("most expensive PL1 rules that cannot be filtered (cost over the benign corpus):")
	for i, u := range unf {
		if i == 8 {
			break
		}
		fmt.Printf("    %-7s %8s  %s\n", u.id, u.cost.Round(time.Microsecond), u.why)
	}
}
