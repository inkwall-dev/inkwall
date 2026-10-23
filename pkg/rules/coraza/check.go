// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"bufio"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Directive is one SecLang directive, possibly spanning several lines.
type Directive struct {
	// Line is the 1-based line the directive starts on.
	Line int
	// Name is the directive name in lower case, such as "secrule".
	Name string
	// Text is the directive with its continuation lines joined, as Coraza
	// evaluates it.
	Text string
}

// SplitDirectives splits SecLang into directives the way Coraza's parser
// reads them: lines are trimmed, blank lines and comments skipped, a line
// ending in a backslash continues on the next, and a backtick at the end of
// a line opens a block that a line starting with a backtick closes.
func SplitDirectives(s string) ([]Directive, error) {
	var (
		out         []Directive
		buf         strings.Builder
		start       int
		inBackticks bool
	)
	scanner := bufio.NewScanner(strings.NewReader(s))
	scanner.Buffer(make([]byte, 0, 64<<10), len(s)+1)
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if buf.Len() == 0 {
			start = n
		}
		if !inBackticks && line[len(line)-1] == '`' {
			inBackticks = true
		} else if inBackticks && line[0] == '`' {
			inBackticks = false
		}
		if inBackticks {
			buf.WriteString(line)
			buf.WriteString("\n")
			continue
		}
		if strings.HasSuffix(line, `\`) {
			buf.WriteString(strings.TrimSuffix(line, `\`))
			continue
		}
		buf.WriteString(line)
		text := buf.String()
		name, _, _ := strings.Cut(text, " ")
		out = append(out, Directive{Line: start, Name: strings.ToLower(name), Text: text})
		buf.Reset()
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if inBackticks {
		return nil, &RuleError{Line: start, Err: errors.New("backtick block is not closed")}
	}
	if buf.Len() > 0 {
		return nil, &RuleError{Line: start, Err: errors.New("the last line ends with a backslash")}
	}
	return out, nil
}

// userDirectives are the directives policy authors may use: they add,
// remove or change rules. Everything else configures the engine as a whole
// (SecRuleEngine, body limits), touches files (SecAuditLog, SecDebugLog,
// Include) or is unsupported, and is set by Inkwall instead.
var userDirectives = map[string]bool{
	"secrule":                  true,
	"secaction":                true,
	"secmarker":                true,
	"secruleremovebyid":        true,
	"secruleremovebytag":       true,
	"secruleremovebymsg":       true,
	"secruleupdatetargetbyid":  true,
	"secruleupdatetargetbytag": true,
	"secruleupdateactionbyid":  true,
}

// UserDirectiveNames returns the directives CheckUserRules allows, sorted.
func UserDirectiveNames() []string {
	names := make([]string, 0, len(userDirectives))
	for n := range userDirectives {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// RuleError is a problem in user rules, at a line.
type RuleError struct {
	// Line is the 1-based line of the directive, or 0 when unknown.
	Line int
	Err  error
}

func (e *RuleError) Error() string {
	if e.Line == 0 {
		return e.Err.Error()
	}
	return fmt.Sprintf("line %d: %v", e.Line, e.Err)
}

func (e *RuleError) Unwrap() error { return e.Err }

// CheckUserRules checks SecLang written by policy authors, as the engine
// loads it: after the Core Rule Set (Config.Directives), so it may refer to
// CRS rules. Only the directives of UserDirectiveNames are allowed. The
// error is a *RuleError naming the line of the first problem.
func CheckUserRules(rules string) error {
	dirs, err := SplitDirectives(rules)
	if err != nil {
		return err
	}
	for _, d := range dirs {
		if !userDirectives[d.Name] {
			return &RuleError{Line: d.Line, Err: fmt.Errorf("directive %q is not allowed in rule sets (allowed: %s)",
				d.Name, strings.Join(UserDirectiveNames(), ", "))}
		}
	}
	compile := func(n int) error {
		var b strings.Builder
		for _, d := range dirs[:n] {
			b.WriteString(d.Text)
			b.WriteString("\n")
		}
		_, err := New(Config{Directives: b.String()})
		return err
	}
	err = compile(len(dirs))
	if err == nil {
		return nil
	}
	// Coraza stops at the first directive that fails but doesn't say which.
	// Find the shortest failing prefix: its last directive is the culprit.
	lo, hi := 0, len(dirs) // compile(lo) succeeds, compile(hi) fails
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		if compile(mid) == nil {
			lo = mid
		} else {
			hi = mid
		}
	}
	return &RuleError{Line: dirs[hi-1].Line, Err: compileCause(err)}
}

// compileCause strips the wrapping Coraza and New add, keeping the reason.
func compileCause(err error) error {
	msg := err.Error()
	for _, prefix := range []string{"compile rules: ", "invalid WAF config from string: "} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	return errors.New(msg)
}
