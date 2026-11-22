// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"bufio"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
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

// userOperators are the operators policy authors may use. It leaves out
// operators that reach outside the engine: inspectFile runs a program and
// rbl makes DNS queries to a domain the rule names. The engine doesn't
// register them either (disabledOperators), but rejecting them here names
// the line. The *FromFile operators read only the embedded CRS files, and
// the *FromDataset ones need SecDataset, which rule sets can't use.
var userOperators = map[string]bool{
	"beginsWith":           true,
	"contains":             true,
	"containsWord":         true,
	"detectSQLi":           true,
	"detectXSS":            true,
	"endsWith":             true,
	"eq":                   true,
	"ge":                   true,
	"geoLookup":            true,
	"gt":                   true,
	"ipMatch":              true,
	"ipMatchF":             true,
	"ipMatchFromDataset":   true,
	"ipMatchFromFile":      true,
	"le":                   true,
	"lt":                   true,
	"noMatch":              true,
	"pm":                   true,
	"pmf":                  true,
	"pmFromDataset":        true,
	"pmFromFile":           true,
	"restpath":             true,
	"rx":                   true,
	"streq":                true,
	"strmatch":             true,
	"unconditionalMatch":   true,
	"validateByteRange":    true,
	"validateNid":          true,
	"validateSchema":       true,
	"validateUrlEncoding":  true,
	"validateUtf8Encoding": true,
	"within":               true,
}

// UserOperatorNames returns the operators CheckUserRules allows, sorted.
func UserOperatorNames() []string {
	names := make([]string, 0, len(userOperators))
	for n := range userOperators {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ruleFields splits a SecRule directive the way Coraza's rule parser does
// (parseActionOperator): the variables, a space, the operator in double
// quotes and, after it, the actions. It returns the operator unquoted and
// what follows it, the quoted actions or nothing. ok is false when the rule
// doesn't parse; compiling it then fails.
func ruleFields(text string) (operator, rest string, ok bool) {
	_, data, _ := strings.Cut(text, " ")
	data = strings.Trim(data, " ")
	_, rest, found := strings.Cut(data, " ")
	if !found {
		return "", "", false
	}
	rest = strings.TrimLeft(rest, " ")
	if rest == "" || rest[0] != '"' {
		return "", "", false
	}
	end, escapes := -1, 0
	for i := 1; i < len(rest); i++ {
		switch {
		case rest[i] == '\\':
			escapes++
			continue
		case rest[i] == '"' && escapes%2 == 0:
			end = i
		}
		escapes = 0
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return "", "", false
	}
	return strings.ReplaceAll(rest[1:end], `\"`, `"`), strings.TrimLeft(rest[end+1:], " "), true
}

// ruleActions returns the action list of a SecRule directive, unquoted:
// empty when it has none. ok is false when the rule doesn't parse.
func ruleActions(text string) (actions string, ok bool) {
	_, rest, ok := ruleFields(text)
	switch {
	case !ok:
		return "", false
	case rest == "":
		return "", true
	case len(rest) < 2 || rest[0] != '"' || rest[len(rest)-1] != '"':
		return "", false
	}
	return rest[1 : len(rest)-1], true
}

// ruleOperator returns the operator name of a SecRule directive, read the
// way Coraza's rule parser reads it (ParseOperator): "@name args" or
// "!@name args", and anything else is rx. ok is false when the rule doesn't
// parse.
func ruleOperator(text string) (op string, ok bool) {
	operator, _, ok := ruleFields(text)
	if !ok {
		return "", false
	}
	switch {
	case strings.HasPrefix(operator, "!@"):
		operator = operator[2:]
	case strings.HasPrefix(operator, "@"):
		operator = operator[1:]
	default:
		return "rx", true
	}
	name, _, _ := strings.Cut(operator, " ")
	return strings.TrimSpace(name), true
}

// actionNames returns the names of the actions in a rule's action list, in
// lower case, split the way Coraza's parseActions splits them: on commas
// outside single quotes, a backslash escaping the next character, the name
// before the first colon.
func actionNames(actions string) []string {
	var names []string
	start, colon, inQuotes := 0, -1, false
	add := func(end int) {
		if colon < 0 {
			colon = end
		}
		names = append(names, strings.ToLower(strings.TrimSpace(actions[start:colon])))
	}
	for i := 1; i < len(actions); i++ {
		c := actions[i]
		if actions[i-1] == '\\' {
			continue
		}
		if c == '\'' {
			inQuotes = !inQuotes
			continue
		}
		if inQuotes {
			continue
		}
		switch c {
		case ':':
			if colon < 0 {
				colon = i
			}
		case ',':
			add(i)
			start, colon = i+1, -1
		}
	}
	add(len(actions))
	return names
}

// actionValue returns the value of the first action called name (lower
// case) in a rule's action list, split as actionNames splits it, without
// its quotes.
func actionValue(actions, name string) (string, bool) {
	start, inQuotes := 0, false
	for i := 0; i <= len(actions); i++ {
		if i < len(actions) {
			if i > 0 && actions[i-1] == '\\' {
				continue
			}
			if actions[i] == '\'' {
				inQuotes = !inQuotes
			}
			if inQuotes || actions[i] != ',' {
				continue
			}
		}
		n, v, _ := strings.Cut(actions[start:i], ":")
		if strings.EqualFold(strings.TrimSpace(n), name) {
			return strings.Trim(strings.TrimSpace(v), "'"), true
		}
		start = i + 1
	}
	return "", false
}

// CheckReservedIDs refuses rules with an ID from lo to hi, which Inkwall
// reserves for what: an exclusion naming such an ID turns off what it
// names, not the rule. The error is a *RuleError naming the line.
func CheckReservedIDs(rules string, lo, hi int, what string) error {
	dirs, err := SplitDirectives(rules)
	if err != nil {
		return err
	}
	for _, d := range dirs {
		var actions string
		var ok bool
		switch d.Name {
		case "secrule":
			actions, ok = ruleActions(d.Text)
		case "secaction":
			_, args, _ := strings.Cut(d.Text, " ")
			args = strings.TrimSpace(args)
			if ok = len(args) >= 2 && args[0] == '"' && args[len(args)-1] == '"'; ok {
				actions = args[1 : len(args)-1]
			}
		}
		if !ok {
			continue
		}
		v, found := actionValue(actions, "id")
		if !found {
			continue
		}
		if id, err := strconv.Atoi(v); err == nil && id >= lo && id <= hi {
			return &RuleError{Line: d.Line, Err: fmt.Errorf("rule ID %d is reserved for %s (%d-%d): use another ID", id, what, lo, hi)}
		}
	}
	return nil
}

// hasChain reports whether a SecRule directive has the chain action.
func hasChain(text string) bool {
	actions, ok := ruleActions(text)
	return ok && slices.Contains(actionNames(actions), "chain")
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
// CRS rules. Only the directives of UserDirectiveNames are allowed, and the
// last SecRule can't open a chain. The error is a *RuleError naming the line
// of the first problem.
func CheckUserRules(rules string) error {
	dirs, err := SplitDirectives(rules)
	if err != nil {
		return err
	}
	var lastRule *Directive
	for i, d := range dirs {
		if !userDirectives[d.Name] {
			return &RuleError{Line: d.Line, Err: fmt.Errorf("directive %q is not allowed in rule sets (allowed: %s)",
				d.Name, strings.Join(UserDirectiveNames(), ", "))}
		}
		if d.Name == "secrule" {
			if op, ok := ruleOperator(d.Text); ok && !userOperators[op] {
				return &RuleError{Line: d.Line, Err: fmt.Errorf("operator %q is not allowed in rule sets (allowed: %s)",
					op, strings.Join(UserOperatorNames(), ", "))}
			}
			lastRule = &dirs[i]
		}
	}
	// A chain that no SecRule completes still compiles after the CRS, where
	// its starter then matches alone; before the CRS it doesn't load.
	if lastRule != nil && hasChain(lastRule.Text) {
		return &RuleError{Line: lastRule.Line, Err: errors.New("the last SecRule has the chain action but no SecRule follows to complete the chain: " +
			"add the chained rule after it, or remove chain")}
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

// ruleChangers are the user directives that change rules already loaded.
// Before the CRS (Config.DirectivesBeforeCRS) they can't reach its rules:
// SecRuleRemoveBy* would do nothing, and SecRuleUpdate* wouldn't compile.
var ruleChangers = map[string]bool{
	"secruleremovebyid":        true,
	"secruleremovebytag":       true,
	"secruleremovebymsg":       true,
	"secruleupdatetargetbyid":  true,
	"secruleupdatetargetbytag": true,
	"secruleupdateactionbyid":  true,
}

// CheckRulesBeforeCRS checks that rules CheckUserRules accepted can also
// load before the Core Rule Set (Config.DirectivesBeforeCRS): they must
// not change loaded rules, which there would be none of the CRS's. The
// error is a *RuleError naming the line of the first such directive.
func CheckRulesBeforeCRS(rules string) error {
	dirs, err := SplitDirectives(rules)
	if err != nil {
		return err
	}
	for _, d := range dirs {
		if ruleChangers[d.Name] {
			return &RuleError{Line: d.Line, Err: fmt.Errorf("directive %q changes the rules loaded before it, so before the CRS it can't change the CRS's: "+
				"place this rule set AfterCRS (the default), or turn CRS rules off at runtime with a rule using ctl:ruleRemoveById", d.Name)}
		}
	}
	return nil
}

// compileCause strips the wrapping Coraza and New add, keeping the reason.
func compileCause(err error) error {
	msg := err.Error()
	for _, prefix := range []string{"compile rules: ", "invalid WAF config from string: "} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	return errors.New(msg)
}
