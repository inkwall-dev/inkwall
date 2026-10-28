// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
)

// ingressRouteMatches expands a Traefik IngressRoute into route matches: one
// per route, from its match rule. A rule the engine's matches can't express
// is an error naming the route.
func ingressRouteMatches(ir *unstructured.Unstructured) ([]*bundlev1.RouteMatch, error) {
	routes, _, err := unstructured.NestedSlice(ir.Object, "spec", "routes")
	if err != nil {
		return nil, fmt.Errorf("spec.routes: %w", err)
	}
	var out []*bundlev1.RouteMatch
	seen := map[string]bool{}
	for i, r := range routes {
		route, _ := r.(map[string]any)
		rule, _ := route["match"].(string)
		m, err := parseMatch(rule)
		if err != nil {
			return nil, fmt.Errorf("spec.routes[%d] match %q: %w", i, rule, err)
		}
		// Routes that differ only in what the engine doesn't match on
		// (priority, services) are one route to the engine.
		if k := routeKey(m); !seen[k] {
			seen[k] = true
			out = append(out, m)
		}
	}
	return out, nil
}

// parseMatch reads a Traefik router rule into a route match. It reads Host,
// Path and PathPrefix matchers, each with one string (`...` or "..."), joined
// by && and grouped by parentheses: what the engine can match on. Any other
// rule (||, !, other matchers) is an error saying what can't be read. No Host
// matches any host, no path every path; Traefik's PathPrefix is a string
// prefix, read as an element-wise one (the engine inspects the paths of a
// covered host that match none of its routes with its most general policy).
func parseMatch(rule string) (*bundlev1.RouteMatch, error) {
	p := &matchParser{rule: rule}
	if strings.TrimSpace(rule) == "" {
		return nil, errors.New("the rule is empty")
	}
	if err := p.conjunction(); err != nil {
		return nil, err
	}
	switch tok := p.next(); tok {
	case "":
	case "||":
		return nil, errors.New("|| is not supported: write one route per alternative")
	default:
		return nil, fmt.Errorf("unexpected %q", tok)
	}
	m := &bundlev1.RouteMatch{Host: p.host, Path: p.path}
	if m.Path == nil {
		m.Path = &bundlev1.PathMatch{Type: bundlev1.PathMatchType_PATH_MATCH_TYPE_PREFIX, Value: "/"}
	}
	return m, nil
}

// matchParser is a recursive-descent parser of the rules parseMatch reads:
//
//	conjunction = term { "&&" term }
//	term        = "(" conjunction ")" | matcher "(" string ")"
type matchParser struct {
	rule string
	pos  int
	// What the matchers read so far.
	host     string
	hasHost  bool
	path     *bundlev1.PathMatch
	pathFrom string
}

func (p *matchParser) conjunction() error {
	for {
		if err := p.term(); err != nil {
			return err
		}
		if p.peek() != "&&" {
			return nil
		}
		p.next()
	}
}

func (p *matchParser) term() error {
	switch tok := p.next(); {
	case tok == "(":
		if err := p.conjunction(); err != nil {
			return err
		}
		switch tok := p.next(); tok {
		case ")":
			return nil
		case "||":
			return errors.New("|| is not supported: write one route per alternative")
		default:
			return fmt.Errorf("missing ) before %q", tok)
		}
	case tok == "!":
		return errors.New("! is not supported")
	case isIdent(tok):
		return p.matcher(tok)
	case tok == "":
		return errors.New("the rule ends early")
	default:
		return fmt.Errorf("unexpected %q", tok)
	}
}

func (p *matchParser) matcher(name string) error {
	switch name {
	case "Host", "Path", "PathPrefix":
	default:
		return fmt.Errorf("%s is not supported: only Host, Path and PathPrefix, joined by &&, can be protected", name)
	}
	if tok := p.next(); tok != "(" {
		return fmt.Errorf("missing ( after %s", name)
	}
	var args []string
	for {
		arg, err := p.str()
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		args = append(args, arg)
		if tok := p.next(); tok == ")" {
			break
		} else if tok != "," {
			return fmt.Errorf("%s: missing )", name)
		}
	}
	if len(args) != 1 {
		return fmt.Errorf("%s takes one value, not %d: write one route per value", name, len(args))
	}
	value := args[0]
	if name == "Host" {
		host := strings.ToLower(value)
		switch {
		case host == "" || strings.Contains(host, "*"):
			return fmt.Errorf("Host(%q) is not a host name", value)
		case p.hasHost && host != p.host:
			return errors.New("more than one Host")
		}
		p.host, p.hasHost = host, true
		return nil
	}
	if !strings.HasPrefix(value, "/") {
		return fmt.Errorf("%s(%q) is not an absolute path", name, value)
	}
	// The engine compares clean paths, as it cleans request paths.
	m := &bundlev1.PathMatch{Type: bundlev1.PathMatchType_PATH_MATCH_TYPE_PREFIX, Value: path.Clean(value)}
	if name == "Path" {
		m.Type = bundlev1.PathMatchType_PATH_MATCH_TYPE_EXACT
	}
	if p.path != nil {
		return fmt.Errorf("more than one path matcher (%s and %s)", p.pathFrom, name)
	}
	p.path, p.pathFrom = m, name
	return nil
}

// str reads a string: `raw` or "quoted", as Go writes them.
func (p *matchParser) str() (string, error) {
	p.skipSpace()
	if p.pos >= len(p.rule) {
		return "", errors.New("missing value")
	}
	switch quote := p.rule[p.pos]; quote {
	case '`':
		end := strings.IndexByte(p.rule[p.pos+1:], '`')
		if end < 0 {
			return "", errors.New("unterminated `")
		}
		s := p.rule[p.pos+1 : p.pos+1+end]
		p.pos += end + 2
		return s, nil
	case '"':
		for i := p.pos + 1; i < len(p.rule); i++ {
			switch p.rule[i] {
			case '\\':
				i++
			case '"':
				s, err := strconv.Unquote(p.rule[p.pos : i+1])
				if err != nil {
					return "", fmt.Errorf("bad string %s", p.rule[p.pos:i+1])
				}
				p.pos = i + 1
				return s, nil
			}
		}
		return "", errors.New(`unterminated "`)
	default:
		return "", errors.New("the value must be a string in ` or \"")
	}
}

// next returns the next token and moves past it: "&&", "||", "!", "(",
// ")", ",", an identifier, another character, or "" at the end. Strings
// are read by str.
func (p *matchParser) next() string {
	tok := p.peek()
	p.pos += len(tok)
	return tok
}

func (p *matchParser) peek() string {
	p.skipSpace()
	rest := p.rule[p.pos:]
	switch {
	case rest == "":
		return ""
	case strings.HasPrefix(rest, "&&"), strings.HasPrefix(rest, "||"):
		return rest[:2]
	}
	n := 0
	for n < len(rest) && isIdentByte(rest[n]) {
		n++
	}
	if n == 0 {
		n = 1
	}
	return rest[:n]
}

func (p *matchParser) skipSpace() {
	for p.pos < len(p.rule) && strings.IndexByte(" \t\r\n", p.rule[p.pos]) >= 0 {
		p.pos++
	}
}

func isIdent(tok string) bool { return tok != "" && isIdentByte(tok[0]) }

func isIdentByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}
