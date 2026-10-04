// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package router decides, before any rule runs, how much of a request needs
// inspection (pipeline tier T0). Skipping is how most traffic avoids the cost
// of rule evaluation, so matching is deliberately conservative: a request is
// only skipped when its path is unambiguous.
package router

import (
	"fmt"
	"path"
	"strings"
)

// Decision is how much of a request to inspect.
type Decision uint8

const (
	// InspectAll inspects headers, URI and body. It is the default.
	InspectAll Decision = iota
	// SkipBody inspects headers and URI but not the body.
	SkipBody
	// SkipAll does not inspect the request at all.
	SkipAll
)

// Table maps paths to decisions. The zero value inspects everything. It is
// safe for concurrent use once built.
type Table struct {
	skipAll  []pattern
	skipBody []pattern
}

type pattern struct {
	value  string
	prefix bool
}

// New builds a table. Patterns are exact paths ("/healthz") or prefixes
// ending in "*" ("/static/*"). Patterns must be absolute and clean.
func New(skipAll, skipBody []string) (*Table, error) {
	t := &Table{}
	var err error
	if t.skipAll, err = compile(skipAll); err != nil {
		return nil, err
	}
	if t.skipBody, err = compile(skipBody); err != nil {
		return nil, err
	}
	return t, nil
}

func compile(patterns []string) ([]pattern, error) {
	var out []pattern
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		prefix := strings.HasSuffix(p, "*")
		value := strings.TrimSuffix(p, "*")
		if !strings.HasPrefix(value, "/") {
			return nil, fmt.Errorf("path pattern %q must start with /", p)
		}
		if strings.Contains(value, "*") {
			return nil, fmt.Errorf("path pattern %q: * is only allowed at the end", p)
		}
		if !plainPath(value) {
			return nil, fmt.Errorf("path pattern %q can never match: only plain ASCII path characters are matched (no %%, ;, ?, #, backslash or non-ASCII)", p)
		}
		// Compare against the cleaned form, keeping a trailing slash.
		if c := path.Clean(value); c != strings.TrimSuffix(value, "/") && c != value {
			return nil, fmt.Errorf("path pattern %q is not clean (use %q)", p, c)
		}
		out = append(out, pattern{value: value, prefix: prefix})
	}
	return out, nil
}

// Decide returns the decision for a request URI (path and query, as
// received). Anything that cannot be matched unambiguously is inspected.
func (t *Table) Decide(rawURI string) Decision {
	if t == nil || (len(t.skipAll) == 0 && len(t.skipBody) == 0) {
		return InspectAll
	}
	p, ok := unambiguousPath(rawURI)
	if !ok {
		return InspectAll
	}
	if matchAny(t.skipAll, p) {
		return SkipAll
	}
	if matchAny(t.skipBody, p) {
		return SkipBody
	}
	return InspectAll
}

// unambiguousPath returns the request path if every component that sees it
// (Inkwall, the proxy, the application) would read it the same way. Only
// plain ASCII path characters are accepted (see plainPath); percent-encoding,
// non-ASCII or invalid UTF-8 bytes (fullwidth or overlong dots), backslashes,
// semicolons, repeated slashes and dot segments are rejected, because
// applications differ in how they interpret them, and that difference is how
// a skip rule becomes a bypass.
func unambiguousPath(rawURI string) (string, bool) {
	rawPath, _, _ := strings.Cut(rawURI, "?")
	if rawPath == "" || rawPath[0] != '/' {
		return "", false
	}
	if !plainPath(rawPath) || strings.Contains(rawPath, "//") {
		return "", false
	}
	clean := path.Clean(rawPath)
	if strings.HasSuffix(rawPath, "/") && clean != "/" {
		clean += "/"
	}
	if clean != rawPath {
		return "", false // contained "." or ".." segments
	}
	return rawPath, true
}

// plainPath reports whether s consists only of RFC 3986 path characters that
// need no decoding: unreserved (ALPHA, DIGIT, "-", ".", "_", "~"), "/", ":",
// "@" and the sub-delims except ";". An allowlist, so that no byte an
// application might normalize differently can reach a skip decision.
func plainPath(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-._~/:@!$&'()*+,=", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func matchAny(patterns []pattern, p string) bool {
	for _, pat := range patterns {
		if pat.prefix {
			if strings.HasPrefix(p, pat.value) {
				return true
			}
		} else if p == pat.value {
			return true
		}
	}
	return false
}
