// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3/types"
)

// RuleInfo describes one rule of the embedded rules (the OWASP CRS and
// Coraza's recommended rules), from the rule itself: tools show it next to
// a rule ID (inkwallctl explain).
type RuleInfo struct {
	ID int
	// Message is the rule's msg action: what it detects. Rules that only
	// set things up have none.
	Message string
	// Severity is the rule's, lower case ("critical"); "" when it has
	// none.
	Severity string
	// ParanoiaLevel is the CRS paranoia level the rule belongs to
	// (its paranoia-level/N tag); 0 when it has none.
	ParanoiaLevel int
	// File is the CRS rules file (REQUEST-942-...conf); "" for Coraza's.
	File string
}

// msgRE is a rule's msg action, quoted or not.
var msgRE = regexp.MustCompile(`\bmsg:(?:'((?:[^'\\]|\\.)*)'|([^,"']+))`)

// macroRE is a macro in a msg, with the parentheses around it: Coraza
// expands it with the transaction's data, which a description must not
// show.
var macroRE = regexp.MustCompile(`\s*\([^()]*%\{[^}]*\}[^()]*\)|%\{[^}]*\}`)

// embeddedRules reads the embedded rules once: each rule's ID, msg,
// severity and paranoia level.
var embeddedRules = sync.OnceValues(func() (map[int]RuleInfo, error) {
	info := map[int]RuleInfo{}
	_, err := compile(Config{}, func(r types.RuleMetadata) {
		id := r.ID()
		if !inRange(id, crsIDMin, crsIDMax) && !inRange(id, corazaIDMin, corazaIDMax) {
			return
		}
		ri := info[id]
		ri.ID = id
		ri.File = strings.TrimPrefix(r.File(), "@owasp_crs/")
		if m := msgRE.FindStringSubmatch(r.Raw()); m != nil && ri.Message == "" {
			msg := strings.ReplaceAll(m[1]+m[2], `\'`, `'`)
			ri.Message = strings.TrimSpace(macroRE.ReplaceAllString(msg, ""))
		}
		if ri.Severity == "" && r.Severity() >= 0 && strings.Contains(r.Raw(), "severity:") {
			ri.Severity = strings.ToLower(r.Severity().String())
		}
		for _, tag := range r.Tags() {
			if n, ok := strings.CutPrefix(tag, "paranoia-level/"); ok {
				ri.ParanoiaLevel, _ = strconv.Atoi(n)
			}
		}
		info[id] = ri
	})
	return info, err
})

// EmbeddedRule describes the embedded rule with this ID: CRS's (900000 to
// 999999) or Coraza's recommended (200000 to 200099). ok is false for any
// other ID, a rule of the user's own.
func EmbeddedRule(id int) (RuleInfo, bool, error) {
	info, err := embeddedRules()
	if err != nil {
		return RuleInfo{}, false, err
	}
	ri, ok := info[id]
	return ri, ok, nil
}
