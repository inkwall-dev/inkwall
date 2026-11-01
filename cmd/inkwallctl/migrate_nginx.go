// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/pkg/router"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// This file converts ingress-nginx's ModSecurity settings into Inkwall
// objects. It follows ingress-nginx's template (buildModSecurityForLocation
// and the http block of nginx.tmpl): the controller ConfigMap's settings
// apply to every Ingress, then the Ingress's own annotations.

// ingress-nginx's annotations, after the prefix, and ConfigMap keys.
const (
	annEnable        = "enable-modsecurity"
	annCRS           = "enable-owasp-core-rules"
	annSnippet       = "modsecurity-snippet"
	annTransactionID = "modsecurity-transaction-id"
	annCanary        = "canary"

	cmEnable  = "enable-modsecurity"
	cmCRS     = "enable-owasp-modsecurity-crs"
	cmSnippet = "modsecurity-snippet"
)

// The nginx snippets, as annotations and ConfigMap keys, in which nginx's
// own ModSecurity directives (modsecurity, modsecurity_rules...) can turn
// ModSecurity on or add rules besides the settings above.
var (
	annNginxSnippets = []string{"configuration-snippet", "server-snippet"}
	cmNginxSnippets  = []string{"http-snippet", "server-snippet", "location-snippet"}
)

// nginxModSecurity finds nginx's ModSecurity directives in a snippet.
var nginxModSecurity = regexp.MustCompile(`(?i)(^|[\s;{}])modsecurity(_[a-z_]+)?\s`)

// The files ingress-nginx ships: its recommended ModSecurity configuration
// (SecRuleEngine DetectionOnly) and the OWASP CRS.
const (
	nginxRecommendedConf = "/etc/nginx/modsecurity/modsecurity.conf"
	nginxCRSConf         = "/etc/nginx/owasp-modsecurity-crs/nginx-modsecurity.conf"
)

// nginxBodyLimit is SecRequestBodyLimit in ingress-nginx's modsecurity.conf.
const nginxBodyLimit = 13107200

// crsRuleSetName is the ClusterWAFRuleSet with the built-in CRS that
// migrated policies use when they set its paranoia level or threshold, or
// add rules of their own.
const crsRuleSetName = "owasp-crs-v4"

// nginxGlobal is the ModSecurity part of the ingress-nginx ConfigMap.
type nginxGlobal struct {
	enable, crs bool
	snippet     string
	// nginxSnippets are the ConfigMap's nginx snippets with ModSecurity
	// directives, as sources for the report.
	nginxSnippets []string
	// source names the ConfigMap in the report.
	source string
}

// migration is the result for one Ingress: the objects, and what was
// mapped, what to check and what could not be migrated, in order.
type migration struct {
	namespace, name string
	policy          *wafv1alpha1.WAFPolicy
	ruleSet         *wafv1alpha1.WAFRuleSet
	// usesCRSRuleSet is set when the policy refers to crsRuleSetName.
	usesCRSRuleSet bool
	items          []item
}

type itemKind int

const (
	// mapped: converted to an equivalent setting.
	itemMapped itemKind = iota
	// check: converted or left out, with a difference the user should know.
	itemCheck
	// todo: not migrated; it needs a human.
	itemTodo
)

type item struct {
	kind   itemKind
	source string // "annotation modsecurity-snippet, line 3"
	text   string
}

func (m *migration) add(kind itemKind, source, format string, args ...any) {
	m.items = append(m.items, item{kind: kind, source: source, text: fmt.Sprintf(format, args...)})
}

// todos counts the items that need a human.
func (m *migration) todos() int {
	n := 0
	for _, it := range m.items {
		if it.kind == itemTodo {
			n++
		}
	}
	return n
}

// engineState is SecRuleEngine.
type engineState int

const (
	engineUnset engineState = iota
	engineOn
	engineDetectionOnly
	engineOff
)

// modsec is ModSecurity's configuration for one Ingress, as far as it maps
// to a WAFPolicy.
type modsec struct {
	engine       engineState
	engineSource string
	crs          bool
	paranoia     int32
	threshold    int32
	body         wafv1alpha1.BodySpec
	exclusions   []wafv1alpha1.Exclusion
	skip         []wafv1alpha1.PathPattern
	skipBody     []wafv1alpha1.PathPattern
	// bodyLimit is the SecRequestBodyLimit of ingress-nginx's
	// modsecurity.conf when it is loaded; 0 when unknown.
	bodyLimit int64
	// partial is the SecRequestBodyLimitAction ProcessPartial directive, if
	// any, and partialItem the index of its item.
	partial     string
	partialItem int
	// rules are directives kept as they are, in a WAFRuleSet loaded after
	// the CRS, with where they came from.
	rules []rule
}

type rule struct {
	text, source string
	// item is the index of the rule's item in the migration.
	item int
}

// migrateIngress converts the ModSecurity settings of one Ingress, with the
// controller's global ones. prefix is the annotation prefix
// (nginx.ingress.kubernetes.io). It returns nil when ModSecurity doesn't
// apply to the Ingress and it has no ModSecurity annotation.
func migrateIngress(ing *networkingv1.Ingress, global nginxGlobal, prefix string) *migration {
	m := migrateSettings(ing, global, prefix)
	// ingress-nginx serves a canary Ingress's traffic with the main
	// Ingress's settings, not its own.
	if canary, err := strconv.ParseBool(ing.Annotations[prefix+"/"+annCanary]); m == nil || err != nil || !canary {
		return m
	}
	m = &migration{namespace: ing.Namespace, name: ing.Name}
	m.add(itemCheck, "annotation "+annCanary, "a canary Ingress: ingress-nginx applies the main Ingress's ModSecurity settings to it, not its own; no WAFPolicy: the main Ingress's policy covers its hosts and paths")
	return m
}

// migrateSettings is migrateIngress without the canary case.
func migrateSettings(ing *networkingv1.Ingress, global nginxGlobal, prefix string) *migration {
	m := &migration{namespace: ing.Namespace, name: ing.Name}
	ann := func(name string) (string, bool) {
		v, ok := ing.Annotations[prefix+"/"+name]
		return v, ok
	}
	annSource := func(name string) string { return "annotation " + name }
	// As ingress-nginx's parser: an invalid boolean is false, and an
	// invalid enable-modsecurity counts as not set.
	boolAnn := func(name string) (value, set bool) {
		v, ok := ann(name)
		if !ok {
			return false, false
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			m.add(itemCheck, annSource(name), "%q is not a boolean: ingress-nginx reads it as false", v)
			return false, false
		}
		return b, true
	}
	enable, enableSet := boolAnn(annEnable)
	crs, _ := boolAnn(annCRS)
	snippet, _ := ann(annSnippet)
	txID, _ := ann(annTransactionID)
	hasAnnotations := false
	for _, a := range []string{annEnable, annCRS, annSnippet, annTransactionID} {
		if _, ok := ann(a); ok {
			hasAnnotations = true
		}
	}

	// nginx's own ModSecurity directives can't be read with the settings.
	nginxSnippets := slices.Clone(global.nginxSnippets)
	for _, a := range annNginxSnippets {
		if v, _ := ann(a); nginxModSecurity.MatchString(v) {
			nginxSnippets = append(nginxSnippets, annSource(a))
		}
	}
	for _, src := range nginxSnippets {
		m.add(itemTodo, src, "not migrated: nginx's ModSecurity directives (modsecurity, modsecurity_rules...): only enable-modsecurity, enable-owasp-core-rules and modsecurity-snippet are converted; convert them by hand")
	}

	switch {
	case !global.enable && !enable:
		if !hasAnnotations {
			if len(nginxSnippets) > 0 {
				return m
			}
			return nil
		}
		m.add(itemCheck, annSource(annEnable), "ModSecurity is off for this Ingress (enable-modsecurity is not true, nor %s in the ConfigMap): its other ModSecurity annotations have no effect; nothing to migrate", cmEnable)
		return m
	case enableSet && !enable:
		m.add(itemCheck, annSource(annEnable), "false turns ModSecurity off for this Ingress, whatever the ConfigMap says: nothing to migrate")
		return m
	}

	var s modsec
	if global.enable {
		if global.snippet != "" {
			s.apply(m, global.snippet, global.source+" "+cmSnippet)
		} else {
			s.recommended(global.source + " " + cmEnable)
		}
		if global.crs {
			s.crs = true
			m.add(itemMapped, global.source+" "+cmCRS, "the built-in OWASP CRS v4")
		}
	}
	if snippet != "" {
		s.apply(m, snippet, annSource(annSnippet))
	}
	if txID != "" {
		m.add(itemCheck, annSource(annTransactionID), "not migrated: Inkwall has no setting for the ModSecurity transaction ID (logging only; protection is unchanged)")
	}
	if !global.enable && snippet == "" {
		s.recommended(annSource(annEnable))
	}
	if !global.crs && crs {
		s.crs = true
		m.add(itemMapped, annSource(annCRS), "the built-in OWASP CRS v4")
	}
	s.build(m)
	return m
}

// recommended applies ingress-nginx's modsecurity.conf: of what maps to a
// WAFPolicy, it only sets SecRuleEngine DetectionOnly.
func (s *modsec) recommended(source string) {
	s.engine, s.engineSource = engineDetectionOnly, source+" (ingress-nginx's modsecurity.conf)"
	s.bodyLimit = nginxBodyLimit
}

// logOnly are directives that only configure ModSecurity's own logs:
// Inkwall logs verdicts itself, so leaving them out changes no verdict.
var logOnly = map[string]bool{
	"secauditengine": true, "secauditlog": true, "secauditlog2": true, "secauditlogparts": true,
	"secauditlogformat": true, "secauditlogtype": true, "secauditlogstoragedir": true,
	"secauditlogrelevantstatus": true, "secauditlogdirmode": true, "secauditlogfilemode": true,
	"secdebuglog": true, "secdebugloglevel": true, "secstatusengine": true, "seccomponentsignature": true,
}

// apply reads the directives of a modsecurity-snippet.
func (s *modsec) apply(m *migration, snippet, source string) {
	dirs, err := coraza.SplitDirectives(snippet)
	if err != nil {
		m.add(itemTodo, source, "not migrated: can't read it as SecLang: %v", err)
		return
	}
	for _, d := range dirs {
		src := fmt.Sprintf("%s, line %d", source, d.Line)
		args, ok := splitArgs(d.Text)
		if !ok {
			m.add(itemTodo, src, "not migrated: %s: unbalanced quotes", d.Text)
			continue
		}
		arg := func(i int) string {
			if i < len(args) {
				return args[i]
			}
			return ""
		}
		switch d.Name {
		case "secruleengine":
			switch strings.ToLower(arg(1)) {
			case "on":
				s.engine = engineOn
			case "detectiononly":
				s.engine = engineDetectionOnly
			case "off":
				s.engine = engineOff
			default:
				m.add(itemTodo, src, "not migrated: %s: unknown SecRuleEngine value", d.Text)
				continue
			}
			s.engineSource = src
		case "include":
			switch arg(1) {
			case nginxCRSConf:
				s.crs = true
				m.add(itemMapped, src, "%s: the built-in OWASP CRS v4", d.Text)
			case nginxRecommendedConf:
				// It sets the body directives again, over those above it.
				if s.body != (wafv1alpha1.BodySpec{}) {
					s.body, s.partial = wafv1alpha1.BodySpec{}, ""
					m.add(itemTodo, src, "not migrated: %s resets SecRequestBodyAccess, SecRequestBodyLimit and SecRequestBodyLimitAction set above it: those are left out; set body by hand", d.Text)
				}
				s.recommended(src)
			default:
				m.add(itemTodo, src, "not migrated: %s: Inkwall can't read files from the ingress-nginx pod; put the rules in a WAFRuleSet", d.Text)
			}
		case "secrequestbodyaccess":
			on := strings.EqualFold(arg(1), "on")
			if !on && !strings.EqualFold(arg(1), "off") {
				m.add(itemTodo, src, "not migrated: %s: want On or Off", d.Text)
				continue
			}
			s.body.Inspect = &on
			m.add(itemMapped, src, "%s: body.inspect: %t", d.Text, on)
		case "secrequestbodylimit":
			n, err := strconv.ParseInt(arg(1), 10, 64)
			if err != nil || n < 1 {
				m.add(itemTodo, src, "not migrated: %s: not a positive number", d.Text)
				continue
			}
			if n > policyMaxBodyBytes {
				m.add(itemCheck, src, "%s: body.maxBytes: %d, the most Inkwall inspects; bodies between the two limits are now over the limit (body.onOversize)", d.Text, policyMaxBodyBytes)
				n = policyMaxBodyBytes
			} else {
				m.add(itemMapped, src, "%s: body.maxBytes: %d", d.Text, n)
			}
			s.body.MaxBytes = &n
		case "secrequestbodylimitaction":
			switch strings.ToLower(arg(1)) {
			case "reject":
				s.body.OnOversize = wafv1alpha1.OversizeDeny
				s.partial = ""
				m.add(itemMapped, src, "%s: body.onOversize: Deny", d.Text)
			case "processpartial":
				s.body.OnOversize = wafv1alpha1.OversizeAllow
				s.partial, s.partialItem = d.Text, len(m.items)
				m.add(itemCheck, src, "%s: body.onOversize: Allow; ModSecurity inspected the first part of an oversize body, Inkwall forwards it uninspected", d.Text)
			default:
				m.add(itemTodo, src, "not migrated: %s: want Reject or ProcessPartial", d.Text)
			}
		case "secaction":
			s.secAction(m, d.Text, args, src)
		case "secrule":
			s.secRule(m, d.Text, args, src)
		case "secruleremovebyid":
			s.removeByID(m, d.Text, args, src)
		case "secruleupdatetargetbyid":
			s.updateTarget(m, d.Text, args, src)
		case "secmarker", "secruleremovebytag", "secruleremovebymsg", "secruleupdatetargetbytag", "secruleupdateactionbyid":
			s.keep(m, d.Text, src)
		case "secresponsebodyaccess":
			if strings.EqualFold(arg(1), "off") {
				m.add(itemMapped, src, "%s: Inkwall doesn't inspect responses", d.Text)
			} else {
				m.add(itemTodo, src, "not migrated: %s: Inkwall doesn't inspect responses", d.Text)
			}
		default:
			if logOnly[d.Name] {
				m.add(itemCheck, src, "not migrated: %s: ModSecurity's own logs; the engine logs verdicts itself (protection is unchanged)", d.Text)
				continue
			}
			m.add(itemTodo, src, "not migrated: %s: no equivalent in Inkwall", d.Text)
		}
	}
}

// policyMaxBodyBytes is the CRD's limit on body.maxBytes.
const policyMaxBodyBytes = 10 << 20

// keep adds a directive to the policy's WAFRuleSet, loaded after the CRS.
func (s *modsec) keep(m *migration, text, src string) {
	s.rules = append(s.rules, rule{text: text, source: src, item: len(m.items)})
	m.add(itemMapped, src, "kept in the WAFRuleSet: %s", text)
}

// crsVariables are the CRS settings a WAFPolicy has a field for.
var crsVariables = map[string]string{
	"tx.paranoia_level":                  "paranoiaLevel", // CRS v3
	"tx.blocking_paranoia_level":         "paranoiaLevel", // CRS v4
	"tx.inbound_anomaly_score_threshold": "inboundAnomalyThreshold",
}

// secAction maps a SecAction that sets CRS variables (crs-setup.conf's
// 900000, 900110) to the CRS binding's fields; any other SecAction is kept.
func (s *modsec) secAction(m *migration, text string, args []string, src string) {
	if len(args) != 2 {
		m.add(itemTodo, src, "not migrated: %s: want SecAction \"actions\"", text)
		return
	}
	acts := parseActions(args[1])
	var setvars []action
	for _, a := range acts {
		switch {
		case a.name == "setvar" && strings.HasPrefix(strings.ToLower(a.value), "tx."):
			setvars = append(setvars, a)
		case isMetadata(a):
		default:
			// A rule doing more than set variables: keep it.
			s.keep(m, text, src)
			return
		}
	}
	for _, a := range setvars {
		name, value, _ := strings.Cut(a.value, "=")
		name = strings.ToLower(name)
		n, err := strconv.ParseInt(value, 10, 32)
		field := crsVariables[name]
		switch {
		case name == "tx.crs_setup_version":
			m.add(itemCheck, src, "setvar:%s: not needed by the built-in CRS", a.value)
		case name == "tx.outbound_anomaly_score_threshold":
			m.add(itemCheck, src, "not migrated: setvar:%s: Inkwall doesn't inspect responses", a.value)
		case field == "":
			m.add(itemTodo, src, "not migrated: setvar:%s: no WAFPolicy field sets this CRS variable", a.value)
		case err != nil:
			m.add(itemTodo, src, "not migrated: setvar:%s: not a number", a.value)
		case field == "paranoiaLevel" && (n < 1 || n > 4):
			m.add(itemTodo, src, "not migrated: setvar:%s: the paranoia level is 1 to 4", a.value)
		case field == "paranoiaLevel":
			s.paranoia = int32(n)
			m.add(itemMapped, src, "setvar:%s: paranoiaLevel: %d", a.value, n)
		case n < 1 || n > 10000:
			m.add(itemTodo, src, "not migrated: setvar:%s: the threshold is 1 to 10000", a.value)
		default:
			s.threshold = int32(n)
			m.add(itemMapped, src, "setvar:%s: inboundAnomalyThreshold: %d", a.value, n)
		}
	}
}

// secRule maps a rule exclusion keyed on the path:
//
//	SecRule REQUEST_FILENAME "@beginsWith /api/" "id:1000,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
//
// to an exclusion (or a skipped path, for ctl:ruleEngine=Off). Any other
// rule without ctl actions is kept; one with them is reported, since it
// would run after the CRS instead of before.
func (s *modsec) secRule(m *migration, text string, args []string, src string) {
	if len(args) != 4 {
		m.add(itemTodo, src, "not migrated: %s: want SecRule VARIABLES \"OPERATOR\" \"ACTIONS\"", text)
		return
	}
	acts := parseActions(args[3])
	hasCtl := slices.ContainsFunc(acts, func(a action) bool { return a.name == "ctl" })
	if !hasCtl {
		s.keep(m, text, src)
		return
	}
	todo := func(why string) {
		m.add(itemTodo, src, "not migrated: %s: %s", text, why)
	}
	path, why := exclusionPath(args[1], args[2])
	if why != "" {
		todo(why)
		return
	}

	type target struct {
		id  int32
		arg string
	}
	var (
		ids      []int32
		targets  []target
		skip     bool
		skipBody bool
		// Without a phase action, a rule runs in phase 2.
		phase2 = true
		// expanded are the ranges expanded to CRS rule IDs.
		expanded []string
	)
	for _, a := range acts {
		if a.name == "phase" {
			switch a.value {
			case "1":
				phase2 = false
			case "2", "request":
				phase2 = true
			default:
				todo("an exclusion must run in phase 1 or 2")
				return
			}
			continue
		}
		if isMetadata(a) {
			continue
		}
		if a.name != "ctl" {
			todo(fmt.Sprintf("action %s: only ctl actions and metadata (id, phase, pass, nolog, t:none, msg, tag, ver) map to an exclusion", a.name))
			return
		}
		option, value, _ := strings.Cut(a.value, "=")
		switch strings.ToLower(option) {
		case "ruleremovebyid":
			list, err := ruleIDs(value)
			if err != nil {
				todo(fmt.Sprintf("ctl:%s: %v", a.value, err))
				return
			}
			ids = append(ids, list...)
			if strings.Contains(value, "-") {
				expanded = append(expanded, fmt.Sprintf("%s (%d rules)", value, len(list)))
			}
		case "ruleremovetargetbyid":
			idText, t, _ := strings.Cut(value, ";")
			list, err := ruleIDs(idText)
			if err != nil {
				todo(fmt.Sprintf("ctl:%s: %v", a.value, err))
				return
			}
			arg, ok := argsTarget(t)
			if !ok {
				todo(fmt.Sprintf("ctl:%s: only an ARGS:name target maps to an exclusion's argument", a.value))
				return
			}
			for _, id := range list {
				targets = append(targets, target{id, arg})
			}
			if strings.Contains(idText, "-") {
				expanded = append(expanded, fmt.Sprintf("%s (%d rules)", idText, len(list)))
			}
		case "ruleengine":
			if !strings.EqualFold(value, "off") {
				todo(fmt.Sprintf("ctl:%s: only ruleEngine=Off maps (to skip.paths)", a.value))
				return
			}
			skip = true
		case "requestbodyaccess":
			if !strings.EqualFold(value, "off") {
				todo(fmt.Sprintf("ctl:%s: only requestBodyAccess=Off maps (to skip.bodyPaths)", a.value))
				return
			}
			skipBody = true
		default:
			todo(fmt.Sprintf("ctl:%s has no equivalent", a.value))
			return
		}
	}

	// The whole rule maps: apply it.
	var done []string
	for _, id := range ids {
		s.exclude(id, path, "")
	}
	for _, t := range targets {
		s.exclude(t.id, path, t.arg)
	}
	if len(ids)+len(targets) > 0 {
		done = append(done, "exclusions")
	}
	if skip {
		s.skip = appendUnique(s.skip, path)
		done = append(done, "skip.paths")
	}
	if skipBody {
		s.skipBody = appendUnique(s.skipBody, path)
		done = append(done, "skip.bodyPaths")
	}
	m.add(itemMapped, src, "%s: %s on %s", text, strings.Join(done, " and "), path)
	if len(expanded) > 0 {
		m.add(itemCheck, src, "the range(s) %s expanded to the embedded CRS's rules in them: rules a later CRS adds to a range are not excluded", strings.Join(expanded, ", "))
	}
	if phase2 {
		m.add(itemCheck, src, "the rule ran in phase 2; Inkwall applies exclusions from phase 1, so the excluded rules' phase 1 checks are off on %s too", path)
	}
}

// exclusionPath returns the path pattern of a rule's variable and operator,
// or why it has none.
func exclusionPath(variable, operator string) (wafv1alpha1.PathPattern, string) {
	variable = strings.ToUpper(variable)
	op, value, _ := strings.Cut(operator, " ")
	op = strings.ToLower(op)
	var p string
	switch {
	case variable != "REQUEST_FILENAME" && variable != "REQUEST_URI":
		return "", "only an exclusion keyed on REQUEST_FILENAME or REQUEST_URI maps to a path"
	case op == "@beginswith":
		p = value + "*"
	case op == "@streq" && variable == "REQUEST_FILENAME" && strings.Contains(value, "*"):
		// A * ending a WAFPolicy path makes it a prefix.
		return "", "@streq matches a path with * literally, which a WAFPolicy path can't"
	case op == "@streq" && variable == "REQUEST_FILENAME":
		p = value
	default:
		// REQUEST_URI has the query: @streq on it matches no URI with one.
		return "", "only @beginsWith (on REQUEST_FILENAME or REQUEST_URI) or @streq (on REQUEST_FILENAME) maps to a path"
	}
	if !pathPattern.MatchString(p) {
		return "", fmt.Sprintf("path %q has characters a WAFPolicy path can't", value)
	}
	if _, err := router.New([]string{p}, nil); err != nil {
		return "", err.Error()
	}
	return wafv1alpha1.PathPattern(p), ""
}

// pathPattern is the CRD's pattern for a PathPattern.
var pathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~/:@!$&'()+,=-]*\*?$`)

// argumentPattern is the CRD's pattern for an exclusion's argument.
var argumentPattern = regexp.MustCompile(`^[A-Za-z0-9_.\-\[\]]+$`)

// argsTarget returns the argument of an ARGS:name target.
func argsTarget(target string) (string, bool) {
	name, ok := strings.CutPrefix(target, "ARGS:")
	if !ok || !argumentPattern.MatchString(name) {
		return "", false
	}
	return name, true
}

// ruleID parses one rule ID.
func ruleID(s string) (int32, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 32)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%q is not a single rule ID", s)
	}
	return int32(n), nil
}

// The IDs the OWASP CRS reserves: a range within them only removes CRS
// rules, which the engine embeds.
const (
	crsIDMin = 900000
	crsIDMax = 999999
)

// ruleIDs parses a ctl rule ID: one ID, or a range of CRS IDs expanded to
// the embedded CRS's rules in it. A range reaching outside the CRS IDs
// could remove the user's own rules too, which an exclusion can't express.
func ruleIDs(s string) ([]int32, error) {
	lo, hi, isRange := strings.Cut(strings.TrimSpace(s), "-")
	if !isRange {
		id, err := ruleID(s)
		return []int32{id}, err
	}
	from, err1 := ruleID(lo)
	to, err2 := ruleID(hi)
	switch {
	case err1 != nil || err2 != nil || from > to:
		return nil, fmt.Errorf("%q is not a rule ID or range", s)
	case from < crsIDMin || to > crsIDMax:
		return nil, fmt.Errorf("the range %s reaches outside the CRS rule IDs (%d-%d): only a range of CRS rules maps to an exclusion", s, crsIDMin, crsIDMax)
	}
	crs, err := coraza.CRSRuleIDs()
	if err != nil {
		return nil, err
	}
	var ids []int32
	for _, id := range crs {
		if id >= int(from) && id <= int(to) {
			ids = append(ids, int32(id)) // #nosec G115 -- a CRS ID, at most crsIDMax
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("the range %s has no CRS rule", s)
	}
	return ids, nil
}

// removeByID maps SecRuleRemoveById with single IDs to an exclusion
// everywhere; with a range, it is kept.
func (s *modsec) removeByID(m *migration, text string, args []string, src string) {
	var ids []int32
	for _, a := range args[1:] {
		id, err := ruleID(a)
		if err != nil {
			s.keep(m, text, src)
			return
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		m.add(itemTodo, src, "not migrated: %s: no rule ID", text)
		return
	}
	for _, id := range ids {
		s.exclude(id, "", "")
	}
	m.add(itemMapped, src, "%s: exclusions", text)
}

// updateTarget maps SecRuleUpdateTargetById ID "!ARGS:a|!ARGS:b" to
// exclusions of those arguments; any other form is kept.
func (s *modsec) updateTarget(m *migration, text string, args []string, src string) {
	if len(args) != 3 {
		s.keep(m, text, src)
		return
	}
	id, err := ruleID(args[1])
	if err != nil {
		s.keep(m, text, src)
		return
	}
	var names []string
	for _, t := range strings.Split(args[2], "|") {
		name, ok := argsTarget(strings.TrimPrefix(t, "!"))
		if !ok || !strings.HasPrefix(t, "!") {
			s.keep(m, text, src)
			return
		}
		names = append(names, name)
	}
	for _, n := range names {
		s.exclude(id, "", n)
	}
	m.add(itemMapped, src, "%s: exclusions", text)
}

// exclude adds a rule ID to the exclusion for path and argument.
func (s *modsec) exclude(id int32, path wafv1alpha1.PathPattern, argument string) {
	for i := range s.exclusions {
		e := &s.exclusions[i]
		var p wafv1alpha1.PathPattern
		var a string
		if e.When != nil {
			p, a = e.When.Path, e.When.Argument
		}
		if p == path && a == argument && len(e.RuleIDs) < maxExclusionIDs {
			if !slices.Contains(e.RuleIDs, id) {
				e.RuleIDs = append(e.RuleIDs, id)
			}
			return
		}
	}
	e := wafv1alpha1.Exclusion{RuleIDs: []int32{id}}
	if path != "" || argument != "" {
		e.When = &wafv1alpha1.ExclusionMatch{Path: path, Argument: argument}
	}
	s.exclusions = append(s.exclusions, e)
}

// The CRD's limits.
const (
	maxExclusionIDs = 64
	maxExclusions   = 128
	maxSkipPaths    = 64
)

func appendUnique(list []wafv1alpha1.PathPattern, p wafv1alpha1.PathPattern) []wafv1alpha1.PathPattern {
	if slices.Contains(list, p) {
		return list
	}
	return append(list, p)
}

// build makes the policy and rule set.
func (s *modsec) build(m *migration) {
	if s.engine == engineOff {
		m.add(itemCheck, s.engineSource, "SecRuleEngine Off: ModSecurity inspects nothing; nothing to migrate")
		return
	}

	// Rules kept as SecLang must load: drop (and report) those the
	// validating webhook would reject, one at a time.
	for len(s.rules) > 0 {
		var b strings.Builder
		starts := make([]int, len(s.rules)) // the line each rule starts on
		line := 1
		for i, r := range s.rules {
			starts[i] = line
			b.WriteString(r.text)
			b.WriteString("\n")
			line += strings.Count(r.text, "\n") + 1
		}
		err := coraza.CheckUserRules(b.String())
		if err == nil {
			break
		}
		bad := len(s.rules) - 1
		var re *coraza.RuleError
		if errors.As(err, &re) && re.Line >= 1 {
			for i, start := range starts {
				if start <= re.Line {
					bad = i
				}
			}
			err = re.Err
		}
		r := s.rules[bad]
		m.items[r.item] = item{kind: itemTodo, source: r.source, text: fmt.Sprintf("not migrated: %s: the engine rejects it: %v", r.text, err)}
		s.rules = slices.Delete(s.rules, bad, bad+1)
	}
	for _, r := range s.rules {
		if strings.Contains(strings.ToLower(r.text), "ctl:") {
			m.add(itemCheck, r.source, "kept rule with a ctl action now runs after the CRS, not before: check what it changes")
		}
	}

	if !s.crs {
		if s.paranoia != 0 || s.threshold != 0 {
			m.add(itemCheck, "", "a CRS paranoia level or threshold is set but the CRS is not loaded: left out")
			s.paranoia, s.threshold = 0, 0
		}
		if len(s.rules) == 0 {
			m.add(itemCheck, "", "ModSecurity is on but runs no rules besides its own configuration's: nothing to migrate")
			return
		}
	}

	var mode wafv1alpha1.PolicyMode
	switch s.engine {
	case engineOn:
		mode = wafv1alpha1.PolicyBlock
		m.add(itemMapped, s.engineSource, "SecRuleEngine On: mode: Block")
	case engineDetectionOnly:
		mode = wafv1alpha1.PolicyDetect
		m.add(itemMapped, s.engineSource, "SecRuleEngine DetectionOnly: mode: Detect")
	default:
		mode = wafv1alpha1.PolicyDetect
		m.add(itemCheck, "", "no SecRuleEngine in the effective configuration: mode: Detect; set mode: Block once the verdicts look right")
	}
	p := &wafv1alpha1.WAFPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: wafv1alpha1.GroupVersion.String(), Kind: "WAFPolicy"},
		ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: m.name},
		Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: m.name}},
			Mode:       mode,
		},
	}
	if s.crs && (s.paranoia != 0 || s.threshold != 0 || len(s.rules) > 0) {
		b := wafv1alpha1.RuleSetBinding{Ref: wafv1alpha1.RuleSetRef{Kind: "ClusterWAFRuleSet", Name: crsRuleSetName}}
		if s.paranoia != 0 {
			b.ParanoiaLevel = &s.paranoia
		}
		if s.threshold != 0 {
			b.InboundAnomalyThreshold = &s.threshold
		}
		p.Spec.RuleSets = append(p.Spec.RuleSets, b)
		m.usesCRSRuleSet = true
	}
	if len(s.rules) > 0 {
		name := m.name + "-modsecurity"
		var b strings.Builder
		for _, r := range s.rules {
			fmt.Fprintf(&b, "# %s\n%s\n", r.source, r.text)
		}
		m.ruleSet = &wafv1alpha1.WAFRuleSet{
			TypeMeta:   metav1.TypeMeta{APIVersion: wafv1alpha1.GroupVersion.String(), Kind: "WAFRuleSet"},
			ObjectMeta: metav1.ObjectMeta{Namespace: m.namespace, Name: name},
			Spec:       wafv1alpha1.WAFRuleSetSpec{Source: wafv1alpha1.RuleSetSource{SecLang: b.String()}},
		}
		p.Spec.RuleSets = append(p.Spec.RuleSets, wafv1alpha1.RuleSetBinding{Ref: wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: name}})
	}
	if len(s.exclusions) > maxExclusions {
		m.add(itemTodo, "", "%d exclusions, more than a WAFPolicy's %d: the last %d are left out", len(s.exclusions), maxExclusions, len(s.exclusions)-maxExclusions)
		s.exclusions = s.exclusions[:maxExclusions]
	}
	p.Spec.Exclusions = s.exclusions
	for _, list := range []*[]wafv1alpha1.PathPattern{&s.skip, &s.skipBody} {
		if len(*list) > maxSkipPaths {
			m.add(itemTodo, "", "%d skipped paths, more than a WAFPolicy's %d: the last %d are left out", len(*list), maxSkipPaths, len(*list)-maxSkipPaths)
			*list = (*list)[:maxSkipPaths]
		}
	}
	if len(s.skip) > 0 || len(s.skipBody) > 0 {
		p.Spec.Skip = &wafv1alpha1.SkipSpec{Paths: s.skip, BodyPaths: s.skipBody}
	}
	if s.partial != "" && s.body.MaxBytes == nil {
		// ProcessPartial inspected bodies up to SecRequestBodyLimit, not
		// up to the engine's default.
		it := &m.items[s.partialItem]
		if s.bodyLimit == 0 {
			*it = item{kind: itemTodo, source: it.source, text: fmt.Sprintf("not migrated: %s without SecRequestBodyLimit: how much ModSecurity inspected is unknown; set body.maxBytes and body.onOversize: Allow", s.partial)}
			s.body.OnOversize = ""
		} else {
			n := min(s.bodyLimit, policyMaxBodyBytes)
			s.body.MaxBytes = &n
			*it = item{kind: itemCheck, source: it.source, text: fmt.Sprintf("%s: body.onOversize: Allow and body.maxBytes: %d, modsecurity.conf's SecRequestBodyLimit (%d) capped at the most Inkwall inspects; ModSecurity inspected the first part of an oversize body, Inkwall forwards it uninspected", s.partial, n, s.bodyLimit)}
		}
	}
	if s.body != (wafv1alpha1.BodySpec{}) {
		p.Spec.Body = &s.body
	}
	m.policy = p
}

// action is one action of a SecRule or SecAction.
type action struct {
	name, value string
}

// metadataActions don't change what a rule does to the request.
var metadataActions = map[string]bool{
	"id": true, "pass": true, "nolog": true, "log": true, "noauditlog": true, "auditlog": true,
	"msg": true, "tag": true, "ver": true, "rev": true, "severity": true, "maturity": true, "accuracy": true,
}

func isMetadata(a action) bool {
	return metadataActions[a.name] || a.name == "phase" || (a.name == "t" && strings.EqualFold(a.value, "none"))
}

// parseActions splits a SecLang action list on the commas outside single
// quotes, and each action into its lower-case name and its value without
// quotes.
func parseActions(s string) []action {
	var out []action
	var cur strings.Builder
	quoted := false
	flush := func() {
		text := strings.TrimSpace(cur.String())
		cur.Reset()
		if text == "" {
			return
		}
		name, value, _ := strings.Cut(text, ":")
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			value = value[1 : len(value)-1]
		}
		out = append(out, action{name: strings.ToLower(strings.TrimSpace(name)), value: value})
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(c)
			i++
			cur.WriteByte(s[i])
		case c == '\'':
			quoted = !quoted
			cur.WriteByte(c)
		case c == ',' && !quoted:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// splitArgs splits a directive into its name and arguments: words, or
// double-quoted strings in which \" is a quote.
func splitArgs(s string) ([]string, bool) {
	var out []string
	for i := 0; i < len(s); {
		switch s[i] {
		case ' ', '\t', '\n':
			i++
		case '"':
			var b strings.Builder
			i++
			for ; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && s[i+1] == '"' {
					i++
				}
				b.WriteByte(s[i])
			}
			if i >= len(s) {
				return nil, false
			}
			i++
			out = append(out, b.String())
		default:
			j := i
			for j < len(s) && s[j] != ' ' && s[j] != '\t' && s[j] != '\n' {
				j++
			}
			out = append(out, s[i:j])
			i = j
		}
	}
	return out, true
}

// ingressClass returns an Ingress's class, from its spec or the
// kubernetes.io/ingress.class annotation.
func ingressClass(ing *networkingv1.Ingress) string {
	if c := ing.Spec.IngressClassName; c != nil {
		return *c
	}
	return ing.Annotations["kubernetes.io/ingress.class"]
}

// sortMigrations orders results by namespace and name.
func sortMigrations(ms []*migration) {
	slices.SortFunc(ms, func(a, b *migration) int {
		return cmp.Or(cmp.Compare(a.namespace, b.namespace), cmp.Compare(a.name, b.name))
	})
}
