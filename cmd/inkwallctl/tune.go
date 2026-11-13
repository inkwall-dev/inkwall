// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/resolver"
	"github.com/inkwall-dev/inkwall/pkg/policy"
)

const tuneUsage = "usage: inkwallctl tune [--from-logs] [--policy FILE ...] [--rule-set FILE ...] [--configmap FILE ...] [--ingress FILE ...] [--broad] [-o text|yaml] FILE ..."

// tuneConfig holds the flags of inkwallctl tune.
type tuneConfig struct {
	fromLogs bool
	broad    bool
	output   string
	// minCount: groups seen fewer times aren't suggested.
	minCount int
	// The WAF objects, to validate the suggestions and write the patched
	// policies; optional.
	objects config
	files   []string
}

func parseTuneFlags(args []string, stderr io.Writer) (tuneConfig, error) {
	var cfg tuneConfig
	fs := flag.NewFlagSet("tune", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, tuneUsage)
		fmt.Fprintln(stderr, "Reads security events (Detect mode's, or Block mode's false positives) and suggests the narrowest exclusions: a rule, on one path, for one argument, argument name, cookie or header. FILE is '-' for standard input.")
		fs.PrintDefaults()
	}
	fs.BoolVar(&cfg.fromLogs, "from-logs", false, "the files are engine logs (kubectl logs -c inkwall-engine): their \"security event\" lines; without it, one security event per line, as JSON (the events API's)")
	fs.BoolVar(&cfg.broad, "broad", false, "also suggest a rule off for every variable on a path, when what it matched has no exclusion field (the request body, the URI); never a rule off for every path")
	fs.StringVar(&cfg.output, "o", "text", "output: text (the report), or yaml (with --policy: the WAFPolicies with the exclusions added; otherwise the exclusions to add, by policy)")
	fs.IntVar(&cfg.minCount, "min-count", 1, "suggest only for a rule, path and variable seen at least this many times")
	fs.Var(&cfg.objects.policies, "policy", "WAFPolicy YAML file: the suggestions are validated against it, as inkwallctl test --policy does, and -o yaml writes it patched (repeatable)")
	fs.Var(&cfg.objects.ruleSets, "rule-set", "WAFRuleSet or ClusterWAFRuleSet YAML file the policies use (repeatable)")
	fs.Var(&cfg.objects.configMaps, "configmap", "ConfigMap YAML file rule sets read rules from (repeatable)")
	fs.Var(&cfg.objects.ingresses, "ingress", "Ingress, IngressRoute, HTTPRoute or VirtualService YAML file the policies target (repeatable)")
	fs.StringVar(&cfg.objects.namespace, "namespace", "default", "namespace of the objects that don't name one")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	cfg.files = fs.Args()
	switch {
	case len(cfg.files) == 0:
		return cfg, errors.New("give the events or log files, or - for standard input")
	case cfg.output != "text" && cfg.output != "yaml":
		return cfg, fmt.Errorf("-o: %q, want text or yaml", cfg.output)
	case cfg.minCount < 1:
		return cfg, fmt.Errorf("--min-count: %d, want 1 or more", cfg.minCount)
	case len(cfg.objects.policies) == 0 && cfg.objects.policyFiles():
		return cfg, errors.New("--rule-set, --configmap and --ingress need --policy")
	}
	return cfg, nil
}

func runTune(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cfg, err := parseTuneFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	var evs []tuneEvent
	for _, f := range cfg.files {
		r := stdin
		if f != "-" {
			fh, err := os.Open(f) // #nosec G304 -- a file the user names
			if err != nil {
				fmt.Fprintln(stderr, "error:", err)
				return 2
			}
			defer fh.Close()
			r = fh
		}
		read, err := readTuneEvents(r, cfg.fromLogs)
		if err != nil {
			fmt.Fprintf(stderr, "error: %s: %v\n", f, err)
			return 2
		}
		evs = append(evs, read...)
	}
	rep := tune(evs, cfg.broad, cfg.minCount)
	if cfg.objects.policyFiles() {
		if err := rep.validate(cfg.objects, stderr); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
	}
	if cfg.output == "yaml" {
		out, err := rep.yaml()
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		fmt.Fprint(stdout, out)
		return 0
	}
	rep.print(stdout)
	return 0
}

// tuneEvent is a security event, from the events API or an engine's log.
// Every field but Policy is the request's or comes from it: data written
// by the client.
type tuneEvent struct {
	Policy    string
	Path      string
	Action    string
	Reason    string
	RequestID string
	ClientIP  string
	Matches   []tuneMatch
	// For inkwallctl explain: the rest of the event.
	Phase, Method, Host                string
	Status, AnomalyScore, Interrupting int
}

type tuneMatch struct {
	RuleID   int
	Variable string
}

// readTuneEvents reads JSON lines: engine log lines (fromLogs: only the
// "security event" ones) or events, with protojson's camelCase names or
// the proto's snake_case ones.
func readTuneEvents(r io.Reader, fromLogs bool) ([]tuneEvent, error) {
	lines := eventsOnly
	if fromLogs {
		lines = logLines
	}
	return readEvents(r, lines, nil)
}

// eventLines is what readEvents reads.
type eventLines int

const (
	// eventsOnly: one event per line, the events API's; any other line is
	// an error.
	eventsOnly eventLines = iota
	// logLines: an engine's log, of which the "security event" lines are
	// read and the others skipped.
	logLines
	// anyLines: either, line by line; lines that are neither are skipped.
	anyLines
)

// readEvents reads the security events in r. keep, if set, is asked first
// about every line: it skips the lines it returns false for, unparsed.
func readEvents(r io.Reader, lines eventLines, keep func(string) bool) ([]tuneEvent, error) {
	fromLogs := lines != eventsOnly
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var evs []tuneEvent
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || (keep != nil && !keep(text)) {
			continue
		}
		if fromLogs {
			// kubectl logs --prefix, or a timestamp: the JSON starts at
			// the first brace.
			if i := strings.IndexByte(text, '{'); i > 0 {
				text = text[i:]
			}
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(text), &raw); err != nil {
			if fromLogs {
				continue // not a JSON log line
			}
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		_, isLog := raw["msg"]
		if fromLogs && (lines == logLines || isLog) && str(raw, "msg") != "security event" {
			continue
		}
		ev := tuneEvent{
			Policy:    str(raw, "policy"),
			Path:      str(raw, "path"),
			Action:    strings.ToLower(strings.TrimPrefix(str(raw, "action"), "ACTION_")),
			Reason:    strings.ToLower(strings.TrimPrefix(str(raw, "reason"), "REASON_")),
			RequestID: str(raw, "request_id", "requestId"),
			ClientIP:  str(raw, "client_ip", "clientIp"),
			Phase:     strings.ToLower(strings.TrimPrefix(str(raw, "phase"), "PHASE_")),
			Method:    str(raw, "method"),
			Host:      str(raw, "host"),
		}
		ev.Status, _ = strconv.Atoi(str(raw, "status"))
		ev.AnomalyScore, _ = strconv.Atoi(str(raw, "anomaly_score", "anomalyScore"))
		ev.Interrupting, _ = strconv.Atoi(str(raw, "interrupting_rule_id", "interruptingRuleId"))
		var matches []map[string]json.RawMessage
		if m, ok := raw["matches"]; ok {
			if err := json.Unmarshal(m, &matches); err != nil {
				return nil, fmt.Errorf("line %d: matches: %w", line, err)
			}
		}
		for _, m := range matches {
			// Rule IDs are int32s in the bundle: one out of its range is
			// no rule (0), not another rule's ID.
			id, err := strconv.ParseInt(str(m, "rule_id", "ruleId"), 10, 32)
			if err != nil {
				id = 0
			}
			ev.Matches = append(ev.Matches, tuneMatch{RuleID: int(id), Variable: str(m, "variable")})
		}
		evs = append(evs, ev)
	}
	return evs, sc.Err()
}

// str returns the first of keys that holds a JSON string or number, as
// text.
func str(m map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		raw, ok := m[k]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
		return string(raw)
	}
	return ""
}

// The variables an exclusion can name (ExclusionMatch).
const (
	targetArgument     = "argument"
	targetArgumentName = "argumentName"
	targetCookie       = "cookie"
	targetHeader       = "header"
)

// nameRE is the syntax of an exclusion's argument, cookie or header.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9_.\-\[\]]{1,256}$`)

// pathRE is an exact path a WAFPolicy can name (PathPattern, without a
// trailing *).
var pathRE = regexp.MustCompile(`^/[A-Za-z0-9._~/:@!$&'()+,=-]*$`)

// target returns the exclusion field and name for a matched variable, ""
// when no field can name it.
func target(variable string) (field, name string) {
	collection, key, ok := strings.Cut(variable, ":")
	if !ok || !nameRE.MatchString(key) {
		return "", ""
	}
	switch strings.ToUpper(collection) {
	case "ARGS", "ARGS_GET", "ARGS_POST":
		return targetArgument, key
	case "ARGS_NAMES", "ARGS_GET_NAMES", "ARGS_POST_NAMES":
		return targetArgumentName, key
	case "REQUEST_COOKIES":
		return targetCookie, key
	case "REQUEST_HEADERS":
		return targetHeader, key
	}
	return "", ""
}

// scoreRule reports a rule that only sums up the anomaly score (the CRS's
// 949xxx, 959xxx and 980xxx): excluding it would turn the policy off, and
// the rules that added to the score are what to tune.
func scoreRule(id int, variable string) bool {
	switch id / 1000 {
	case 949, 959, 980:
		return true
	}
	return strings.HasPrefix(strings.ToUpper(variable), "TX:")
}

// tuneGroup is one rule matching one variable on one path of one policy.
type tuneGroup struct {
	Policy, Path, Variable string
	RuleID                 int
	Count                  int
	clients, ids           map[string]bool
	SampleIDs              []string
	// Field and Name: what the exclusion names; "" when nothing can.
	Field, Name string
	// Why it isn't suggested, when it isn't.
	Skip string
}

func (g *tuneGroup) Clients() int { return len(g.clients) }

// tuneReport is the grouped events and the suggested exclusions.
type tuneReport struct {
	Events int
	// WouldDeny counts the logged requests (Detect mode) Block mode would
	// deny, by policy.
	WouldDeny map[string]int
	Groups    []*tuneGroup
	// Suggestions are the exclusions to add, by policy.
	Suggestions map[string][]wafv1alpha1.Exclusion
	// Patched are the policies with the exclusions added (validate).
	Patched []wafv1alpha1.WAFPolicy
}

// tune groups the events' matches by policy, path, rule and variable, and
// suggests an exclusion for each group seen at least minCount times: the
// rule, on the exact path, for the argument, argument name, cookie or
// header it matched. Rules that matched the same variable on the same path
// share one exclusion. Never a rule for every path; a rule for every
// variable on a path only with broad.
func tune(evs []tuneEvent, broad bool, minCount int) *tuneReport {
	rep := &tuneReport{Events: len(evs), WouldDeny: map[string]int{}, Suggestions: map[string][]wafv1alpha1.Exclusion{}}
	groups := map[string]*tuneGroup{}
	denied := map[string]map[string]bool{}
	for _, ev := range evs {
		if ev.Action == "log" && ev.Reason == "rule" {
			if denied[ev.Policy] == nil {
				denied[ev.Policy] = map[string]bool{}
			}
			denied[ev.Policy][cmp.Or(ev.RequestID, strconv.Itoa(len(denied[ev.Policy])))] = true
		}
		for _, m := range ev.Matches {
			if m.RuleID == 0 || scoreRule(m.RuleID, m.Variable) {
				continue
			}
			key := strings.Join([]string{ev.Policy, ev.Path, strconv.Itoa(m.RuleID), m.Variable}, "\x00")
			g := groups[key]
			if g == nil {
				g = &tuneGroup{Policy: ev.Policy, Path: ev.Path, Variable: m.Variable, RuleID: m.RuleID,
					clients: map[string]bool{}, ids: map[string]bool{}}
				g.Field, g.Name = target(m.Variable)
				groups[key] = g
			}
			g.Count++
			if ev.ClientIP != "" {
				g.clients[ev.ClientIP] = true
			}
			if ev.RequestID != "" && !g.ids[ev.RequestID] && len(g.SampleIDs) < 3 {
				g.ids[ev.RequestID] = true
				g.SampleIDs = append(g.SampleIDs, ev.RequestID)
			}
		}
	}
	for p, ids := range denied {
		rep.WouldDeny[p] = len(ids)
	}
	for _, g := range groups {
		rep.Groups = append(rep.Groups, g)
	}
	slices.SortFunc(rep.Groups, func(a, b *tuneGroup) int {
		return cmp.Or(strings.Compare(a.Policy, b.Policy), b.Count-a.Count, strings.Compare(a.Path, b.Path),
			a.RuleID-b.RuleID, strings.Compare(a.Variable, b.Variable))
	})

	// exclusions by policy, then by (path, field, name).
	type exKey struct{ path, field, name string }
	byKey := map[string]map[exKey]*wafv1alpha1.Exclusion{}
	var order []struct {
		policy string
		key    exKey
	}
	for _, g := range rep.Groups {
		switch {
		case g.Policy == "":
			g.Skip = "no policy: the request wasn't inspected by a WAFPolicy"
		case g.Count < minCount:
			g.Skip = fmt.Sprintf("seen %d times, under --min-count", g.Count)
		case !pathRE.MatchString(g.Path):
			g.Skip = "the path has characters a WAFPolicy path can't hold"
		case g.Field == "" && !broad:
			g.Skip = "no exclusion field names " + g.Variable + ": --broad would turn the rule off for every variable on the path"
		}
		if g.Skip != "" {
			continue
		}
		k := exKey{g.Path, g.Field, g.Name}
		if byKey[g.Policy] == nil {
			byKey[g.Policy] = map[exKey]*wafv1alpha1.Exclusion{}
		}
		ex := byKey[g.Policy][k]
		if ex == nil {
			ex = &wafv1alpha1.Exclusion{When: &wafv1alpha1.ExclusionMatch{Path: wafv1alpha1.PathPattern(g.Path)}}
			switch g.Field {
			case targetArgument:
				ex.When.Argument = g.Name
			case targetArgumentName:
				ex.When.ArgumentName = g.Name
			case targetCookie:
				ex.When.Cookie = g.Name
			case targetHeader:
				ex.When.Header = g.Name
			}
			byKey[g.Policy][k] = ex
			order = append(order, struct {
				policy string
				key    exKey
			}{g.Policy, k})
		}
		if g.RuleID < math.MinInt32 || g.RuleID > math.MaxInt32 {
			continue // readTuneEvents reads none
		}
		id := int32(g.RuleID)
		if !slices.Contains(ex.RuleIDs, id) {
			ex.RuleIDs = append(ex.RuleIDs, id)
		}
	}
	for _, o := range order {
		ex := byKey[o.policy][o.key]
		slices.Sort(ex.RuleIDs)
		rep.Suggestions[o.policy] = append(rep.Suggestions[o.policy], *ex)
	}
	for p := range rep.Suggestions {
		slices.SortFunc(rep.Suggestions[p], func(a, b wafv1alpha1.Exclusion) int {
			return cmp.Or(strings.Compare(string(a.When.Path), string(b.When.Path)), strings.Compare(describeWhen(a.When), describeWhen(b.When)))
		})
	}
	return rep
}

// validate adds the suggestions to the policies in the files, and checks
// them as inkwallctl test --policy does: resolved as the operator does,
// and compiled as the engine does.
func (rep *tuneReport) validate(objects config, notes io.Writer) error {
	files := slices.Concat(objects.policies, objects.ruleSets, objects.configMaps, objects.ingresses)
	in, suspended, err := loadObjects(files, objects.namespace, notes)
	if err != nil {
		return err
	}
	_, err = rep.validateInput(in, suspended, notes)
	if errors.Is(err, errExclusionLimit) {
		return fmt.Errorf("%w: raise --min-count", err)
	}
	return err
}

// errExclusionLimit: a policy would have more exclusions than it takes.
var errExclusionLimit = errors.New("over the 64 a policy takes")

// validateInput adds the suggestions to the policies of in, and checks them
// as validate does. It returns the bundle the operator would publish with
// them. in's policies are changed.
func (rep *tuneReport) validateInput(in resolver.Input, suspended bool, notes io.Writer) (*bundlev1.Bundle, error) {
	for i := range in.Policies {
		p := &in.Policies[i]
		add := rep.Suggestions[resolver.PolicyID(p.Namespace, p.Name)]
		if len(add) == 0 {
			continue
		}
		p.Spec.Exclusions = append(p.Spec.Exclusions, add...)
		if n := len(p.Spec.Exclusions); n > 64 {
			return nil, fmt.Errorf("WAFPolicy %s/%s would have %d exclusions, %w", p.Namespace, p.Name, n, errExclusionLimit)
		}
		rep.Patched = append(rep.Patched, *p)
	}
	for id := range rep.Suggestions {
		ns, name, _ := strings.Cut(id, "/")
		if !slices.ContainsFunc(in.Policies, func(p wafv1alpha1.WAFPolicy) bool {
			return types.NamespacedName{Namespace: p.Namespace, Name: p.Name} == types.NamespacedName{Namespace: ns, Name: name}
		}) {
			fmt.Fprintf(notes, "note: WAFPolicy %s is not in the --policy files: its suggestions aren't validated\n", id)
		}
	}
	b, err := inputBundle(in, suspended, notes)
	if err != nil {
		return nil, fmt.Errorf("the policies with the suggestions: %w", err)
	}
	if _, err := policy.Compile(b, policy.Options{}); err != nil {
		return nil, fmt.Errorf("the engine would reject the policies with the suggestions: %w", err)
	}
	return b, nil
}

func describeWhen(w *wafv1alpha1.ExclusionMatch) string {
	switch {
	case w.Argument != "":
		return "argument " + w.Argument
	case w.ArgumentName != "":
		return "argument name " + w.ArgumentName
	case w.Cookie != "":
		return "cookie " + w.Cookie
	case w.Header != "":
		return "header " + w.Header
	}
	return "every variable"
}

// print writes the report as text.
func (rep *tuneReport) print(w io.Writer) {
	fmt.Fprintf(w, "%d security events\n", rep.Events)
	policies := map[string]bool{}
	for p := range rep.WouldDeny {
		policies[p] = true
	}
	for _, g := range rep.Groups {
		policies[g.Policy] = true
	}
	for _, p := range tuneKeys(policies) {
		fmt.Fprintf(w, "\nWAFPolicy %s", cmp.Or(p, "(none)"))
		if n := rep.WouldDeny[p]; n > 0 {
			fmt.Fprintf(w, ": %d logged requests would be denied in Block mode", n)
		}
		fmt.Fprintln(w)
		for _, g := range rep.Groups {
			if g.Policy != p {
				continue
			}
			fmt.Fprintf(w, "  %d@%s on %s: %s, %s", g.RuleID, g.Variable, g.Path, plural(g.Count, "time"), plural(g.Clients(), "client IP"))
			if len(g.SampleIDs) > 0 {
				fmt.Fprintf(w, " (request IDs %s)", strings.Join(g.SampleIDs, ", "))
			}
			fmt.Fprintln(w)
			if g.Skip != "" {
				fmt.Fprintf(w, "    not suggested: %s\n", g.Skip)
			}
		}
		if exs := rep.Suggestions[p]; len(exs) > 0 {
			fmt.Fprintln(w, "  Suggested exclusions:")
			for _, ex := range exs {
				ids := make([]string, len(ex.RuleIDs))
				for i, id := range ex.RuleIDs {
					ids[i] = strconv.Itoa(int(id))
				}
				fmt.Fprintf(w, "    rules %s, on %s, for %s\n", strings.Join(ids, ","), ex.When.Path, describeWhen(ex.When))
			}
		}
	}
	fmt.Fprintln(w, "\nSuggestions are only as good as the events: check that each group is a false positive, not an attack, before you add it. -o yaml writes them.")
}

// yaml writes the patched policies, or without them the exclusions to add
// by policy.
func (rep *tuneReport) yaml() (string, error) {
	var b strings.Builder
	if rep.Patched != nil {
		for _, p := range rep.Patched {
			p.APIVersion, p.Kind = wafv1alpha1.GroupVersion.String(), "WAFPolicy"
			p.ManagedFields, p.ResourceVersion, p.UID, p.Generation, p.CreationTimestamp = nil, "", "", 0, metav1.Time{}
			raw, err := json.Marshal(p)
			if err != nil {
				return "", err
			}
			var obj map[string]any
			if err := json.Unmarshal(raw, &obj); err != nil {
				return "", err
			}
			// The status is the operator's.
			delete(obj, "status")
			out, err := yaml.Marshal(obj)
			if err != nil {
				return "", err
			}
			b.WriteString("---\n")
			b.Write(out)
		}
		return b.String(), nil
	}
	type entry struct {
		Policy     string                  `json:"policy"`
		Exclusions []wafv1alpha1.Exclusion `json:"exclusions"`
	}
	var list []entry
	for _, p := range tuneKeys(rep.Suggestions) {
		list = append(list, entry{p, rep.Suggestions[p]})
	}
	out, err := yaml.Marshal(list)
	if err != nil {
		return "", err
	}
	b.WriteString("# The exclusions to add to each WAFPolicy's spec.exclusions.\n")
	b.Write(out)
	return b.String(), nil
}

func tuneKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// plural is n and noun, plural unless n is 1.
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}
