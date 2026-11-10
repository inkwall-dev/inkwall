// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/enginereport"
	"github.com/inkwall-dev/inkwall/operator/reasons"
	"github.com/inkwall-dev/inkwall/operator/resolver"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

const explainUsage = `usage: inkwallctl explain request [flags] REQUEST-ID
       inkwallctl explain policy [flags] NAMESPACE/NAME`

// explainConfig holds the flags of inkwallctl explain.
type explainConfig struct {
	kubeconfig, context string
	// namespace is the operator's.
	namespace string
	output    string
	// request: where the events are. files: log or events files, instead
	// of the engines' logs; pods: the engine pods to read (namespace/name),
	// instead of every engine the operator reports.
	files []string
	pods  listFlag
	since time.Duration
	// request: the WAF objects to check the suggestion with, instead of the
	// cluster's.
	objects config
	// The request ID or the policy (namespace/name).
	arg string
}

func parseExplainFlags(what string, args []string, stderr io.Writer) (explainConfig, error) {
	var cfg explainConfig
	fs := flag.NewFlagSet("explain "+what, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.kubeconfig, "kubeconfig", "", "kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	fs.StringVar(&cfg.context, "context", "", "kubeconfig context (default: the current one)")
	fs.StringVar(&cfg.namespace, "namespace", "inkwall-system", "the operator's namespace")
	fs.StringVar(&cfg.output, "o", "text", "output: text or json (docs/troubleshooting.md describes the JSON)")
	var files listFlag
	if what == "request" {
		fs.Usage = func() {
			fmt.Fprintln(stderr, "usage: inkwallctl explain request [flags] REQUEST-ID")
			fmt.Fprintln(stderr, "Finds the security event of a request by its ID (X-Request-Id) in the engines' logs, read through the API server, or in --file, and says why it was denied: the policy, the reason, the score against the threshold, each rule with what it detects and where it matched, and the narrowest exclusion that would allow it, checked as inkwallctl test --policy does. Never shows what a rule matched. Read only. Exits 1 when no event has the ID.")
			fs.PrintDefaults()
		}
		fs.Var(&files, "file", "read the events from this file instead of the cluster: engine logs (kubectl logs), or events as JSON lines; - is standard input (repeatable)")
		fs.Var(&cfg.pods, "pod", "read this engine pod's log, namespace/name, instead of every engine pod the operator reports (repeatable)")
		fs.DurationVar(&cfg.since, "since", 24*time.Hour, "read the engines' logs this far back")
		fs.Var(&cfg.objects.policies, "policy", "WAFPolicy YAML file to check the suggested exclusion with, instead of the cluster's policy (repeatable)")
		fs.Var(&cfg.objects.ruleSets, "rule-set", "with --policy: WAFRuleSet or ClusterWAFRuleSet YAML file the policies use (repeatable)")
		fs.Var(&cfg.objects.configMaps, "configmap", "with --policy: ConfigMap YAML file rule sets read rules from (repeatable)")
		fs.Var(&cfg.objects.ingresses, "ingress", "with --policy: Ingress, IngressRoute, HTTPRoute or VirtualService YAML file the policies target (repeatable)")
	} else {
		fs.Usage = func() {
			fmt.Fprintln(stderr, "usage: inkwallctl explain policy [flags] NAMESPACE/NAME")
			fmt.Fprintln(stderr, "Walks a WAFPolicy's conditions (Accepted, Programmed, Enforced, Ready) and, for each that isn't True, prints the cause and the fix from docs/troubleshooting.md, with the targets and the engines involved. Read only. Exits 1 when the policy isn't Ready.")
			fs.PrintDefaults()
		}
	}
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	cfg.files = files
	if fs.NArg() != 1 {
		if what == "request" {
			return cfg, errors.New("give one request ID")
		}
		return cfg, errors.New("give one policy, as namespace/name")
	}
	cfg.arg = fs.Arg(0)
	switch {
	case cfg.output != "text" && cfg.output != "json":
		return cfg, fmt.Errorf("-o: %q, want text or json", cfg.output)
	case len(cfg.files) > 0 && len(cfg.pods) > 0:
		return cfg, errors.New("--file and --pod: give one")
	case cfg.since <= 0 && what == "request":
		return cfg, fmt.Errorf("--since: %s, want more than 0", cfg.since)
	case len(cfg.objects.policies) == 0 && cfg.objects.policyFiles():
		return cfg, errors.New("--rule-set, --configmap and --ingress need --policy")
	}
	if what == "request" && (cfg.arg == "" || len(cfg.arg) > maxRequestID) {
		return cfg, fmt.Errorf("a request ID has 1 to %d bytes", maxRequestID)
	}
	if what == "policy" {
		ns, name, ok := strings.Cut(cfg.arg, "/")
		if !ok || ns == "" || name == "" || strings.Contains(name, "/") {
			return cfg, fmt.Errorf("%q: give the policy as namespace/name", cfg.arg)
		}
	}
	for _, p := range cfg.pods {
		if ns, name, ok := strings.Cut(p, "/"); !ok || ns == "" || name == "" {
			return cfg, fmt.Errorf("--pod %q: want namespace/name", p)
		}
	}
	return cfg, nil
}

// engineContainer is the engine's container in a proxy pod
// (operator/internal/injection.ContainerName).
const engineContainer = "inkwall-engine"

// maxRequestID is the longest request ID an event holds
// (pkg/events.maxRequestID).
const maxRequestID = 128

// explainCluster is what explain reads from the cluster: objects, and the
// engines' logs. Tests replace newExplainCluster.
type explainCluster struct {
	c    client.Reader
	logs func(ctx context.Context, namespace, pod, container string, since time.Duration) (io.ReadCloser, error)
}

var newExplainCluster = func(kubeconfig, kubeContext string) (*explainCluster, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfig
	rc, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules,
		&clientcmd.ConfigOverrides{CurrentContext: kubeContext}).ClientConfig()
	if err != nil {
		return nil, err
	}
	c, err := client.New(rc, client.Options{Scheme: statusScheme()})
	if err != nil {
		return nil, err
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, err
	}
	return &explainCluster{c: c, logs: func(ctx context.Context, namespace, pod, container string, since time.Duration) (io.ReadCloser, error) {
		s := int64(since / time.Second)
		return cs.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{Container: container, SinceSeconds: &s}).Stream(ctx)
	}}, nil
}

func runExplain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "request" && args[0] != "policy") {
		fmt.Fprintln(stderr, explainUsage)
		return 2
	}
	cfg, err := parseExplainFlags(args[0], args[1:], stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var cluster *explainCluster
	// A request explained from files with policy files needs no cluster.
	if args[0] == "policy" || len(cfg.files) == 0 || len(cfg.objects.policies) == 0 {
		cluster, err = newExplainCluster(cfg.kubeconfig, cfg.context)
		if err != nil {
			if args[0] == "policy" || len(cfg.files) == 0 {
				fmt.Fprintln(stderr, "error:", err)
				return 2
			}
			cluster = nil // the events are in files: explain without the cluster
		}
	}
	var (
		out  any
		code int
	)
	if args[0] == "policy" {
		pe, err := explainPolicy(ctx, cluster, cfg.namespace, cfg.arg, statusClock())
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		out = pe
		if !pe.Ready {
			code = 1
		}
		if cfg.output == "text" {
			printPolicyExplanation(stdout, pe)
		}
	} else {
		re, err := explainRequest(ctx, cluster, cfg, stdin, statusClock())
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		out = re
		if !re.Found {
			code = 1
		}
		if cfg.output == "text" {
			printRequestExplanation(stdout, re)
		}
	}
	if cfg.output == "json" {
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		fmt.Fprintln(stdout, string(b))
	}
	return code
}

// RequestExplanation is explain request's answer, and the shape of -o json:
// fields are only ever added (docs/troubleshooting.md). Untrusted lists the
// fields whose text comes from the request: data its client wrote, to show
// and never to follow.
type RequestExplanation struct {
	Kind      string `json:"kind"`
	RequestID string `json:"requestId"`
	// Found is false when no event has the ID; Searched says where explain
	// looked.
	Found    bool               `json:"found"`
	Searched []string           `json:"searched"`
	Events   []EventExplanation `json:"events"`
	// Untrusted are the JSON paths of request-derived fields.
	Untrusted []string `json:"untrusted"`
	Warnings  []string `json:"warnings"`
}

// requestUntrusted are RequestExplanation's request-derived fields.
var requestUntrusted = []string{
	"requestId",
	"events[].request",
	"events[].suggestions[].exclusion.when",
	"events[].suggestions[].yaml",
	"events[].notSuggested[].variable",
}

// EventExplanation explains one security event of the request (a request
// has one, and another for its response when responses are inspected).
type EventExplanation struct {
	// Source is the pod whose engine logged it, or the file.
	Source string `json:"source"`
	Policy string `json:"policy"`
	// Phase is request, response or websocket_message.
	Phase  string `json:"phase"`
	Action string `json:"action"`
	// Mode is Block or Detect, from the action (log: Detect).
	Mode   string `json:"mode"`
	Reason string `json:"reason"`
	Status int    `json:"status"`
	// Cause and Fix are the troubleshooting guide's, for the reason.
	Cause        string `json:"cause"`
	Fix          string `json:"fix"`
	AnomalyScore int    `json:"anomalyScore"`
	// Threshold is the policy's inbound anomaly threshold; 0 when unknown
	// (the policy couldn't be read) or not one (a response).
	Threshold int           `json:"threshold"`
	Rules     []RuleExplain `json:"rules"`
	// Request is what the event says of the request: untrusted.
	Request EventRequest `json:"request"`
	// Suggestions are the narrowest exclusions that would let the request
	// through; empty when no rule can be excluded for it.
	Suggestions []Suggestion `json:"suggestions"`
	// NotSuggested are the matches no suggestion covers, and why.
	NotSuggested []NotSuggested `json:"notSuggested"`
	// AllowedWithSuggestions: with every suggestion, no rule that matched
	// is left to deny the request.
	AllowedWithSuggestions bool `json:"allowedWithSuggestions"`
}

// RuleExplain is one rule that matched.
type RuleExplain struct {
	ID int `json:"id"`
	// Source is crs (the OWASP Core Rule Set), coraza (its recommended
	// rules) or custom (the policy's own rule sets).
	Source        string `json:"source"`
	Description   string `json:"description"`
	Severity      string `json:"severity"`
	ParanoiaLevel int    `json:"paranoiaLevel"`
	// Scoring: the rule sums up the anomaly score; excluding it would
	// turn the policy off, so it is never suggested.
	Scoring      bool `json:"scoring"`
	Interrupting bool `json:"interrupting"`
	// Variables are where it matched (ARGS:q): untrusted, the names come
	// from the request. Never the value.
	Variables []string `json:"variables"`
}

// EventRequest is the request, as the event has it: untrusted.
type EventRequest struct {
	ID       string       `json:"id"`
	Method   string       `json:"method"`
	Host     string       `json:"host"`
	Path     string       `json:"path"`
	ClientIP string       `json:"clientIp"`
	Matches  []MatchPoint `json:"matches"`
}

// MatchPoint is where a rule matched: the variable's name, never its
// value.
type MatchPoint struct {
	RuleID   int    `json:"ruleId"`
	Variable string `json:"variable"`
}

// Suggestion is an exclusion to add to the policy's spec.exclusions.
type Suggestion struct {
	Policy    string                `json:"policy"`
	Exclusion wafv1alpha1.Exclusion `json:"exclusion"`
	// YAML is the exclusion as an item of spec.exclusions.
	YAML string `json:"yaml"`
	// Verified: the policy with every suggestion resolves as the operator
	// does and compiles as the engine does (inkwallctl test --policy's
	// code). VerifiedWith is the policy's source; VerifyError why it isn't.
	Verified     bool   `json:"verified"`
	VerifiedWith string `json:"verifiedWith"`
	VerifyError  string `json:"verifyError"`
}

// NotSuggested is a match no exclusion is suggested for.
type NotSuggested struct {
	RuleID   int    `json:"ruleId"`
	Variable string `json:"variable"`
	Why      string `json:"why"`
}

// explainRequest finds the request's events and explains them.
func explainRequest(ctx context.Context, cluster *explainCluster, cfg explainConfig, stdin io.Reader, now time.Time) (*RequestExplanation, error) {
	re := &RequestExplanation{Kind: "RequestExplanation", RequestID: cfg.arg, Searched: []string{}, Events: []EventExplanation{},
		Untrusted: requestUntrusted, Warnings: []string{}}
	type sourced struct {
		ev     tuneEvent
		source string
	}
	var found []sourced
	// keep skips, unparsed, the lines that can't be the request's.
	keep := func(line string) bool { return strings.Contains(line, cfg.arg) }
	collect := func(source string, evs []tuneEvent) {
		for _, ev := range evs {
			if ev.RequestID == cfg.arg {
				found = append(found, sourced{ev, source})
			}
		}
	}
	if len(cfg.files) > 0 {
		for _, f := range cfg.files {
			r := stdin
			if f != "-" {
				fh, err := os.Open(f) // #nosec G304 -- a file the user names
				if err != nil {
					return nil, err
				}
				defer fh.Close()
				r = fh
			}
			evs, err := readEvents(r, anyLines, keep)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			re.Searched = append(re.Searched, "file "+f)
			collect(f, evs)
		}
	} else {
		pods, err := enginePods(ctx, cluster, cfg, now)
		if err != nil {
			return nil, err
		}
		for _, p := range pods {
			evs, err := podEvents(ctx, cluster, p, cfg.since, keep)
			if err != nil {
				re.Warnings = append(re.Warnings, fmt.Sprintf("can't read the log of pod %s: %v", p, err))
				continue
			}
			re.Searched = append(re.Searched, "pod "+p)
			collect(p, evs)
			if len(found) > 0 {
				// A request is inspected by one engine: its events are
				// in one log.
				break
			}
		}
	}
	re.Found = len(found) > 0
	for _, f := range found {
		re.Events = append(re.Events, explainEvent(ctx, cluster, cfg, f.ev, f.source, re))
	}
	return re, nil
}

// enginePods returns the pods whose logs to read: --pod, or every engine
// pod the operator reports.
func enginePods(ctx context.Context, cluster *explainCluster, cfg explainConfig, now time.Time) ([]string, error) {
	if len(cfg.pods) > 0 {
		return cfg.pods, nil
	}
	engines, _, err := enginereport.Read(ctx, cluster.c, cfg.namespace, 30*time.Second, now)
	if err != nil {
		return nil, fmt.Errorf("list the engines the operator reports (or name their pods with --pod): %w", err)
	}
	var pods []string
	for _, e := range engines {
		if e.PodNamespace != "" && e.PodName != "" {
			pods = append(pods, e.PodNamespace+"/"+e.PodName)
		}
	}
	slices.Sort(pods)
	pods = slices.Compact(pods)
	if len(pods) == 0 {
		return nil, errors.New("the operator reports no engine pod: name them with --pod, or read a log file with --file")
	}
	return pods, nil
}

// podEvents reads the security events in an engine pod's log: its
// inkwall-engine container, or its only container (a standalone engine).
func podEvents(ctx context.Context, cluster *explainCluster, pod string, since time.Duration, keep func(string) bool) ([]tuneEvent, error) {
	ns, name, _ := strings.Cut(pod, "/")
	var p corev1.Pod
	if err := cluster.c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &p); err != nil {
		return nil, err
	}
	container := ""
	for _, c := range p.Spec.Containers {
		if c.Name == engineContainer {
			container = c.Name
		}
	}
	if container == "" {
		if len(p.Spec.Containers) != 1 {
			return nil, fmt.Errorf("no %s container", engineContainer)
		}
		container = p.Spec.Containers[0].Name
	}
	rc, err := cluster.logs(ctx, ns, name, container, since)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return readEvents(rc, logLines, keep)
}

// explainEvent explains one event: its reason, its rules, and the
// narrowest exclusions (tune's), checked as inkwallctl test --policy does.
func explainEvent(ctx context.Context, cluster *explainCluster, cfg explainConfig, ev tuneEvent, source string, re *RequestExplanation) EventExplanation {
	reason := strings.ReplaceAll(ev.Reason, "_", "-")
	ee := EventExplanation{
		Source: source, Policy: ev.Policy, Phase: cmp.Or(ev.Phase, "request"), Action: ev.Action, Reason: reason,
		Status: ev.Status, AnomalyScore: ev.AnomalyScore, Rules: []RuleExplain{}, Suggestions: []Suggestion{}, NotSuggested: []NotSuggested{},
		Request: EventRequest{ID: ev.RequestID, Method: ev.Method, Host: ev.Host, Path: ev.Path, ClientIP: ev.ClientIP, Matches: []MatchPoint{}},
	}
	switch ev.Action {
	case "log":
		ee.Mode = string(wafv1alpha1.PolicyDetect)
	case "deny":
		ee.Mode = string(wafv1alpha1.PolicyBlock)
	}
	if e, ok := reasons.Lookup(reasons.KindSecurityEvent, "reason", reason); ok {
		ee.Cause, ee.Fix = reasons.Text(e.Meaning), reasons.Text(e.Fix)
	}

	// The rules, in the order they matched; the interrupting one too.
	byID := map[int]*RuleExplain{}
	var order []int
	addRule := func(id int) *RuleExplain {
		if r := byID[id]; r != nil {
			return r
		}
		r := &RuleExplain{ID: id, Source: "custom", Variables: []string{}}
		if info, ok, err := coraza.EmbeddedRule(id); err == nil && ok {
			r.Source, r.Description, r.Severity, r.ParanoiaLevel = "crs", info.Message, info.Severity, info.ParanoiaLevel
			if id < 900000 {
				r.Source = "coraza"
			}
		}
		byID[id] = r
		order = append(order, id)
		return r
	}
	for _, m := range ev.Matches {
		if m.RuleID == 0 {
			continue
		}
		ee.Request.Matches = append(ee.Request.Matches, MatchPoint(m))
		r := addRule(m.RuleID)
		r.Scoring = r.Scoring || scoreRule(m.RuleID, m.Variable)
		if !slices.Contains(r.Variables, m.Variable) {
			r.Variables = append(r.Variables, m.Variable)
		}
	}
	if ev.Interrupting != 0 {
		r := addRule(ev.Interrupting)
		r.Interrupting = true
		r.Scoring = r.Scoring || scoreRule(ev.Interrupting, "")
	}
	for _, id := range order {
		ee.Rules = append(ee.Rules, *byID[id])
	}

	// The narrowest exclusions, by tune's logic, for a request the rules
	// denied (or would have, in Detect mode).
	if reason != "rule" || ev.Policy == "" {
		if ev.Policy == "" {
			re.Warnings = append(re.Warnings, "the event names no policy: nothing to exclude")
		}
		return ee
	}
	rep := tune([]tuneEvent{ev}, false, 1)
	for _, g := range rep.Groups {
		if g.Skip != "" {
			// explain suggests no broader exclusion than a variable's:
			// tune's --broad isn't one of its flags.
			why, _, _ := strings.Cut(g.Skip, ": --broad")
			ee.NotSuggested = append(ee.NotSuggested, NotSuggested{RuleID: g.RuleID, Variable: g.Variable, Why: why})
		}
	}
	for _, ex := range rep.Suggestions[ev.Policy] {
		s := Suggestion{Policy: ev.Policy, Exclusion: ex}
		if b, err := yaml.Marshal([]wafv1alpha1.Exclusion{ex}); err == nil {
			s.YAML = string(b)
		}
		ee.Suggestions = append(ee.Suggestions, s)
	}
	ee.AllowedWithSuggestions = len(ee.Suggestions) > 0 && len(ee.NotSuggested) == 0

	// The policy: to check the suggestions with, and for its threshold.
	in, with, err := explainInput(ctx, cluster, cfg, ev.Policy)
	if err != nil {
		re.Warnings = append(re.Warnings, fmt.Sprintf("WAFPolicy %s: %v: the suggestions aren't verified, and the threshold is unknown", ev.Policy, err))
		for i := range ee.Suggestions {
			ee.Suggestions[i].VerifyError = err.Error()
		}
		return ee
	}
	var notes strings.Builder
	b, err := rep.validateInput(in, false, &notes)
	for i := range ee.Suggestions {
		ee.Suggestions[i].VerifiedWith = with
		if err != nil {
			ee.Suggestions[i].VerifyError = err.Error()
		} else {
			ee.Suggestions[i].Verified = true
		}
	}
	if b == nil {
		// The threshold of the policy as it is.
		b, _ = inputBundle(in, false, io.Discard)
	}
	if ee.Phase == "request" {
		ee.Threshold = inboundThreshold(b, ev.Policy)
	}
	return ee
}

// explainInput returns the policy and what it references, from the
// --policy files or from the cluster, and says which.
func explainInput(ctx context.Context, cluster *explainCluster, cfg explainConfig, policyID string) (resolver.Input, string, error) {
	ns, name, _ := strings.Cut(policyID, "/")
	if len(cfg.objects.policies) > 0 {
		files := slices.Concat(cfg.objects.policies, cfg.objects.ruleSets, cfg.objects.configMaps, cfg.objects.ingresses)
		// The files' objects without a namespace are the policy's.
		in, _, err := loadObjects(files, ns, io.Discard)
		if err != nil {
			return in, "", err
		}
		i := slices.IndexFunc(in.Policies, func(p wafv1alpha1.WAFPolicy) bool { return p.Namespace == ns && p.Name == name })
		if i < 0 {
			return in, "", errors.New("not in the --policy files")
		}
		return in, "the --policy files", nil
	}
	if cluster == nil {
		return resolver.Input{}, "", errors.New("no cluster to read it from: give it with --policy")
	}
	in, err := clusterInput(ctx, cluster.c, ns, name)
	return in, "the cluster", err
}

// clusterInput reads the policy and the rule sets, ConfigMaps and IP lists
// it references: only those, by name (get, never list).
func clusterInput(ctx context.Context, c client.Reader, ns, name string) (resolver.Input, error) {
	var in resolver.Input
	var p wafv1alpha1.WAFPolicy
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &p); err != nil {
		return in, err
	}
	in.Policies = []wafv1alpha1.WAFPolicy{p}
	configMap := func(ns, name string) error {
		var cm corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &cm); err != nil {
			if apierrors.IsNotFound(err) {
				return nil // the resolver says what is missing
			}
			return err
		}
		in.ConfigMaps = append(in.ConfigMaps, cm)
		return nil
	}
	for _, b := range p.Spec.RuleSets {
		switch b.Ref.Kind {
		case "WAFRuleSet":
			var rs wafv1alpha1.WAFRuleSet
			rsNS := cmp.Or(b.Ref.Namespace, ns)
			if err := c.Get(ctx, types.NamespacedName{Namespace: rsNS, Name: b.Ref.Name}, &rs); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return in, err
			}
			in.RuleSets = append(in.RuleSets, rs)
			if ref := rs.Spec.Source.ConfigMapRef; ref != nil {
				if err := configMap(rsNS, ref.Name); err != nil {
					return in, err
				}
			}
		case "ClusterWAFRuleSet":
			var rs wafv1alpha1.ClusterWAFRuleSet
			if err := c.Get(ctx, types.NamespacedName{Name: b.Ref.Name}, &rs); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return in, err
			}
			in.ClusterRuleSets = append(in.ClusterRuleSets, rs)
			if ref := rs.Spec.Source.ConfigMapRef; ref != nil {
				if err := configMap(ref.Namespace, ref.Name); err != nil {
					return in, err
				}
			}
		}
	}
	if l := p.Spec.IPLists; l != nil {
		for _, n := range slices.Concat(l.Allow, l.Deny) {
			var list wafv1alpha1.WAFIPList
			if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: string(n)}, &list); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return in, err
			}
			in.IPLists = append(in.IPLists, list)
		}
	}
	return in, nil
}

// inboundThreshold is the policy's CRS inbound anomaly threshold in b, as
// the engine compiles it (pkg/policy); 0 when b doesn't have the policy or
// it runs no CRS.
func inboundThreshold(b *bundlev1.Bundle, policyID string) int {
	if b == nil {
		return 0
	}
	builtin := map[string]bool{}
	for _, rs := range b.GetRuleSets() {
		if rs.GetBuiltin() != bundlev1.BuiltinRuleSet_BUILTIN_RULE_SET_UNSPECIFIED {
			builtin[rs.GetId()] = true
		}
	}
	for _, p := range b.GetPolicies() {
		if p.GetId() != policyID {
			continue
		}
		if len(p.GetRuleSets()) == 0 {
			return coraza.DefaultInboundAnomalyThreshold // the CRS with its defaults
		}
		for _, rs := range p.GetRuleSets() {
			if builtin[rs.GetRuleSetId()] {
				return int(cmp.Or(rs.GetInboundAnomalyThreshold(), coraza.DefaultInboundAnomalyThreshold))
			}
		}
	}
	return 0
}

// PolicyExplanation is explain policy's answer, and the shape of -o json:
// fields are only ever added (docs/troubleshooting.md).
type PolicyExplanation struct {
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	Generation int64  `json:"generation"`
	Mode       string `json:"mode"`
	// Ready is true when the Ready condition is True for this generation.
	Ready      bool               `json:"ready"`
	Targets    []TargetExplain    `json:"targets"`
	Conditions []ConditionExplain `json:"conditions"`
	Engines    []EngineRef        `json:"engines"`
	Warnings   []string           `json:"warnings"`
}

// TargetExplain is one of the policy's targets.
type TargetExplain struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	SectionName string `json:"sectionName,omitempty"`
}

// ConditionExplain is one condition, and for one that isn't True, its
// cause and fix from the troubleshooting guide.
type ConditionExplain struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
	// Current is false when the condition is about an older generation
	// (the operator hasn't reported on this one yet).
	Current bool   `json:"current"`
	Cause   string `json:"cause"`
	Fix     string `json:"fix"`
}

// policyConditions are walked in this order: Ready takes the reason of the
// first of the others that isn't True.
var policyConditions = []string{wafv1alpha1.ConditionAccepted, wafv1alpha1.ConditionProgrammed, wafv1alpha1.ConditionEnforced, wafv1alpha1.ConditionReady}

// explainPolicy reads a policy and explains its conditions.
func explainPolicy(ctx context.Context, cluster *explainCluster, namespace, id string, now time.Time) (*PolicyExplanation, error) {
	ns, name, _ := strings.Cut(id, "/")
	var p wafv1alpha1.WAFPolicy
	switch err := cluster.c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &p); {
	case apierrors.IsNotFound(err):
		return nil, fmt.Errorf("no WAFPolicy %s", id)
	case meta.IsNoMatchError(err):
		return nil, errors.New("the cluster has no WAFPolicy kind: is Inkwall installed?")
	case err != nil:
		return nil, fmt.Errorf("read WAFPolicy %s: %w", id, err)
	}
	pe := &PolicyExplanation{Kind: "PolicyExplanation", Namespace: ns, Name: name, Generation: p.Generation,
		Mode: string(cmp.Or(p.Spec.Mode, wafv1alpha1.PolicyBlock)), Targets: []TargetExplain{},
		Conditions: []ConditionExplain{}, Engines: []EngineRef{}, Warnings: []string{}}
	for _, t := range p.Spec.TargetRefs {
		pe.Targets = append(pe.Targets, TargetExplain{Kind: t.Kind, Name: t.Name, SectionName: t.SectionName})
	}
	for _, t := range policyConditions {
		ce := ConditionExplain{Type: t, Status: string(metav1.ConditionUnknown)}
		c := meta.FindStatusCondition(p.Status.Conditions, t)
		if c == nil {
			ce.Reason, ce.Message = "Not"+t, "not reported yet"
			if t == wafv1alpha1.ConditionReady {
				ce.Reason = "NotAccepted"
			}
		} else {
			ce.Status, ce.Reason, ce.Message = string(c.Status), c.Reason, c.Message
			ce.Current = c.ObservedGeneration == p.Generation
		}
		if !ce.Current && c != nil {
			ce.Cause = fmt.Sprintf("The operator hasn't reported %s on generation %d yet (it reported on %d). It lasts seconds.", t, p.Generation, c.ObservedGeneration)
			ce.Fix = "If it lasts, check that the operator runs: `inkwallctl status`."
		} else if ce.Status != string(metav1.ConditionTrue) {
			if e, ok := policyEntry(t, ce.Reason, ce.Message); ok {
				ce.Cause, ce.Fix = reasons.Text(e.Meaning), reasons.Text(e.Fix)
			} else {
				ce.Cause = "This version of inkwallctl doesn't know the reason " + ce.Reason + ": the message says what to fix, and docs/troubleshooting.md of the operator's version."
			}
		}
		if t == wafv1alpha1.ConditionReady {
			pe.Ready = ce.Status == string(metav1.ConditionTrue) && ce.Current
		}
		pe.Conditions = append(pe.Conditions, ce)
	}

	// The engines that don't run the policy's bundle, while it isn't
	// Enforced.
	if enforced := meta.FindStatusCondition(p.Status.Conditions, wafv1alpha1.ConditionEnforced); enforced == nil || enforced.Status != metav1.ConditionTrue {
		engines, _, err := enginereport.Read(ctx, cluster.c, namespace, 30*time.Second, now)
		if err != nil {
			pe.Warnings = append(pe.Warnings, fmt.Sprintf("can't read the engine reports: %v", err))
		}
		want := uint64(max(p.Status.BundleVersion, 0))
		for _, e := range engines {
			ref := EngineRef{Namespace: e.PodNamespace, Pod: cmp.Or(e.PodName, e.ID), Version: cmp.Or(e.EngineVersion, "unknown"),
				Applied: e.Applied, Rejected: e.Rejected, RejectError: e.RejectError}
			switch {
			case want == 0 || e.Applied >= want:
				continue
			case e.Rejected >= want:
				ref.State, ref.Hint = engineRejected, "the engine rejected the bundle: restart its pod so it runs the operator's version (docs/troubleshooting.md)"
			default:
				ref.State, ref.Hint = engineBehind, "the engine doesn't run the policy's bundle yet: check its connection to the operator"
			}
			pe.Engines = append(pe.Engines, ref)
		}
	}
	return pe, nil
}

// policyEntry finds the guide's entry for a policy condition's reason.
// Ready's reason is another condition's: its message names which.
func policyEntry(condition, reason, message string) (reasons.Entry, bool) {
	if e, ok := reasons.Lookup(reasons.KindWAFPolicy, condition, reason); ok {
		return e, true
	}
	if condition != wafv1alpha1.ConditionReady {
		return reasons.Entry{}, false
	}
	if from, _, ok := strings.Cut(message, ": "); ok {
		if e, ok := reasons.Lookup(reasons.KindWAFPolicy, from, reason); ok {
			return e, true
		}
	}
	for _, t := range policyConditions {
		if e, ok := reasons.Lookup(reasons.KindWAFPolicy, t, reason); ok {
			return e, true
		}
	}
	return reasons.Entry{}, false
}

// printPolicyExplanation writes the explanation as text.
func printPolicyExplanation(w io.Writer, pe *PolicyExplanation) {
	state := "Ready"
	if !pe.Ready {
		state = "not Ready"
	}
	fmt.Fprintf(w, "WAFPolicy %s/%s (generation %d, mode %s): %s\n", pe.Namespace, pe.Name, pe.Generation, pe.Mode, state)
	targets := make([]string, 0, len(pe.Targets))
	for _, t := range pe.Targets {
		s := t.Kind + " " + t.Name
		if t.SectionName != "" {
			s += " (" + t.SectionName + ")"
		}
		targets = append(targets, s)
	}
	fmt.Fprintf(w, "Targets: %s\n", cmp.Or(strings.Join(targets, ", "), "none"))
	for _, c := range pe.Conditions {
		fmt.Fprintf(w, "\n%s: %s, %s", c.Type, c.Status, c.Reason)
		if c.Message != "" {
			fmt.Fprintf(w, ": %s", terminalSafe(c.Message))
		}
		fmt.Fprintln(w)
		if c.Cause != "" {
			fmt.Fprintf(w, "  Cause: %s\n", c.Cause)
		}
		if c.Fix != "" {
			fmt.Fprintf(w, "  Fix:   %s\n", c.Fix)
		}
	}
	if len(pe.Engines) > 0 {
		fmt.Fprintln(w, "\nEngines that don't run the policy's bundle:")
		for _, e := range pe.Engines {
			fmt.Fprintf(w, "  %s/%s (%s, %s, bundle %d): %s\n", e.Namespace, e.Pod, e.Version, e.State, e.Applied, e.Hint)
			if e.RejectError != "" {
				fmt.Fprintf(w, "    rejected bundle %d: %s\n", e.Rejected, terminalSafe(e.RejectError))
			}
		}
	}
	for _, warning := range pe.Warnings {
		fmt.Fprintf(w, "\nwarning: %s\n", warning)
	}
}

// printRequestExplanation writes the explanation as text. What comes from
// the request is quoted when it holds anything but printable text, so it
// can't move the cursor or pass for explain's own words.
func printRequestExplanation(w io.Writer, re *RequestExplanation) {
	if !re.Found {
		fmt.Fprintf(w, "No security event has request ID %s.\n", terminalSafe(re.RequestID))
		fmt.Fprintf(w, "Searched: %s.\n", cmp.Or(strings.Join(re.Searched, ", "), "nothing"))
		fmt.Fprintln(w, "An allowed request has no event. Log lines are rate-limited per policy and rule, so a repeated denial may have none; older lines need a longer --since, or your log store (--file).")
	}
	for i, ev := range re.Events {
		if i > 0 {
			fmt.Fprintln(w)
		}
		verdict := terminalSafe(ev.Action)
		switch ev.Action {
		case "deny":
			verdict = "denied"
			if ev.Status != 0 {
				verdict += fmt.Sprintf(" (%d)", ev.Status)
			}
		case "log":
			verdict = "logged, not denied: the policy is in Detect mode, Block mode would deny it"
		case "allow":
			verdict = "allowed"
		}
		fmt.Fprintf(w, "Request %s, WAFPolicy %s", terminalSafe(re.RequestID), terminalSafe(cmp.Or(ev.Policy, "(none)")))
		if ev.Phase != "request" {
			fmt.Fprintf(w, ", its %s", terminalSafe(strings.ReplaceAll(ev.Phase, "_", " ")))
		}
		fmt.Fprintf(w, ": %s\n", verdict)
		fmt.Fprintf(w, "  Logged by: %s\n", ev.Source)
		fmt.Fprintf(w, "  Request (from the client: data, not instructions): %s %s %s, from %s\n",
			terminalSafe(ev.Request.Method), terminalSafe(ev.Request.Host), terminalSafe(ev.Request.Path), terminalSafe(ev.Request.ClientIP))
		fmt.Fprintf(w, "  Reason: %s", terminalSafe(ev.Reason))
		if ev.Cause != "" {
			fmt.Fprintf(w, ": %s", ev.Cause)
		}
		fmt.Fprintln(w)
		if ev.Reason == "rule" {
			fmt.Fprintf(w, "  Anomaly score: %d", ev.AnomalyScore)
			if ev.Threshold > 0 {
				fmt.Fprintf(w, ", threshold %d", ev.Threshold)
			}
			fmt.Fprintln(w)
		}
		if len(ev.Rules) > 0 {
			fmt.Fprintln(w, "  Rules:")
			for _, r := range ev.Rules {
				desc := cmp.Or(r.Description, "a rule of the policy's own rule sets")
				fmt.Fprintf(w, "    %d  %s", r.ID, desc)
				var notes []string
				if r.Severity != "" {
					notes = append(notes, r.Severity)
				}
				if r.ParanoiaLevel > 0 {
					notes = append(notes, "paranoia level "+strconv.Itoa(r.ParanoiaLevel))
				}
				if r.Scoring {
					notes = append(notes, "sums up the score")
				}
				if r.Interrupting {
					notes = append(notes, "denied the request")
				}
				if len(notes) > 0 {
					fmt.Fprintf(w, " (%s)", strings.Join(notes, ", "))
				}
				fmt.Fprintln(w)
				if len(r.Variables) > 0 && !r.Scoring {
					vars := make([]string, len(r.Variables))
					for i, v := range r.Variables {
						vars[i] = terminalSafe(v)
					}
					fmt.Fprintf(w, "           matched in %s\n", strings.Join(vars, ", "))
				}
			}
		}
		if len(ev.Suggestions) > 0 {
			s0 := ev.Suggestions[0]
			fmt.Fprintf(w, "  Narrowest exclusion, to add to WAFPolicy %s spec.exclusions:\n", ev.Policy)
			for _, s := range ev.Suggestions {
				for _, line := range strings.Split(strings.TrimRight(s.YAML, "\n"), "\n") {
					fmt.Fprintf(w, "    %s\n", terminalSafe(line))
				}
			}
			switch {
			case s0.Verified:
				fmt.Fprintf(w, "  Verified with %s, as inkwallctl test --policy does: the policy resolves and compiles with it.\n", s0.VerifiedWith)
			default:
				fmt.Fprintf(w, "  Not verified: %s\n", terminalSafe(s0.VerifyError))
			}
			if ev.AllowedWithSuggestions {
				fmt.Fprintln(w, "  It covers every rule that matched: with it, this request would be allowed.")
			}
			fmt.Fprintln(w, "  Add it only if the request is a false positive, not an attack.")
		}
		for _, n := range ev.NotSuggested {
			fmt.Fprintf(w, "  No exclusion for %d@%s: %s\n", n.RuleID, terminalSafe(n.Variable), terminalSafe(n.Why))
		}
		if ev.Fix != "" && ev.Reason != "rule" {
			fmt.Fprintf(w, "  Fix: %s\n", ev.Fix)
		}
	}
	for _, warning := range re.Warnings {
		fmt.Fprintf(w, "\nwarning: %s\n", terminalSafe(warning))
	}
}

// terminalSafe returns s as is when it is printable text, and quoted (Go
// syntax) otherwise: request-derived text must not hold terminal escapes or
// line breaks.
func terminalSafe(s string) string {
	if !utf8.ValidString(s) {
		return strconv.Quote(s)
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return strconv.Quote(s)
		}
	}
	return s
}
