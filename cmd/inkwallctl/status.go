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
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/enginereport"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
)

const statusUsage = "usage: inkwallctl status [--kubeconfig FILE] [--context NAME] [--namespace NS] [-o text|json]"

// statusConfig holds the flags of inkwallctl status.
type statusConfig struct {
	kubeconfig, context string
	// namespace is the operator's.
	namespace string
	output    string
	// stale: engine reports older than this are from replicas that are
	// gone, as the operator's 15 report intervals (2 s each by default).
	stale time.Duration
}

func parseStatusFlags(args []string, stderr io.Writer) (statusConfig, error) {
	var cfg statusConfig
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, statusUsage)
		fmt.Fprintln(stderr, "Reports whether Inkwall works in the cluster: the InkwallConfig, the proxies, the policies that aren't Ready, and the engines. Exits 1 when something needs attention. Read only.")
		fs.PrintDefaults()
	}
	fs.StringVar(&cfg.kubeconfig, "kubeconfig", "", "kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	fs.StringVar(&cfg.context, "context", "", "kubeconfig context (default: the current one)")
	fs.StringVar(&cfg.namespace, "namespace", "inkwall-system", "the operator's namespace")
	fs.StringVar(&cfg.output, "o", "text", "output: text or json (docs/troubleshooting.md describes the JSON)")
	fs.DurationVar(&cfg.stale, "engine-report-stale", 30*time.Second, "an operator replica's engine report older than this is ignored (its replica is gone)")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if fs.NArg() > 0 {
		return cfg, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if cfg.output != "text" && cfg.output != "json" {
		return cfg, fmt.Errorf("-o: %q, want text or json", cfg.output)
	}
	return cfg, nil
}

// newStatusClient returns a read-only client for the kubeconfig context;
// tests replace it.
var newStatusClient = func(kubeconfig, context string) (client.Reader, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfig
	rc, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules,
		&clientcmd.ConfigOverrides{CurrentContext: context}).ClientConfig()
	if err != nil {
		return nil, err
	}
	return client.New(rc, client.Options{Scheme: statusScheme()})
}

// statusClock is the time engine reports are judged fresh at; tests set it.
var statusClock = time.Now

func statusScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	return s
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	cfg, err := parseStatusFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	c, err := newStatusClient(cfg.kubeconfig, cfg.context)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := clusterStatus(ctx, c, cfg.namespace, cfg.stale, statusClock())
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if cfg.output == "json" {
		b, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		fmt.Fprintln(stdout, string(b))
	} else {
		printStatus(stdout, st)
	}
	if !st.Healthy {
		return 1
	}
	return 0
}

// Status is inkwallctl status's report, and the shape of -o json: fields
// are only ever added (docs/troubleshooting.md).
type Status struct {
	// Healthy is false when something needs attention; Problems says what.
	Healthy  bool     `json:"healthy"`
	Problems []string `json:"problems"`
	// Warnings are things status couldn't read or check.
	Warnings []string       `json:"warnings"`
	Config   ConfigStatus   `json:"config"`
	Operator OperatorStatus `json:"operator"`
	Bundle   *BundleStatus  `json:"bundle"`
	Proxies  []ProxyStatus  `json:"proxies"`
	Policies PoliciesStatus `json:"policies"`
	Engines  EnginesStatus  `json:"engines"`
}

// ConfigStatus is the InkwallConfig named default.
type ConfigStatus struct {
	// Exists is false when there is none: every setting is its default.
	Exists     bool              `json:"exists"`
	Mode       string            `json:"mode"`
	Suspended  bool              `json:"suspended"`
	Conditions []ConditionStatus `json:"conditions"`
}

// ConditionStatus is one condition of an object.
type ConditionStatus struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// OperatorStatus is the operator's replicas.
type OperatorStatus struct {
	Namespace string `json:"namespace"`
	// Versions are the image tags its pods run, sorted.
	Versions []string `json:"versions"`
	Pods     int      `json:"pods"`
	Ready    int      `json:"ready"`
}

// BundleStatus is the policy bundle the operator publishes.
type BundleStatus struct {
	Version uint64 `json:"version"`
	// CompressedBytes is its size as stored, gzip-compressed (limit:
	// 7,372,800 bytes).
	CompressedBytes int `json:"compressedBytes"`
	// Chunks is how many Secrets beyond the bundle Secret hold it.
	Chunks int `json:"chunks"`
}

// ProxyStatus is one proxy controller the cluster's classes name.
type ProxyStatus struct {
	Controller     string   `json:"controller"`
	Integration    string   `json:"integration"`
	Support        string   `json:"support"`
	Message        string   `json:"message"`
	IngressClasses []string `json:"ingressClasses"`
	GatewayClasses []string `json:"gatewayClasses"`
	// Inspects is what the engine sees through this proxy.
	Inspects Inspects `json:"inspects"`
}

// Inspects is what an integration lets the engine inspect.
type Inspects struct {
	Requests          bool `json:"requests"`
	Responses         bool `json:"responses"`
	WebSocketMessages bool `json:"webSocketMessages"`
	GRPCMessages      bool `json:"grpcMessages"`
}

// inspects is what each integration's adapter sees: ext_proc gets the
// responses (Envoy Gateway's routes only), every adapter gets request
// bodies, and only the standalone proxy sees WebSocket messages.
var inspects = map[string]Inspects{
	"traefik":       {Requests: true, GRPCMessages: true},
	"envoy-gateway": {Requests: true, Responses: true, GRPCMessages: true},
	"istio":         {Requests: true, GRPCMessages: true},
	"istio-ingress": {Requests: true, GRPCMessages: true},
	"haproxy":       {Requests: true, GRPCMessages: true},
}

// PoliciesStatus counts the WAFPolicies, and lists those not Ready.
type PoliciesStatus struct {
	Total int `json:"total"`
	Ready int `json:"ready"`
	// NotReady groups the others by their Ready condition's reason.
	NotReady []PolicyGroup `json:"notReady"`
}

// PolicyGroup is the policies not Ready for one reason.
type PolicyGroup struct {
	Reason   string      `json:"reason"`
	Policies []PolicyRef `json:"policies"`
}

// PolicyRef is one policy and its Ready condition's message.
type PolicyRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Message   string `json:"message"`
}

// EnginesStatus is the engines connected to the operator.
type EnginesStatus struct {
	Total int `json:"total"`
	// LeftOut engines didn't fit a replica's report: the counts miss them.
	LeftOut int `json:"leftOut"`
	// ByVersion counts them by engine version and bundle state.
	ByVersion []EngineVersionGroup `json:"byVersion"`
	// Attention names the engines behind, rejecting the bundle, or of
	// another version than the operator.
	Attention []EngineRef `json:"attention"`
}

// EngineVersionGroup counts the engines of one version.
type EngineVersionGroup struct {
	Version  string `json:"version"`
	Current  int    `json:"current"`
	Behind   int    `json:"behind"`
	Rejected int    `json:"rejected"`
}

// Engine bundle states.
const (
	engineCurrent  = "current"
	engineBehind   = "behind"
	engineRejected = "rejected"
)

// EngineRef is one engine that needs attention.
type EngineRef struct {
	Namespace   string `json:"namespace"`
	Pod         string `json:"pod"`
	Version     string `json:"version"`
	State       string `json:"state"`
	Applied     uint64 `json:"applied"`
	Rejected    uint64 `json:"rejected,omitempty"`
	RejectError string `json:"rejectError,omitempty"`
	// Outdated: its version isn't the operator's.
	Outdated bool   `json:"outdated"`
	Hint     string `json:"hint"`
}

// clusterStatus reads the cluster: the InkwallConfig, the operator's pods,
// the bundle Secret, the policies and the engine reports. What it may not
// read (RBAC) is a warning, not an error.
func clusterStatus(ctx context.Context, c client.Reader, namespace string, stale time.Duration, now time.Time) (*Status, error) {
	st := &Status{Problems: []string{}, Warnings: []string{}, Proxies: []ProxyStatus{}}
	st.Operator.Namespace = namespace
	st.Operator.Versions = []string{}
	st.Policies.NotReady = []PolicyGroup{}
	st.Engines.ByVersion = []EngineVersionGroup{}
	st.Engines.Attention = []EngineRef{}
	problem := func(format string, a ...any) { st.Problems = append(st.Problems, fmt.Sprintf(format, a...)) }
	warn := func(what string, err error) {
		st.Warnings = append(st.Warnings, fmt.Sprintf("can't read %s: %v", what, err))
	}

	// The InkwallConfig.
	st.Config.Mode = string(wafv1alpha1.ModeStandalone)
	st.Config.Conditions = []ConditionStatus{}
	var cfg wafv1alpha1.InkwallConfig
	switch err := c.Get(ctx, types.NamespacedName{Name: "default"}, &cfg); {
	case err == nil:
		st.Config.Exists = true
		st.Config.Mode = string(cmp.Or(cfg.Spec.Mode, wafv1alpha1.ModeStandalone))
		st.Config.Suspended = cfg.Spec.Suspend
		for _, cond := range cfg.Status.Conditions {
			st.Config.Conditions = append(st.Config.Conditions, ConditionStatus{cond.Type, string(cond.Status), cond.Reason, cond.Message})
		}
		for _, p := range cfg.Status.Proxies {
			st.Proxies = append(st.Proxies, ProxyStatus{
				Controller: p.ControllerName, Integration: p.Integration, Support: string(p.Support), Message: p.Message,
				IngressClasses: nonNil(p.IngressClasses), GatewayClasses: nonNil(p.GatewayClasses),
				Inspects: inspects[p.Integration],
			})
		}
	case apierrors.IsNotFound(err):
	case meta.IsNoMatchError(err):
		return nil, errors.New("the cluster has no InkwallConfig kind: is Inkwall installed?")
	default:
		return nil, fmt.Errorf("read the InkwallConfig: %w", err)
	}
	if st.Config.Suspended {
		problem("inspection is suspended (InkwallConfig spec.suspend): every engine allows every request")
	}
	if cond := meta.FindStatusCondition(cfg.Status.Conditions, wafv1alpha1.ConditionControlPlaneConnected); cond != nil &&
		cond.Status == "False" && st.Config.Mode != string(wafv1alpha1.ModeStandalone) {
		problem("the control plane is not connected (%s): %s", cond.Reason, cond.Message)
	}

	// The operator's pods.
	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.InNamespace(namespace), client.MatchingLabels{"app.kubernetes.io/component": "operator", "app.kubernetes.io/part-of": "inkwall"}); err != nil {
		warn("the operator's pods", err)
	} else {
		versions := map[string]bool{}
		for _, p := range pods.Items {
			st.Operator.Pods++
			if podReady(&p) {
				st.Operator.Ready++
			}
			for _, ctr := range p.Spec.Containers {
				if ctr.Name == "operator" {
					versions[imageTag(ctr.Image)] = true
				}
			}
		}
		for v := range versions {
			st.Operator.Versions = append(st.Operator.Versions, v)
		}
		slices.Sort(st.Operator.Versions)
		if st.Operator.Ready == 0 {
			problem("no operator replica is ready in %s: policy changes don't reach the engines, and new proxy pods may not start (docs/troubleshooting.md)", namespace)
		}
	}

	// The bundle.
	var secret corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: bundle.BundleSecret}, &secret); err != nil {
		if !apierrors.IsNotFound(err) {
			warn("the bundle Secret", err)
		} else {
			problem("no policy bundle is published yet (Secret %s/%s)", namespace, bundle.BundleSecret)
		}
	} else {
		b := &BundleStatus{}
		b.Version, _ = strconv.ParseUint(secret.Annotations[bundle.VersionAnnotation], 10, 64)
		if data, ok := secret.Data[bundle.BundleKey]; ok {
			b.CompressedBytes = len(data)
		} else if m, err := bundlesecret.ParseManifest(bundle.BundleSecret, secret.Data[bundle.ManifestKey]); err == nil {
			b.CompressedBytes, b.Chunks = m.Size, len(m.Chunks)
		}
		st.Bundle = b
	}

	// The policies.
	var policies wafv1alpha1.WAFPolicyList
	if err := c.List(ctx, &policies); err != nil {
		return nil, fmt.Errorf("list WAFPolicies: %w", err)
	}
	groups := map[string][]PolicyRef{}
	for _, p := range policies.Items {
		st.Policies.Total++
		ready := meta.FindStatusCondition(p.Status.Conditions, wafv1alpha1.ConditionReady)
		if ready != nil && ready.Status == "True" && ready.ObservedGeneration == p.Generation {
			st.Policies.Ready++
			continue
		}
		reason, msg := "Unknown", "the operator hasn't reported on this generation yet"
		if ready != nil && ready.ObservedGeneration == p.Generation {
			reason, msg = ready.Reason, ready.Message
		}
		groups[reason] = append(groups[reason], PolicyRef{Namespace: p.Namespace, Name: p.Name, Message: msg})
	}
	for _, reason := range sortedKeys(groups) {
		refs := groups[reason]
		slices.SortFunc(refs, func(a, b PolicyRef) int {
			return cmp.Or(strings.Compare(a.Namespace, b.Namespace), strings.Compare(a.Name, b.Name))
		})
		st.Policies.NotReady = append(st.Policies.NotReady, PolicyGroup{Reason: reason, Policies: refs})
	}
	if n := st.Policies.Total - st.Policies.Ready; n > 0 {
		problem("%d of %d WAFPolicies are not Ready", n, st.Policies.Total)
	}

	// The engines.
	engines, leftOut, err := enginereport.Read(ctx, c, namespace, stale, now)
	if err != nil {
		warn("the engine reports", err)
		return finish(st), nil
	}
	st.Engines.Total, st.Engines.LeftOut = len(engines), leftOut
	if leftOut > 0 {
		problem("%d engines are left out of the operator's reports (too many for a ConfigMap): their state is unknown", leftOut)
	}
	current := uint64(0)
	if st.Bundle != nil {
		current = st.Bundle.Version
	}
	if current == 0 {
		for _, e := range engines {
			current = max(current, e.Applied)
		}
	}
	operatorVersion := ""
	if len(st.Operator.Versions) == 1 {
		operatorVersion = st.Operator.Versions[0]
	}
	byVersion := map[string]*EngineVersionGroup{}
	for _, e := range engines {
		state := engineCurrent
		switch {
		case e.Applied >= current:
		case e.Rejected >= current:
			state = engineRejected
		default:
			state = engineBehind
		}
		version := cmp.Or(e.EngineVersion, "unknown")
		g := byVersion[version]
		if g == nil {
			g = &EngineVersionGroup{Version: version}
			byVersion[version] = g
		}
		switch state {
		case engineCurrent:
			g.Current++
		case engineBehind:
			g.Behind++
		case engineRejected:
			g.Rejected++
		}
		outdated := operatorVersion != "" && sameRelease(e.EngineVersion) && !sameVersion(e.EngineVersion, operatorVersion)
		if state == engineCurrent && !outdated {
			continue
		}
		ref := EngineRef{Namespace: e.PodNamespace, Pod: e.PodName, Version: version, State: state,
			Applied: e.Applied, Rejected: e.Rejected, RejectError: e.RejectError, Outdated: outdated}
		if ref.Pod == "" {
			ref.Pod = e.ID
		}
		switch {
		case state == engineRejected:
			ref.Hint = "the engine rejected the bundle: see its reason and log (docs/troubleshooting.md)"
		case outdated:
			ref.Hint = fmt.Sprintf("its version isn't the operator's (%s): restart the pod (kubectl -n %s delete pod %s) or roll its workload", operatorVersion, ref.Namespace, ref.Pod)
		default:
			ref.Hint = "the engine doesn't run the current bundle yet: check its connection to the operator"
		}
		st.Engines.Attention = append(st.Engines.Attention, ref)
	}
	for _, v := range sortedKeys(byVersion) {
		st.Engines.ByVersion = append(st.Engines.ByVersion, *byVersion[v])
	}
	if n := len(st.Engines.Attention); n > 0 {
		problem("%d engines need attention (behind, rejecting the bundle, or of another version)", n)
	}
	if len(engines) == 0 && st.Policies.Total > 0 && !st.Config.Suspended {
		problem("no engine is connected to the operator, but %d WAFPolicies exist", st.Policies.Total)
	}
	return finish(st), nil
}

func finish(st *Status) *Status {
	st.Healthy = len(st.Problems) == 0
	return st
}

func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// imageTag returns an image reference's tag, or the reference without a
// tag.
func imageTag(image string) string {
	image, _, _ = strings.Cut(image, "@")
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		return image[i+1:]
	}
	return image
}

// sameRelease reports whether an engine version is a release's (v1.2.3 or
// 1.2.3), which can be compared with the operator's.
func sameRelease(v string) bool {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

func sameVersion(a, b string) bool { return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v") }

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// printStatus writes the report as text.
func printStatus(w io.Writer, st *Status) {
	yesNo := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	if st.Config.Exists {
		fmt.Fprintf(w, "InkwallConfig: mode %s, suspended %s\n", st.Config.Mode, yesNo(st.Config.Suspended))
	} else {
		fmt.Fprintf(w, "InkwallConfig: none (defaults: mode %s, not suspended)\n", st.Config.Mode)
	}
	fmt.Fprintf(w, "Operator: %d/%d replicas ready in %s, version %s\n", st.Operator.Ready, st.Operator.Pods, st.Operator.Namespace,
		cmp.Or(strings.Join(st.Operator.Versions, ", "), "unknown"))
	if st.Bundle != nil {
		fmt.Fprintf(w, "Bundle: version %d, %d bytes compressed", st.Bundle.Version, st.Bundle.CompressedBytes)
		if st.Bundle.Chunks > 0 {
			fmt.Fprintf(w, " in %d chunks", st.Bundle.Chunks)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "\nProxies:")
	if len(st.Proxies) == 0 {
		fmt.Fprintln(w, "  none found")
	} else {
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  CONTROLLER\tINTEGRATION\tSUPPORT\tREQUESTS\tRESPONSES\tWS MESSAGES\tGRPC MESSAGES")
		for _, p := range st.Proxies {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.Controller, cmp.Or(p.Integration, "-"), p.Support,
				yesNo(p.Inspects.Requests), yesNo(p.Inspects.Responses), yesNo(p.Inspects.WebSocketMessages), yesNo(p.Inspects.GRPCMessages))
		}
		_ = tw.Flush()
		for _, p := range st.Proxies {
			if p.Message != "" {
				fmt.Fprintf(w, "  %s: %s\n", p.Controller, p.Message)
			}
		}
	}

	fmt.Fprintf(w, "\nPolicies: %d of %d Ready\n", st.Policies.Ready, st.Policies.Total)
	for _, g := range st.Policies.NotReady {
		fmt.Fprintf(w, "  %s:\n", g.Reason)
		for _, p := range g.Policies {
			fmt.Fprintf(w, "    %s/%s: %s\n", p.Namespace, p.Name, p.Message)
		}
	}

	fmt.Fprintf(w, "\nEngines: %d connected\n", st.Engines.Total)
	if len(st.Engines.ByVersion) > 0 {
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  VERSION\tCURRENT\tBEHIND\tREJECTED")
		for _, g := range st.Engines.ByVersion {
			fmt.Fprintf(tw, "  %s\t%d\t%d\t%d\n", g.Version, g.Current, g.Behind, g.Rejected)
		}
		_ = tw.Flush()
	}
	for _, e := range st.Engines.Attention {
		fmt.Fprintf(w, "  %s/%s (%s, %s, bundle %d): %s\n", e.Namespace, e.Pod, e.Version, e.State, e.Applied, e.Hint)
		if e.RejectError != "" {
			fmt.Fprintf(w, "    rejected bundle %d: %s\n", e.Rejected, e.RejectError)
		}
	}

	for _, warning := range st.Warnings {
		fmt.Fprintf(w, "\nwarning: %s\n", warning)
	}
	if st.Healthy {
		fmt.Fprintln(w, "\nOK: nothing needs attention.")
		return
	}
	fmt.Fprintln(w, "\nNeeds attention:")
	for _, p := range st.Problems {
		fmt.Fprintf(w, "  - %s\n", p)
	}
}
