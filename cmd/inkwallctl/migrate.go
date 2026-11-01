// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	networkingv1client "k8s.io/client-go/kubernetes/typed/networking/v1"
	"k8s.io/client-go/tools/clientcmd"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/resolver"
)

// migrateConfig is the configuration of migrate ingress-nginx.
type migrateConfig struct {
	files      listFlag
	cluster    bool
	kubeconfig string
	context    string
	namespace  string
	configMap  string // namespace/name
	class      string
	prefix     string
	outDir     string
	target     string
}

// migrateInput is what migrate reads: the Ingresses, the ConfigMap's
// settings and, with --target, the routes replacing the Ingresses.
type migrateInput struct {
	ingresses     []networkingv1.Ingress
	global        nginxGlobal
	httpRoutes    []gatewayv1.HTTPRoute
	ingressRoutes []unstructured.Unstructured
}

const migrateUsage = "usage: inkwallctl migrate ingress-nginx [flags] -f FILE ... | --cluster"

// runMigrate runs inkwallctl migrate. It exits 0 when everything was
// migrated, 1 when something needs a human, 2 on an error.
func runMigrate(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "ingress-nginx" {
		fmt.Fprintln(stderr, migrateUsage)
		return 2
	}
	cfg, err := parseMigrateFlags(args[1:], stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	var in migrateInput
	if cfg.cluster {
		in, err = readCluster(cfg, stderr)
	} else {
		in, err = readMigrateFiles(cfg, stderr)
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	ingresses := in.ingresses
	var repl *replacements
	switch cfg.target {
	case targetHTTPRoute:
		repl = newReplacements("HTTPRoute", in.httpRoutes, nil)
	case targetIngressRoute:
		repl = newReplacements("IngressRoute", nil, in.ingressRoutes)
	}

	var results []*migration
	// shared lists the policies by the requests their Ingresses match.
	shared := map[string][]*migration{}
	skipped := 0
	for i := range ingresses {
		ing := &ingresses[i]
		class := ingressClass(ing)
		if class != "" && class != cfg.class {
			skipped++
			continue
		}
		m := migrateIngress(ing, in.global, cfg.prefix)
		if m == nil {
			continue
		}
		if class == "" && m.policy != nil {
			m.add(itemCheck, "", "the Ingress has no class: assumed served by ingress-nginx")
		}
		if m.policy != nil {
			matches, _ := routeMatches(resolver.Input{Ingresses: []networkingv1.Ingress{*ing}}, ing.Namespace,
				wafv1alpha1.TargetRef{Kind: "Ingress", Name: ing.Name})
			for k := range matches {
				shared[k] = append(shared[k], m)
			}
		}
		if repl != nil {
			repl.retarget(m, ing)
		}
		results = append(results, m)
	}
	warnShared(shared)
	sortMigrations(results)

	if err := writeMigration(cfg, results, stdout); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	todos := report(stderr, results, len(ingresses), skipped, cfg.class)
	if todos > 0 {
		return 1
	}
	return 0
}

// warnShared adds a check item to the policies whose Ingresses match the
// same host and path: only one policy applies to a request.
func warnShared(shared map[string][]*migration) {
	for _, k := range slices.Sorted(maps.Keys(shared)) {
		ms := shared[k]
		if len(ms) < 2 {
			continue
		}
		for _, m := range ms {
			var others []string
			for _, o := range ms {
				if o != m {
					others = append(others, o.namespace+"/"+o.name)
				}
			}
			m.add(itemCheck, "", "host and path %s are also matched by the Ingress(es) %s: only one policy applies to a request (the oldest); merge the settings into the policy that should apply", k, strings.Join(others, ", "))
		}
	}
}

func parseMigrateFlags(args []string, stderr io.Writer) (migrateConfig, error) {
	var cfg migrateConfig
	fs := flag.NewFlagSet("migrate ingress-nginx", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, migrateUsage)
		fmt.Fprintln(stderr, "Converts ingress-nginx's ModSecurity annotations and ConfigMap settings into WAFPolicy objects.")
		fmt.Fprintln(stderr, "Prints them as YAML (or writes them to --output); never changes the cluster.")
		fmt.Fprintln(stderr, "Exits 0 when everything was migrated, 1 when something needs a human (see the summary), 2 on an error.")
		fs.PrintDefaults()
	}
	fs.Var(&cfg.files, "f", "file (or directory of .yaml, .yml and .json files) with Ingresses and the ingress-nginx ConfigMap, as YAML documents or a kubectl List; - reads stdin (repeatable)")
	fs.BoolVar(&cfg.cluster, "cluster", false, "read the Ingresses and the ConfigMap from the cluster of the current kubeconfig context (read only)")
	fs.StringVar(&cfg.kubeconfig, "kubeconfig", "", "with --cluster: kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	fs.StringVar(&cfg.context, "context", "", "with --cluster: kubeconfig context (default: the current one)")
	fs.StringVar(&cfg.namespace, "namespace", "", "with --cluster: only the Ingresses of this namespace (default: all); with -f: namespace of the objects that don't name one (default: default)")
	fs.StringVar(&cfg.configMap, "controller-configmap", "ingress-nginx/ingress-nginx-controller", "NAMESPACE/NAME of the ingress-nginx ConfigMap, whose enable-modsecurity, enable-owasp-modsecurity-crs and modsecurity-snippet apply to every Ingress")
	fs.StringVar(&cfg.class, "ingress-class", "nginx", "ingress class of ingress-nginx: Ingresses of other classes are left out")
	fs.StringVar(&cfg.prefix, "annotation-prefix", "nginx.ingress.kubernetes.io", "ingress-nginx's annotation prefix (its --annotations-prefix)")
	fs.StringVar(&cfg.outDir, "output", "", "directory to write one file per Ingress into, instead of printing to stdout")
	fs.StringVar(&cfg.target, "target", targetIngress, "what the policies target: ingress (the Ingresses), httproute or ingressroute (the Gateway API HTTPRoutes or Traefik IngressRoutes replacing them, read from the -f files or the cluster, matched by hosts and paths)")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	switch {
	case fs.NArg() > 0:
		return cfg, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	case cfg.cluster == (len(cfg.files) > 0):
		return cfg, errors.New("give -f FILE or --cluster")
	case !cfg.cluster && (cfg.kubeconfig != "" || cfg.context != ""):
		return cfg, errors.New("--kubeconfig and --context apply only to --cluster")
	case strings.Count(cfg.configMap, "/") != 1 || strings.HasPrefix(cfg.configMap, "/") || strings.HasSuffix(cfg.configMap, "/"):
		return cfg, fmt.Errorf("--controller-configmap %q: want NAMESPACE/NAME", cfg.configMap)
	case cfg.prefix == "":
		return cfg, errors.New("--annotation-prefix must not be empty")
	case cfg.target != targetIngress && cfg.target != targetHTTPRoute && cfg.target != targetIngressRoute:
		return cfg, fmt.Errorf("--target %q: want ingress, httproute or ingressroute", cfg.target)
	}
	return cfg, nil
}

// globalSettings reads the ModSecurity keys of the ingress-nginx ConfigMap.
// Invalid booleans are false, as in ingress-nginx.
func globalSettings(cm *corev1.ConfigMap, notes io.Writer) nginxGlobal {
	g := nginxGlobal{source: "ConfigMap " + cm.Namespace + "/" + cm.Name, snippet: cm.Data[cmSnippet]}
	for key, dst := range map[string]*bool{cmEnable: &g.enable, cmCRS: &g.crs} {
		v, ok := cm.Data[key]
		if !ok {
			continue
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			fmt.Fprintf(notes, "note: %s %s: %q is not a boolean: ingress-nginx reads it as false\n", g.source, key, v)
		}
		*dst = b
	}
	for _, key := range cmNginxSnippets {
		if nginxModSecurity.MatchString(cm.Data[key]) {
			g.nginxSnippets = append(g.nginxSnippets, g.source+" "+key)
		}
	}
	return g
}

// readMigrateFiles reads the Ingresses and the ConfigMap in the -f files;
// other kinds are skipped.
func readMigrateFiles(cfg migrateConfig, notes io.Writer) (migrateInput, error) {
	var (
		in    migrateInput
		found bool
	)
	namespace := cmp.Or(cfg.namespace, "default")
	var add func(file string, doc []byte) error
	add = func(file string, doc []byte) error {
		var head struct {
			APIVersion string            `json:"apiVersion"`
			Kind       string            `json:"kind"`
			Metadata   metav1.ObjectMeta `json:"metadata"`
			Items      []json.RawMessage `json:"items"`
		}
		if err := yaml.Unmarshal(doc, &head); err != nil {
			return err
		}
		ns := cmp.Or(head.Metadata.Namespace, namespace)
		switch {
		case strings.HasSuffix(head.Kind, "List"):
			for _, item := range head.Items {
				if err := add(file, item); err != nil {
					return err
				}
			}
		case head.Kind == "Ingress" && head.APIVersion == networkingv1.SchemeGroupVersion.String():
			var ing networkingv1.Ingress
			if err := yaml.Unmarshal(doc, &ing); err != nil {
				return fmt.Errorf("the Ingress %s: %w", head.Metadata.Name, err)
			}
			ing.Namespace = ns
			in.ingresses = append(in.ingresses, ing)
		case cfg.target == targetHTTPRoute && head.Kind == "HTTPRoute" && head.APIVersion == gatewayv1.GroupVersion.String():
			var hr gatewayv1.HTTPRoute
			if err := yaml.Unmarshal(doc, &hr); err != nil {
				return fmt.Errorf("the HTTPRoute %s: %w", head.Metadata.Name, err)
			}
			hr.Namespace = ns
			in.httpRoutes = append(in.httpRoutes, hr)
		case cfg.target == targetIngressRoute && head.Kind == "IngressRoute" && head.APIVersion == integrations.TraefikIngressRouteGVK.GroupVersion().String():
			var ir unstructured.Unstructured
			j, err := yaml.YAMLToJSON(doc)
			if err == nil {
				err = ir.UnmarshalJSON(j)
			}
			if err != nil {
				return fmt.Errorf("the IngressRoute %s: %w", head.Metadata.Name, err)
			}
			ir.SetNamespace(ns)
			in.ingressRoutes = append(in.ingressRoutes, ir)
		case head.Kind == "ConfigMap" && ns+"/"+head.Metadata.Name == cfg.configMap:
			var cm corev1.ConfigMap
			if err := yaml.Unmarshal(doc, &cm); err != nil {
				return fmt.Errorf("the ConfigMap %s: %w", head.Metadata.Name, err)
			}
			cm.Namespace = ns
			in.global, found = globalSettings(&cm, notes), true
		case head.Kind == "":
			return errors.New("an object without a kind")
		default:
			fmt.Fprintf(notes, "note: %s: %s %s skipped\n", file, head.Kind, strings.TrimPrefix(ns+"/"+head.Metadata.Name, "/"))
		}
		return nil
	}
	read := func(file string, r io.Reader) error {
		docs := utilyaml.NewYAMLReader(bufio.NewReader(r))
		for {
			doc, err := docs.Read()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err == nil && !isEmptyDocument(doc) {
				err = add(file, doc)
			}
			if err != nil {
				return fmt.Errorf("%s: %w", file, err)
			}
		}
	}

	var paths []string
	for _, f := range cfg.files {
		if f == "-" {
			if err := read("stdin", os.Stdin); err != nil {
				return in, err
			}
			continue
		}
		paths = append(paths, f)
	}
	files, err := expandDirs(paths)
	if err != nil {
		return in, err
	}
	for _, file := range files {
		// The path comes from the user's own command line.
		f, err := os.Open(filepath.Clean(file))
		if err != nil {
			return in, err
		}
		err = read(file, f)
		_ = f.Close()
		if err != nil {
			return in, err
		}
	}
	if !found {
		fmt.Fprintf(notes, "note: no ConfigMap %s in the files: ModSecurity is taken as off globally (only the annotations count)\n", cfg.configMap)
	}
	return in, nil
}

// kubeClient reads the API groups migrate needs; the typed clients of
// these groups only keep inkwallctl small. Routes, whose CRDs may be
// missing, are read with the dynamic client.
type kubeClient struct {
	core       corev1client.CoreV1Interface
	networking networkingv1client.NetworkingV1Interface
	dynamic    dynamic.Interface
}

// newKubeClient returns a client for the kubeconfig context; tests replace
// it.
var newKubeClient = func(kubeconfig, context string) (kubeClient, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfig
	rc, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules,
		&clientcmd.ConfigOverrides{CurrentContext: context}).ClientConfig()
	if err != nil {
		return kubeClient{}, err
	}
	core, err := corev1client.NewForConfig(rc)
	if err != nil {
		return kubeClient{}, err
	}
	networking, err := networkingv1client.NewForConfig(rc)
	if err != nil {
		return kubeClient{}, err
	}
	dyn, err := dynamic.NewForConfig(rc)
	if err != nil {
		return kubeClient{}, err
	}
	return kubeClient{core: core, networking: networking, dynamic: dyn}, nil
}

// readCluster lists the Ingresses (and, with --target, the routes) and
// gets the ConfigMap. It only reads.
func readCluster(cfg migrateConfig, notes io.Writer) (migrateInput, error) {
	var in migrateInput
	c, err := newKubeClient(cfg.kubeconfig, cfg.context)
	if err != nil {
		return in, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmNamespace, cmName, _ := strings.Cut(cfg.configMap, "/")
	cm, err := c.core.ConfigMaps(cmNamespace).Get(ctx, cmName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		fmt.Fprintf(notes, "note: no ConfigMap %s in the cluster: ModSecurity is taken as off globally (only the annotations count); set --controller-configmap if ingress-nginx uses another\n", cfg.configMap)
	case err != nil:
		return in, fmt.Errorf("get ConfigMap %s: %w", cfg.configMap, err)
	default:
		in.global = globalSettings(cm, notes)
	}

	opts := metav1.ListOptions{Limit: 500}
	for {
		list, err := c.networking.Ingresses(cfg.namespace).List(ctx, opts)
		if err != nil {
			return in, fmt.Errorf("list Ingresses: %w", err)
		}
		in.ingresses = append(in.ingresses, list.Items...)
		if opts.Continue = list.Continue; opts.Continue == "" {
			break
		}
	}

	var gvr schema.GroupVersionResource
	switch cfg.target {
	case targetHTTPRoute:
		gvr = schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "httproutes"}
	case targetIngressRoute:
		gvr = integrations.TraefikIngressRouteGVK.GroupVersion().WithResource("ingressroutes")
	default:
		return in, nil
	}
	opts = metav1.ListOptions{Limit: 500}
	for {
		list, err := c.dynamic.Resource(gvr).Namespace(cfg.namespace).List(ctx, opts)
		switch {
		case apierrors.IsNotFound(err):
			fmt.Fprintf(notes, "note: the cluster has no %s: their CRD isn't installed\n", gvr.GroupResource())
			return in, nil
		case err != nil:
			return in, fmt.Errorf("list %s: %w", gvr.GroupResource(), err)
		}
		for _, o := range list.Items {
			if cfg.target == targetIngressRoute {
				in.ingressRoutes = append(in.ingressRoutes, o)
				continue
			}
			var hr gatewayv1.HTTPRoute
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(o.Object, &hr); err != nil {
				return in, fmt.Errorf("the HTTPRoute %s/%s: %w", o.GetNamespace(), o.GetName(), err)
			}
			in.httpRoutes = append(in.httpRoutes, hr)
		}
		if opts.Continue = list.GetContinue(); opts.Continue == "" {
			return in, nil
		}
	}
}

// writeMigration prints the objects, or writes them to cfg.outDir: one file
// per Ingress, and one for the CRS rule set they share.
func writeMigration(cfg migrateConfig, results []*migration, stdout io.Writer) error {
	type file struct {
		name string
		docs [][]byte
	}
	var files []file
	usesCRS := false
	for _, m := range results {
		usesCRS = usesCRS || m.usesCRSRuleSet
	}
	if usesCRS {
		rs := &wafv1alpha1.ClusterWAFRuleSet{
			TypeMeta:   metav1.TypeMeta{APIVersion: wafv1alpha1.GroupVersion.String(), Kind: "ClusterWAFRuleSet"},
			ObjectMeta: metav1.ObjectMeta{Name: crsRuleSetName},
			Spec:       wafv1alpha1.ClusterWAFRuleSetSpec{Source: wafv1alpha1.ClusterRuleSetSource{Builtin: wafv1alpha1.BuiltinCRSv4}},
		}
		doc, err := objectYAML("# The built-in OWASP CRS v4, for the policies that tune it or add rules.\n", rs)
		if err != nil {
			return err
		}
		files = append(files, file{name: "clusterwafruleset-" + crsRuleSetName + ".yaml", docs: [][]byte{doc}})
	}
	for _, m := range results {
		if m.policy == nil {
			continue
		}
		f := file{name: m.namespace + "-" + m.name + ".yaml"}
		head := fmt.Sprintf("# From the ingress-nginx ModSecurity settings of Ingress %s/%s.\n", m.namespace, m.name)
		if n := m.todos(); n > 0 {
			head += fmt.Sprintf("# %d setting(s) were not migrated: see the summary of inkwallctl migrate.\n", n)
		}
		if m.ruleSet != nil {
			doc, err := objectYAML(head, m.ruleSet)
			if err != nil {
				return err
			}
			f.docs = append(f.docs, doc)
			head = ""
		}
		doc, err := objectYAML(head, m.policy)
		if err != nil {
			return err
		}
		f.docs = append(f.docs, doc)
		files = append(files, f)
	}

	if cfg.outDir == "" {
		var all [][]byte
		for _, f := range files {
			all = append(all, f.docs...)
		}
		_, err := stdout.Write(bytes.Join(all, []byte("---\n")))
		return err
	}
	if err := os.MkdirAll(cfg.outDir, 0o750); err != nil {
		return err
	}
	for _, f := range files {
		path := filepath.Join(cfg.outDir, f.name)
		if err := os.WriteFile(path, bytes.Join(f.docs, []byte("---\n")), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// objectYAML marshals an object without its status and the empty fields
// the API server sets.
func objectYAML(comment string, obj any) ([]byte, error) {
	j, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(j, &m); err != nil {
		return nil, err
	}
	delete(m, "status")
	if md, ok := m["metadata"].(map[string]any); ok {
		delete(md, "creationTimestamp")
	}
	y, err := yaml.Marshal(m)
	if err != nil {
		return nil, err
	}
	return append([]byte(comment), y...), nil
}

// report prints the summary and returns the number of items that need a
// human.
func report(w io.Writer, results []*migration, read, skipped int, class string) int {
	policies, ruleSets, todos := 0, 0, 0
	for _, m := range results {
		target := "no WAFPolicy"
		if m.policy != nil {
			policies++
			target = fmt.Sprintf("WAFPolicy %s/%s (%s)", m.namespace, m.name, m.policy.Spec.Mode)
			if m.ruleSet != nil {
				ruleSets++
				target += ", WAFRuleSet " + m.namespace + "/" + m.ruleSet.Name
			}
		}
		fmt.Fprintf(w, "Ingress %s/%s: %s\n", m.namespace, m.name, target)
		for _, it := range m.items {
			label := [...]string{"mapped", "check ", "TODO  "}[it.kind]
			if it.source != "" {
				fmt.Fprintf(w, "  %s  %s: %s\n", label, it.source, it.text)
			} else {
				fmt.Fprintf(w, "  %s  %s\n", label, it.text)
			}
		}
		todos += m.todos()
	}
	fmt.Fprintf(w, "%d Ingress(es) read", read)
	if skipped > 0 {
		fmt.Fprintf(w, " (%d of another class than %s left out)", skipped, class)
	}
	fmt.Fprintf(w, ": %d WAFPolicy, %d WAFRuleSet; %d setting(s) not migrated need a human (TODO)\n", policies, ruleSets, todos)
	return todos
}
