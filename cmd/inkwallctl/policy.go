// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/resolver"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// secretBundleKey is the bundle Secret's key that holds the gzip-compressed
// SignedBundle (operator/bundle.BundleKey).
const secretBundleKey = bundlesecret.BundleKey

// maxBundleBytes bounds a decompressed bundle, as the engine does.
const maxBundleBytes = bundlesecret.MaxBundleBytes

// policyBundle resolves the objects in the --policy, --rule-set, --configmap
// and --ingress files the way the operator does, into the bundle it would
// publish. Notes about the objects go to notes.
func policyBundle(cfg config, notes io.Writer) (*bundlev1.Bundle, error) {
	files := slices.Concat(cfg.policies, cfg.ruleSets, cfg.configMaps, cfg.ingresses)
	in, suspended, err := loadObjects(files, cfg.namespace, notes)
	if err != nil {
		return nil, err
	}
	if len(in.Policies) == 0 {
		return nil, errors.New("no WAFPolicy in the files")
	}
	if len(in.Ingresses)+len(in.IngressRoutes) == 0 {
		// Without the routes, a single policy is tested as if its first
		// target matched every host and path. Several policies would all
		// claim that route.
		if len(in.Policies) > 1 {
			return nil, errors.New("several WAFPolicies: give the Ingresses or IngressRoutes they target with --ingress, so requests can be routed")
		}
		p := &in.Policies[0]
		covered := false
		for _, t := range p.Spec.TargetRefs {
			// The other targets are there, with no route of their own.
			switch t.Kind {
			case "Ingress":
				ing := networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: p.Namespace, Name: t.Name}}
				if !covered {
					ing.Spec.DefaultBackend = &networkingv1.IngressBackend{}
				}
				in.Ingresses = append(in.Ingresses, ing)
			case "IngressRoute":
				routes := []any{}
				if !covered {
					routes = append(routes, map[string]any{"match": "PathPrefix(`/`)"})
				}
				ir := unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"routes": routes}}}
				ir.SetGroupVersionKind(ingressRouteGVK)
				ir.SetNamespace(p.Namespace)
				ir.SetName(t.Name)
				in.IngressRoutes = append(in.IngressRoutes, ir)
			default:
				continue
			}
			if !covered {
				covered = true
				fmt.Fprintf(notes, "note: no --ingress: WAFPolicy %s/%s applies to every host and path\n", p.Namespace, p.Name)
			}
		}
	}

	// Inline rules are checked by the operator's validating webhook when
	// they are saved; rules from a ConfigMap when the bundle is built.
	var problems []string
	check := func(kind, name, seclang string) {
		if seclang == "" {
			return
		}
		if err := coraza.CheckUserRules(seclang); err != nil {
			problems = append(problems, fmt.Sprintf("%s %s: rejected by the validating webhook: %v", kind, name, err))
		}
	}
	for _, rs := range in.RuleSets {
		check("WAFRuleSet", rs.Namespace+"/"+rs.Name, rs.Spec.Source.SecLang)
	}
	for _, rs := range in.ClusterRuleSets {
		check("ClusterWAFRuleSet", rs.Name, rs.Spec.Source.SecLang)
	}
	in.CheckRules = coraza.CheckUserRules

	res := resolver.Resolve(in)
	enforced := map[string]bool{}
	for _, p := range res.Policies {
		enforced[p.GetId()] = true
	}
	for _, p := range in.Policies {
		st := res.PolicyStatus[types.NamespacedName{Namespace: p.Namespace, Name: p.Name}]
		id := resolver.PolicyID(p.Namespace, p.Name)
		switch {
		case !enforced[id]:
			problems = append(problems, fmt.Sprintf("WAFPolicy %s: not enforced: %s: %s", id, st.Reason, st.Message))
		case !st.Accepted:
			fmt.Fprintf(notes, "note: WAFPolicy %s: %s: %s\n", id, st.Reason, st.Message)
		case st.Message != resolver.PolicyValid:
			fmt.Fprintf(notes, "note: WAFPolicy %s: %s\n", id, st.Message)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(res.RuleSetStatus)) {
		if st := res.RuleSetStatus[id]; !st.Accepted {
			kind, name, _ := strings.Cut(id, "/") // "WAFRuleSet/namespace/name"
			problems = append(problems, fmt.Sprintf("%s %s: not accepted: %s: %s", kind, name, st.Reason, st.Message))
		}
	}
	if len(problems) > 0 {
		return nil, errors.New(strings.Join(problems, "\n  "))
	}
	return &bundlev1.Bundle{Policies: res.Policies, RuleSets: res.RuleSets, Suspended: suspended}, nil
}

// loadObjects reads the objects in files, or in the files of directories.
// Each file holds YAML documents or kubectl List objects; objects are taken
// by their kind, whichever flag named the file, and other kinds are
// skipped. Namespaced objects without a namespace get namespace, as kubectl
// apply does.
func loadObjects(files []string, namespace string, notes io.Writer) (resolver.Input, bool, error) {
	var (
		in        resolver.Input
		suspended bool
	)
	seen := map[string]string{} // kind/namespace/name -> file
	var add func(file string, doc []byte) error
	add = func(file string, doc []byte) error {
		var head struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Metadata   struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Items []json.RawMessage `json:"items"`
		}
		if err := yaml.Unmarshal(doc, &head); err != nil {
			return err
		}
		if head.Kind == "List" {
			for _, item := range head.Items {
				if err := add(file, item); err != nil {
					return err
				}
			}
			return nil
		}
		want, known := apiVersions[head.Kind]
		switch {
		case head.Kind == "":
			return errors.New("an object without a kind")
		case !known:
			fmt.Fprintf(notes, "note: %s: %s %s skipped\n", file, head.Kind, head.Metadata.Name)
			return nil
		case head.APIVersion != want:
			return fmt.Errorf("%s %s: apiVersion %q, want %q", head.Kind, head.Metadata.Name, head.APIVersion, want)
		case head.Metadata.Name == "":
			return fmt.Errorf("a %s without a name", head.Kind)
		}
		ns := cmp.Or(head.Metadata.Namespace, namespace)
		if head.Kind == "ClusterWAFRuleSet" || head.Kind == "InkwallConfig" {
			ns = ""
		}
		key := head.Kind + "/" + ns + "/" + head.Metadata.Name
		if prev, ok := seen[key]; ok {
			return fmt.Errorf("%s %s is also in %s", head.Kind, strings.TrimPrefix(ns+"/"+head.Metadata.Name, "/"), prev)
		}
		seen[key] = file

		// Strict, as the API server's field validation: a misspelled field
		// is an error, not a setting silently left out.
		var err error
		switch head.Kind {
		case "WAFPolicy":
			var o wafv1alpha1.WAFPolicy
			err = yaml.UnmarshalStrict(doc, &o)
			o.Namespace = ns
			in.Policies = append(in.Policies, o)
		case "WAFRuleSet":
			var o wafv1alpha1.WAFRuleSet
			err = yaml.UnmarshalStrict(doc, &o)
			o.Namespace = ns
			in.RuleSets = append(in.RuleSets, o)
		case "ClusterWAFRuleSet":
			var o wafv1alpha1.ClusterWAFRuleSet
			err = yaml.UnmarshalStrict(doc, &o)
			in.ClusterRuleSets = append(in.ClusterRuleSets, o)
		case "InkwallConfig":
			var o wafv1alpha1.InkwallConfig
			err = yaml.UnmarshalStrict(doc, &o)
			// The operator reads only the one named default.
			if o.Name == "default" {
				suspended = o.Spec.Suspend
			}
		case "Ingress":
			var o networkingv1.Ingress
			err = yaml.UnmarshalStrict(doc, &o)
			o.Namespace = ns
			in.Ingresses = append(in.Ingresses, o)
		case "IngressRoute":
			// Traefik's types aren't a dependency: the operator reads
			// IngressRoutes as unstructured objects too.
			var o unstructured.Unstructured
			var j []byte
			if j, err = yaml.YAMLToJSON(doc); err == nil {
				err = o.UnmarshalJSON(j)
			}
			o.SetNamespace(ns)
			in.IngressRoutes = append(in.IngressRoutes, o)
		case "ConfigMap":
			var o corev1.ConfigMap
			err = yaml.UnmarshalStrict(doc, &o)
			o.Namespace = ns
			switch {
			case err != nil:
			case o.Labels[resolver.RulesLabel] != "true":
				fmt.Fprintf(notes, "note: %s: ConfigMap %s/%s is not labeled %s=true; the operator doesn't read it\n",
					file, ns, o.Name, resolver.RulesLabel)
			default:
				in.ConfigMaps = append(in.ConfigMaps, o)
			}
		}
		if err != nil {
			return fmt.Errorf("%s %s: %w", head.Kind, head.Metadata.Name, err)
		}
		return nil
	}

	files, err := expandDirs(files)
	if err != nil {
		return in, false, err
	}
	for _, file := range files {
		// The path comes from the user's own command line.
		f, err := os.Open(filepath.Clean(file))
		if err != nil {
			return in, false, err
		}
		docs := utilyaml.NewYAMLReader(bufio.NewReader(f))
		for {
			doc, err := docs.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err == nil && !isEmptyDocument(doc) {
				err = add(file, doc)
			}
			if err != nil {
				_ = f.Close()
				return in, false, fmt.Errorf("%s: %w", file, err)
			}
		}
		_ = f.Close()
	}
	return in, suspended, nil
}

// expandDirs replaces each directory in paths by its .yaml, .yml and .json
// files, in name order, as kubectl apply -f does.
func expandDirs(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		entries, err := os.ReadDir(filepath.Clean(p))
		if err != nil {
			// Not a directory (or not there): read as a file.
			out = append(out, p)
			continue
		}
		n := len(out)
		for _, e := range entries {
			switch filepath.Ext(e.Name()) {
			case ".yaml", ".yml", ".json":
				if !e.IsDir() {
					out = append(out, filepath.Join(p, e.Name()))
				}
			}
		}
		if len(out) == n {
			return nil, fmt.Errorf("%s: no .yaml, .yml or .json file", p)
		}
	}
	return out, nil
}

// apiVersions are the kinds the operator reads, with their API versions.
var apiVersions = map[string]string{
	"WAFPolicy":         wafv1alpha1.GroupVersion.String(),
	"WAFRuleSet":        wafv1alpha1.GroupVersion.String(),
	"ClusterWAFRuleSet": wafv1alpha1.GroupVersion.String(),
	"InkwallConfig":     wafv1alpha1.GroupVersion.String(),
	"Ingress":           networkingv1.SchemeGroupVersion.String(),
	"IngressRoute":      ingressRouteGVK.GroupVersion().String(),
	"ConfigMap":         corev1.SchemeGroupVersion.String(),
}

// ingressRouteGVK is Traefik's IngressRoute, as the operator reads it.
var ingressRouteGVK = schema.GroupVersionKind{Group: "traefik.io", Version: "v1alpha1", Kind: "IngressRoute"}

// isEmptyDocument reports whether a YAML document holds only comments or
// whitespace, as between two "---".
func isEmptyDocument(doc []byte) bool {
	j, err := yaml.YAMLToJSON(doc)
	return err == nil && string(bytes.TrimSpace(j)) == "null"
}

// fileBundle reads a bundle file: the serialized SignedBundle, raw or
// gzip-compressed (the bundle Secret's bundle.pb.gz), or the bundle Secret
// itself (kubectl get secret inkwall-bundle -o yaml, or -o json). With
// keyFile, the signature is checked as the engine checks it; notes say
// what was read.
func fileBundle(file, keyFile string, notes io.Writer) (*bundlev1.Bundle, error) {
	// The paths come from the user's own command line.
	data, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}
	signed, err := decodeSignedBundle(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	verified := "signature not checked (no --bundle-key)"
	if keyFile != "" {
		key, err := readPublicKey(keyFile)
		if err != nil {
			return nil, err
		}
		// Verify before decoding, as the engine does.
		if !ed25519.Verify(key, signed.GetBundle(), signed.GetSignature()) {
			return nil, fmt.Errorf("%s: bad signature (key %q): not signed with --bundle-key", file, signed.GetKeyId())
		}
		verified = "signature verified"
	}
	var b bundlev1.Bundle
	if err := proto.Unmarshal(signed.GetBundle(), &b); err != nil {
		return nil, fmt.Errorf("%s: decode the bundle: %w", file, err)
	}
	created := ""
	if b.GetCreatedAt() != nil {
		created = ", created " + b.GetCreatedAt().AsTime().UTC().Format(time.RFC3339)
	}
	fmt.Fprintf(notes, "note: bundle version %d%s: %d policies, %s\n", b.GetVersion(), created, len(b.GetPolicies()), verified)
	return &b, nil
}

func decodeSignedBundle(data []byte) (*bundlev1.SignedBundle, error) {
	if !isGzip(data) {
		var s corev1.Secret
		var list struct {
			Kind  string          `json:"kind"`
			Items []corev1.Secret `json:"items"`
		}
		var err error
		switch {
		case yaml.Unmarshal(data, &s) == nil && s.Kind == "Secret":
			data, err = secretsBundle([]corev1.Secret{s})
		case yaml.Unmarshal(data, &list) == nil && strings.HasSuffix(list.Kind, "List"):
			data, err = secretsBundle(list.Items)
		}
		if err != nil {
			return nil, err
		}
	}
	if isGzip(data) {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("decompress the bundle: %w", err)
		}
		if data, err = io.ReadAll(io.LimitReader(zr, maxBundleBytes+1)); err != nil {
			return nil, fmt.Errorf("decompress the bundle: %w", err)
		}
		if len(data) > maxBundleBytes {
			return nil, fmt.Errorf("bundle over %d bytes decompressed", maxBundleBytes)
		}
	}
	var signed bundlev1.SignedBundle
	if err := proto.Unmarshal(data, &signed); err != nil || len(signed.GetBundle()) == 0 {
		return nil, errors.New("not a signed bundle (bundle.pb.gz of the inkwall-bundle Secret, compressed or not, or the Secret)")
	}
	return &signed, nil
}

// secretsBundle returns the compressed bundle of the bundle Secret among
// secrets, joined from its chunks, also among them, if it has a manifest.
func secretsBundle(secrets []corev1.Secret) ([]byte, error) {
	byName := map[string]*corev1.Secret{}
	for i := range secrets {
		byName[secrets[i].Name] = &secrets[i]
	}
	for _, s := range secrets {
		if data, ok := s.Data[secretBundleKey]; ok {
			return data, nil
		}
		if s.Data[bundlesecret.ManifestKey] == nil {
			continue
		}
		m, err := bundlesecret.ParseManifest(s.Name, s.Data[bundlesecret.ManifestKey])
		if err != nil {
			return nil, fmt.Errorf("the Secret %s: %w", s.Name, err)
		}
		return bundlesecret.Join(m, func(name string) ([]byte, error) {
			chunk, ok := byName[name]
			if !ok {
				return nil, fmt.Errorf("the bundle is in chunks: get them with the Secret (kubectl get secret %s %s -o yaml)",
					s.Name, strings.Join(m.Chunks, " "))
			}
			return chunk.Data[bundlesecret.ChunkKey], nil
		})
	}
	if len(secrets) == 1 {
		return nil, fmt.Errorf("the Secret %s has no %s", secrets[0].Name, secretBundleKey)
	}
	return nil, fmt.Errorf("no Secret has %s or %s", secretBundleKey, bundlesecret.ManifestKey)
}

func isGzip(b []byte) bool { return bytes.HasPrefix(b, []byte{0x1f, 0x8b}) }

// readPublicKey reads an ed25519 public key: the raw 32 bytes, as in the
// Secrets' ed25519.pub and the engine's --bundle-key, or their base64.
func readPublicKey(file string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		if d, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(b))); err == nil {
			b = d
		}
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("--bundle-key %s: want a raw %d-byte ed25519 key, or its base64", file, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// withDeadline returns b with every policy's inspection deadline set to d:
// a verdict must not depend on how fast the machine running the test is.
func withDeadline(b *bundlev1.Bundle, d time.Duration) *bundlev1.Bundle {
	b = proto.Clone(b).(*bundlev1.Bundle)
	for _, p := range b.GetPolicies() {
		p.Timeout = durationpb.New(d)
	}
	return b
}
