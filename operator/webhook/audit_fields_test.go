// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// specFields walks t's JSON fields under path, as diff names them (a
// list's items under the list's path), and calls visit for each.
func specFields(path string, t reflect.Type, seen map[reflect.Type]bool, visit func(parent, name string)) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] || t.PkgPath() != reflect.TypeFor[wafv1alpha1.WAFPolicySpec]().PkgPath() {
		return
	}
	seen[t] = true
	defer delete(seen, t)
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			specFields(path, f.Type, seen, visit) // embedded
			continue
		}
		visit(path, name)
		specFields(path+"."+name, f.Type, seen, visit)
	}
}

// TestAuditFieldNames lists the fields of the five kinds' specs whose
// names suggest a credential, an address or a header, and how the audit
// log shows them: a field added to the API with such a name fails here
// until it is reviewed and listed (#726).
func TestAuditFieldNames(t *testing.T) {
	want := map[string]mode{
		// URLs: scheme and host only.
		"spec.controlPlane.endpoint":             modeURL,
		"spec.events.export.sinks.json.url":      modeURL,
		"spec.events.export.sinks.otlp.endpoint": modeURL,
		// A sink's headers: never.
		"spec.events.export.sinks.headersSecretRef": modeSecret,
	}
	suspicious := regexp.MustCompile(`(?i)token|passw|secret|key|credential|url|uri|endpoint|header|auth|cert`)
	got := map[string]mode{}
	var plain []string
	for _, spec := range []reflect.Type{
		reflect.TypeFor[wafv1alpha1.WAFPolicySpec](), reflect.TypeFor[wafv1alpha1.WAFRuleSetSpec](),
		reflect.TypeFor[wafv1alpha1.ClusterWAFRuleSetSpec](), reflect.TypeFor[wafv1alpha1.WAFIPListSpec](),
		reflect.TypeFor[wafv1alpha1.InkwallConfigSpec](),
	} {
		modes := map[string]mode{"spec": modePlain}
		specFields("spec", spec, map[reflect.Type]bool{}, func(parent, name string) {
			path := parent + "." + name
			m := fieldMode(modes[parent], parent, name)
			modes[path] = m
			switch {
			case m != modePlain && modes[parent] == m:
				// Under a field already redacted.
			case m != modePlain:
				got[path] = m
			case suspicious.MatchString(name):
				plain = append(plain, path)
			}
		})
	}
	for path, m := range got {
		if w, ok := want[path]; !ok || w != m {
			t.Errorf("%s: mode %d, want %d", path, m, w)
		}
	}
	for path := range want {
		if _, ok := got[path]; !ok {
			t.Errorf("%s: shown in full, or no such field", path)
		}
	}
	// Shown in full: Secrets' and ConfigMaps' names and keys, header
	// names, the rate limit key, the signing key's rotation. None holds a
	// credential; a new field here must not either, or belongs in
	// secretName or urlName.
	slices.Sort(plain)
	plain = slices.Compact(plain)
	reviewed := []string{
		"spec.controlPlane.enrollmentSecretRef",
		"spec.engine.rateLimitKeys",
		"spec.events.export.sinks.json.urlSecretRef",
		"spec.events.export.sinks.json.urlSecretRef.key",
		"spec.events.export.sinks.tls.caSecretRef",
		"spec.events.export.sinks.tls.clientCertificateSecretRef",
		"spec.events.redact.headers",
		"spec.exclusions.when.header",
		// LLM API paths and output-token caps: no credential.
		"spec.llm.endpoints",
		"spec.llm.request.maxOutputTokens",
		"spec.llm.request.requireOutputTokens",
		"spec.rateLimits.key",
		"spec.rateLimits.key.header",
		"spec.signingKey",
		"spec.source.configMapRef.key",
		"spec.webSocket.requiredHeaders",
	}
	for _, path := range plain {
		if !slices.Contains(reviewed, path) {
			t.Errorf("%s is shown in full and isn't reviewed: list it here if it can't hold a credential", path)
		}
	}
	for _, path := range reviewed {
		if !slices.Contains(plain, path) {
			t.Errorf("%s: no such field shown in full", path)
		}
	}
}

// TestAuditGroupsBounded: a user in many groups gets maxGroups listed, and
// the rest counted.
func TestAuditGroupsBounded(t *testing.T) {
	a, out, _ := auditTest()
	v := audited[*wafv1alpha1.WAFPolicy]{allow[*wafv1alpha1.WAFPolicy]{}, a}
	u := alice
	u.Groups = nil
	for i := range 40 {
		u.Groups = append(u.Groups, fmt.Sprintf("team-%02d", i))
	}
	if _, err := v.ValidateCreate(admissionCtx(admissionv1.Create, "WAFPolicy", u, false), policy(wafv1alpha1.PolicyBlock)); err != nil {
		t.Fatal(err)
	}
	l := lines(t, out)
	if groups, _ := l[0]["groups"].([]any); len(groups) != maxGroups || groups[0] != "team-00" || l[0]["groupsOmitted"] != float64(40-maxGroups) {
		t.Errorf("groups %v, omitted %v", l[0]["groups"], l[0]["groupsOmitted"])
	}
}

// TestEventPrefix: the Events' generateName is valid for any object name,
// as the API server checks it (a trailing dash allowed), and so is a name
// made from it.
func TestEventPrefix(t *testing.T) {
	for _, name := range []string{"checkout", strings.Repeat("a", 253), strings.Repeat("a.", 120) + "b", strings.Repeat("ab-", 80) + "c"} {
		p := eventPrefix(name)
		if errs := validation.IsDNS1123Subdomain(strings.TrimSuffix(p, "-") + "a"); len(errs) != 0 {
			t.Errorf("%q: prefix %q: %v", name, p, errs)
		}
		if errs := validation.IsDNS1123Subdomain(p + "x7k2q"); len(errs) != 0 {
			t.Errorf("%q: name %q: %v", name, p+"x7k2q", errs)
		}
	}
}

// TestDeleteWebhooksFailOpen: deleting the objects that aren't the control
// plane's, and the InkwallConfig, never waits for the operator to answer
// (the audit-delete webhooks fail open); only the control plane's deletes
// fail closed, for the SourceGuard (#726).
func TestDeleteWebhooksFailOpen(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "config", "webhook", "manifests.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg admissionregistrationv1.ValidatingWebhookConfiguration
	for _, doc := range strings.Split(string(raw), "\n---\n") {
		if strings.Contains(doc, "kind: ValidatingWebhookConfiguration") {
			if err := yaml.Unmarshal([]byte(doc), &cfg); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(cfg.Webhooks) == 0 {
		t.Fatal("no validating webhooks")
	}
	saas := map[string]string{wafv1alpha1.SourceLabel: wafv1alpha1.SourceSaaS}
	deletes := map[string]bool{}
	for _, w := range cfg.Webhooks {
		if w.SideEffects == nil || *w.SideEffects != admissionregistrationv1.SideEffectClassNoneOnDryRun {
			t.Errorf("%s: sideEffects %v, want NoneOnDryRun", w.Name, w.SideEffects)
		}
		for _, r := range w.Rules {
			if !slices.Contains(r.Operations, admissionregistrationv1.Delete) {
				continue
			}
			fp := *w.FailurePolicy
			fromSaaS := w.ObjectSelector != nil && maps.Equal(w.ObjectSelector.MatchLabels, saas) && len(w.ObjectSelector.MatchExpressions) == 0
			switch {
			case fromSaaS && fp != admissionregistrationv1.Fail:
				t.Errorf("%s: the control plane's deletes fail %s, want Fail", w.Name, fp)
			case !fromSaaS && fp != admissionregistrationv1.Ignore:
				t.Errorf("%s: deletes fail %s, want Ignore", w.Name, fp)
			}
			if fromSaaS {
				continue
			}
			for _, res := range r.Resources {
				deletes[res] = true
				everyOther := w.ObjectSelector != nil && len(w.ObjectSelector.MatchExpressions) == 1 &&
					w.ObjectSelector.MatchExpressions[0].Operator == metav1.LabelSelectorOpNotIn
				if res != "inkwallconfigs" && !everyOther {
					t.Errorf("%s: selector %v, want every object not from the control plane", w.Name, w.ObjectSelector)
				}
			}
		}
	}
	for _, res := range []string{"wafpolicies", "wafrulesets", "clusterwafrulesets", "wafiplists", "inkwallconfigs"} {
		if !deletes[res] {
			t.Errorf("no webhook sees the deletes of %s", res)
		}
	}
}
