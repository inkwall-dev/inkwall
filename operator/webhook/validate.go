// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package webhook holds the operator's admission webhooks. The validating
// webhook checks what the CRD schemas can't (0004 §3.1, level 2): rule sets
// must compile the way the engine loads them, and policy paths must be ones
// the engine's router can match. In Managed mode it also keeps the control
// plane's policies to the operator (SourceGuard).
package webhook

import (
	"context"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/pkg/router"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// ValidatingConfigName is the ValidatingWebhookConfiguration the webhooks
// below are registered in; the certificate rotator injects its CA bundle.
const ValidatingConfigName = "inkwall-operator-validating"

// The webhooks only see the WAF kinds, never other objects, so failing
// closed can't block anything else in the cluster. A rule that slipped in
// while the webhook was down would only fail later, in every engine.
//
// +kubebuilder:webhookconfiguration:mutating=false,name=inkwall-operator-validating
// +kubebuilder:webhook:path=/validate-waf-inkwall-dev-v1alpha1-wafruleset,mutating=false,failurePolicy=fail,sideEffects=None,groups=waf.inkwall.dev,resources=wafrulesets,verbs=create;update,versions=v1alpha1,name=wafrulesets.waf.inkwall.dev,admissionReviewVersions=v1,timeoutSeconds=2
// +kubebuilder:webhook:path=/validate-waf-inkwall-dev-v1alpha1-clusterwafruleset,mutating=false,failurePolicy=fail,sideEffects=None,groups=waf.inkwall.dev,resources=clusterwafrulesets,verbs=create;update,versions=v1alpha1,name=clusterwafrulesets.waf.inkwall.dev,admissionReviewVersions=v1,timeoutSeconds=2
// +kubebuilder:webhook:path=/validate-waf-inkwall-dev-v1alpha1-wafpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=waf.inkwall.dev,resources=wafpolicies,verbs=create;update,versions=v1alpha1,name=wafpolicies.waf.inkwall.dev,admissionReviewVersions=v1,timeoutSeconds=2
//
// Deletes go to the same webhooks only for the control plane's objects (the
// objectSelector), so deleting any other object never needs the operator.
//
// +kubebuilder:webhook:path=/validate-waf-inkwall-dev-v1alpha1-wafruleset,mutating=false,failurePolicy=fail,sideEffects=None,groups=waf.inkwall.dev,resources=wafrulesets,verbs=delete,versions=v1alpha1,name=delete.wafrulesets.waf.inkwall.dev,admissionReviewVersions=v1,timeoutSeconds=2,patch=`{"objectSelector":{"matchLabels":{"inkwall.dev/source":"saas"}}}`
// +kubebuilder:webhook:path=/validate-waf-inkwall-dev-v1alpha1-clusterwafruleset,mutating=false,failurePolicy=fail,sideEffects=None,groups=waf.inkwall.dev,resources=clusterwafrulesets,verbs=delete,versions=v1alpha1,name=delete.clusterwafrulesets.waf.inkwall.dev,admissionReviewVersions=v1,timeoutSeconds=2,patch=`{"objectSelector":{"matchLabels":{"inkwall.dev/source":"saas"}}}`
// +kubebuilder:webhook:path=/validate-waf-inkwall-dev-v1alpha1-wafpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=waf.inkwall.dev,resources=wafpolicies,verbs=delete,versions=v1alpha1,name=delete.wafpolicies.waf.inkwall.dev,admissionReviewVersions=v1,timeoutSeconds=2,patch=`{"objectSelector":{"matchLabels":{"inkwall.dev/source":"saas"}}}`

// Setup registers the validating webhooks with mgr's webhook server, and
// the Pod webhook when inject is set. guard keeps the control plane's
// objects to the operator.
func Setup(mgr manager.Manager, inject *PodInjector, guard *SourceGuard) error {
	if inject != nil {
		mgr.GetWebhookServer().Register(InjectPath, &ctrlwebhook.Admission{Handler: inject})
	}
	if err := builder.WebhookManagedBy(mgr, &wafv1alpha1.WAFRuleSet{}).
		WithValidator(specValidator[*wafv1alpha1.WAFRuleSet]{validateWAFRuleSet, guard}).Complete(); err != nil {
		return err
	}
	if err := builder.WebhookManagedBy(mgr, &wafv1alpha1.ClusterWAFRuleSet{}).
		WithValidator(specValidator[*wafv1alpha1.ClusterWAFRuleSet]{validateClusterWAFRuleSet, guard}).Complete(); err != nil {
		return err
	}
	return builder.WebhookManagedBy(mgr, &wafv1alpha1.WAFPolicy{}).
		WithValidator(specValidator[*wafv1alpha1.WAFPolicy]{validateWAFPolicy, guard}).Complete()
}

// object is a WAF kind with a spec.
type object interface {
	*wafv1alpha1.WAFRuleSet | *wafv1alpha1.ClusterWAFRuleSet | *wafv1alpha1.WAFPolicy
	GetName() string
	GetLabels() map[string]string
}

// specValidator runs validate on create, and on update only when the spec
// changed: an object accepted earlier must stay editable (labels,
// finalizers, deletion) even if a newer engine would reject its spec. The
// guard comes first, on every operation.
type specValidator[T object] struct {
	validate func(T) (admission.Warnings, error)
	guard    *SourceGuard
}

func (v specValidator[T]) ValidateCreate(ctx context.Context, obj T) (admission.Warnings, error) {
	if err := v.guard.check(ctx, obj.GetName(), nil, obj.GetLabels()); err != nil {
		return nil, err
	}
	return v.validate(obj)
}

func (v specValidator[T]) ValidateUpdate(ctx context.Context, oldObj, newObj T) (admission.Warnings, error) {
	if err := v.guard.check(ctx, newObj.GetName(), oldObj.GetLabels(), newObj.GetLabels()); err != nil {
		return nil, err
	}
	if apiequality.Semantic.DeepEqual(spec(oldObj), spec(newObj)) {
		return nil, nil
	}
	return v.validate(newObj)
}

func (v specValidator[T]) ValidateDelete(ctx context.Context, obj T) (admission.Warnings, error) {
	return nil, v.guard.check(ctx, obj.GetName(), obj.GetLabels(), nil)
}

func spec(obj any) any {
	switch o := obj.(type) {
	case *wafv1alpha1.WAFRuleSet:
		return o.Spec
	case *wafv1alpha1.ClusterWAFRuleSet:
		return o.Spec
	case *wafv1alpha1.WAFPolicy:
		return o.Spec
	}
	return obj
}

func invalid(kind, name string, errs field.ErrorList) error {
	if len(errs) == 0 {
		return nil
	}
	return apierrors.NewInvalid(schema.GroupKind{Group: wafv1alpha1.GroupVersion.Group, Kind: kind}, name, errs)
}

const configMapWarning = "rules read from a ConfigMap are checked when the operator builds the bundle, not when the rule set is saved"

func validateWAFRuleSet(rs *wafv1alpha1.WAFRuleSet) (admission.Warnings, error) {
	src := rs.Spec.Source
	var warnings admission.Warnings
	if src.ConfigMapRef != nil {
		warnings = append(warnings, configMapWarning)
	}
	return warnings, invalid("WAFRuleSet", rs.Name, checkSecLang(src.SecLang))
}

func validateClusterWAFRuleSet(rs *wafv1alpha1.ClusterWAFRuleSet) (admission.Warnings, error) {
	src := rs.Spec.Source
	var warnings admission.Warnings
	if src.ConfigMapRef != nil {
		warnings = append(warnings, configMapWarning)
	}
	return warnings, invalid("ClusterWAFRuleSet", rs.Name, checkSecLang(src.SecLang))
}

// checkSecLang compiles inline rules after the Core Rule Set, as the engine
// loads them, and allows only rule directives (coraza.CheckUserRules).
func checkSecLang(rules string) field.ErrorList {
	if rules == "" {
		return nil
	}
	if err := coraza.CheckUserRules(rules); err != nil {
		// The rules can be long: name the line instead of echoing them.
		return field.ErrorList{field.Invalid(field.NewPath("spec", "source", "seclang"), field.OmitValueType{}, err.Error())}
	}
	return nil
}

func validateWAFPolicy(p *wafv1alpha1.WAFPolicy) (admission.Warnings, error) {
	var errs field.ErrorList
	spec := field.NewPath("spec")
	if s := p.Spec.Skip; s != nil {
		errs = append(errs, checkPaths(spec.Child("skip", "paths"), s.Paths)...)
		errs = append(errs, checkPaths(spec.Child("skip", "bodyPaths"), s.BodyPaths)...)
	}
	for i, e := range p.Spec.Exclusions {
		if e.When != nil && e.When.Path != "" {
			errs = append(errs, checkPath(spec.Child("exclusions").Index(i).Child("when", "path"), e.When.Path)...)
		}
	}
	return nil, invalid("WAFPolicy", p.Name, errs)
}

func checkPaths(path *field.Path, patterns []wafv1alpha1.PathPattern) field.ErrorList {
	var errs field.ErrorList
	for i, p := range patterns {
		errs = append(errs, checkPath(path.Index(i), p)...)
	}
	return errs
}

// checkPath accepts the patterns the engine's router accepts. The CRD
// schema already limits the characters; the router also requires clean
// paths, which a regular expression can't express.
func checkPath(path *field.Path, p wafv1alpha1.PathPattern) field.ErrorList {
	if _, err := router.New([]string{string(p)}, nil); err != nil {
		return field.ErrorList{field.Invalid(path, string(p), err.Error())}
	}
	return nil
}
