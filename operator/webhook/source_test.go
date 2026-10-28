// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"errors"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

const operatorUser = "system:serviceaccount:inkwall-system:inkwall-operator"

func guardFor(t *testing.T, mode wafv1alpha1.ClusterMode) *SourceGuard {
	t.Helper()
	s := runtime.NewScheme()
	_ = wafv1alpha1.AddToScheme(s)
	b := fake.NewClientBuilder().WithScheme(s)
	if mode != "" {
		b = b.WithObjects(&wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: wafv1alpha1.InkwallConfigSpec{Mode: mode}})
	}
	return &SourceGuard{Operator: operatorUser, Reader: b.Build()}
}

func asUser(user string, op admissionv1.Operation) context.Context {
	return admission.NewContextWithRequest(context.Background(), admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: op, UserInfo: authenticationv1.UserInfo{Username: user},
		Resource: metav1.GroupVersionResource{Group: wafv1alpha1.GroupVersion.Group, Version: "v1alpha1", Resource: "wafpolicies"},
	}})
}

func TestSourceGuard(t *testing.T) {
	saas := map[string]string{wafv1alpha1.SourceLabel: wafv1alpha1.SourceSaaS, "team": "shop"}
	mine := map[string]string{"team": "shop"}
	managed := guardFor(t, wafv1alpha1.ModeManaged)
	for _, tc := range []struct {
		name     string
		guard    *SourceGuard
		user     string
		op       admissionv1.Operation
		old, new map[string]string
		denied   bool
	}{
		{"someone else's object", managed, "alice", admissionv1.Update, mine, mine, false},
		{"create one labelled saas", managed, "alice", admissionv1.Create, nil, saas, true},
		{"change one", managed, "alice", admissionv1.Update, saas, saas, true},
		{"remove the label", managed, "alice", admissionv1.Update, saas, mine, true},
		{"add the label", managed, "alice", admissionv1.Update, mine, saas, true},
		{"delete one", managed, "alice", admissionv1.Delete, saas, nil, true},
		{"the operator creates one", managed, operatorUser, admissionv1.Create, nil, saas, false},
		{"the operator changes one", managed, operatorUser, admissionv1.Update, saas, saas, false},
		{"the operator deletes one", managed, operatorUser, admissionv1.Delete, saas, nil, false},
		{"the namespace controller deletes one", managed, "system:serviceaccount:kube-system:namespace-controller", admissionv1.Delete, saas, nil, false},
		{"the namespace controller can't change one", managed, "system:serviceaccount:kube-system:namespace-controller", admissionv1.Update, saas, saas, true},
		{"GitOps mode: ordinary objects", guardFor(t, wafv1alpha1.ModeGitOps), "alice", admissionv1.Update, saas, mine, false},
		{"no InkwallConfig: Standalone", guardFor(t, ""), "alice", admissionv1.Delete, saas, nil, false},
		{"no guard", nil, "alice", admissionv1.Delete, saas, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.guard.check(asUser(tc.user, tc.op), "shop", tc.old, tc.new)
			if tc.denied != (err != nil) {
				t.Fatalf("got %v, denied %v", err, tc.denied)
			}
			if tc.denied && !apierrors.IsForbidden(err) {
				t.Errorf("got %v, want Forbidden", err)
			}
		})
	}
}

// The guard fails closed: when the mode can't be read, the request is
// refused.
func TestSourceGuardFailsClosed(t *testing.T) {
	s := runtime.NewScheme()
	_ = wafv1alpha1.AddToScheme(s)
	broken := fake.NewClientBuilder().WithScheme(s).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errors.New("cache not synced")
		},
	}).Build()
	g := &SourceGuard{Operator: operatorUser, Reader: broken}
	saas := map[string]string{wafv1alpha1.SourceLabel: wafv1alpha1.SourceSaaS}
	if err := g.check(asUser("alice", admissionv1.Update), "shop", saas, saas); !apierrors.IsInternalError(err) {
		t.Errorf("got %v, want an internal error", err)
	}
	// Without a request in the context: refused too.
	if err := g.check(context.Background(), "shop", saas, saas); err == nil {
		t.Error("no request: allowed")
	}
}

// The validators run the guard on every operation, before the spec checks.
func TestValidatorsGuard(t *testing.T) {
	v := specValidator[*wafv1alpha1.WAFPolicy]{validate: validateWAFPolicy, guard: guardFor(t, wafv1alpha1.ModeManaged)}
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: "shop", Labels: map[string]string{wafv1alpha1.SourceLabel: wafv1alpha1.SourceSaaS}}}
	ctx := asUser("alice", admissionv1.Delete)
	if _, err := v.ValidateCreate(ctx, p); !apierrors.IsForbidden(err) {
		t.Errorf("create: %v", err)
	}
	if _, err := v.ValidateUpdate(ctx, p, p.DeepCopy()); !apierrors.IsForbidden(err) {
		t.Errorf("metadata-only update: %v", err)
	}
	if _, err := v.ValidateDelete(ctx, p); !apierrors.IsForbidden(err) {
		t.Errorf("delete: %v", err)
	}
}
