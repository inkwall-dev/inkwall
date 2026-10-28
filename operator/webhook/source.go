// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"errors"
	"fmt"
	"slices"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// SourceGuard keeps the control plane's objects, labelled
// inkwall.dev/source: saas, to the operator while the cluster is in Managed
// mode (0004 §4.9): no one else may create, change or delete them, or add
// or remove the label. In the other modes the operator doesn't write them,
// so they are ordinary objects again, which their owners can clean up.
type SourceGuard struct {
	// Operator is the user the operator writes as (OperatorUser).
	Operator string
	// Reader reads the InkwallConfig, whose mode decides.
	Reader client.Reader
}

// namespaceDeleters may delete the control plane's objects too: the
// namespace controller deletes everything in a namespace being deleted, as
// itself or as kube-controller-manager depending on how that runs. Without
// them a deleted namespace would never go away.
var namespaceDeleters = []string{"system:serviceaccount:kube-system:namespace-controller", "system:kube-controller-manager"}

func fromSaaS(labels map[string]string) bool {
	return labels[wafv1alpha1.SourceLabel] == wafv1alpha1.SourceSaaS
}

// check allows the request unless it touches a control plane object (before
// or after: adding and removing the label count) in Managed mode and comes
// from someone other than the operator. It fails closed: an error reading
// the mode refuses.
func (g *SourceGuard) check(ctx context.Context, name string, oldLabels, newLabels map[string]string) error {
	if g == nil || (!fromSaaS(oldLabels) && !fromSaaS(newLabels)) {
		return nil
	}
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return apierrors.NewInternalError(err)
	}
	user := req.UserInfo.Username
	if user == g.Operator || (req.Operation == admissionv1.Delete && slices.Contains(namespaceDeleters, user)) {
		return nil
	}
	var cfg wafv1alpha1.InkwallConfig
	err = g.Reader.Get(ctx, types.NamespacedName{Name: "default"}, &cfg)
	if apierrors.IsNotFound(err) {
		return nil // Standalone
	}
	if err != nil {
		return apierrors.NewInternalError(fmt.Errorf("reading the InkwallConfig: %w", err))
	}
	if cfg.Spec.Mode != wafv1alpha1.ModeManaged {
		return nil
	}
	return apierrors.NewForbidden(schema.GroupResource{Group: req.Resource.Group, Resource: req.Resource.Resource}, name, fmt.Errorf(
		"in Managed mode, objects labelled %s=%s come from the control plane: change them there (only the operator writes them, and the label can't be added or removed)",
		wafv1alpha1.SourceLabel, wafv1alpha1.SourceSaaS))
}

// OperatorUser asks the API server who the operator is (SelfSubjectReview,
// which every authenticated user may ask), so the guard knows its writes
// whatever its ServiceAccount is called.
func OperatorUser(ctx context.Context, c client.Client) (string, error) {
	var user string
	err := retry.OnError(retry.DefaultBackoff, func(error) bool { return ctx.Err() == nil }, func() error {
		r := &authenticationv1.SelfSubjectReview{}
		if err := c.Create(ctx, r); err != nil {
			return err
		}
		user = r.Status.UserInfo.Username
		if user == "" {
			return errors.New("no user name")
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("who the operator is (SelfSubjectReview): %w", err)
	}
	return user, nil
}
