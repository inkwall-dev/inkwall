// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package access tells which integrations the operator may wire (0004 §7).
// Each integration's permissions are in a ClusterRole of its own, which the
// chart can leave out: the operator checks, when it starts, that it has
// them, and disables the integrations it lacks some of.
package access

import (
	"context"
	"fmt"
	"strings"

	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/inkwall-dev/inkwall/operator/config/rbac"
)

// RolePrefix starts the name of each integration's ClusterRole in
// role.yaml, followed by the integration's name.
const RolePrefix = "inkwall-operator-"

// Roles returns the rules of each integration's ClusterRole, by
// integration name.
func Roles() (map[string][]rbacv1.PolicyRule, error) {
	roles := map[string][]rbacv1.PolicyRule{}
	for _, doc := range strings.Split(string(rbac.Roles), "\n---\n") {
		var role rbacv1.ClusterRole
		if err := yaml.Unmarshal([]byte(doc), &role); err != nil {
			return nil, err
		}
		if role.Kind == "ClusterRole" && strings.HasPrefix(role.Name, RolePrefix) {
			roles[strings.TrimPrefix(role.Name, RolePrefix)] = role.Rules
		}
	}
	return roles, nil
}

// Missing returns the permissions of rules the operator lacks
// cluster-wide, as "verb resource.group", asking the API server
// (SelfSubjectAccessReview). The rules name resources and verbs.
func Missing(ctx context.Context, c client.Client, rules []rbacv1.PolicyRule) ([]string, error) {
	var missing []string
	for _, r := range rules {
		for _, group := range r.APIGroups {
			for _, resource := range r.Resources {
				for _, verb := range r.Verbs {
					review := &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{
						ResourceAttributes: &authorizationv1.ResourceAttributes{Group: group, Resource: resource, Verb: verb},
					}}
					if err := c.Create(ctx, review); err != nil {
						return nil, fmt.Errorf("check %s %s: %w", verb, resource, err)
					}
					if !review.Status.Allowed {
						missing = append(missing, strings.TrimSuffix(verb+" "+resource+"."+group, "."))
					}
				}
			}
		}
	}
	return missing, nil
}

// Denied returns, by integration name, why the operator may not wire an
// integration: the permissions of its ClusterRole it lacks.
func Denied(ctx context.Context, c client.Client) (map[string]string, error) {
	roles, err := Roles()
	if err != nil {
		return nil, err
	}
	denied := map[string]string{}
	for name, rules := range roles {
		missing, err := Missing(ctx, c, rules)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if len(missing) == 0 {
			continue
		}
		if len(missing) > 3 {
			missing = append(missing[:3], fmt.Sprintf("%d more", len(missing)-3))
		}
		denied[name] = fmt.Sprintf("the %s integration is disabled: the operator may not %s (the chart's rbac.integrations.%s role isn't granted: "+
			"set it to true, or helm upgrade once the proxy is installed); the operator restarts with it once granted", name, strings.Join(missing, ", "), chartValue(name))
	}
	return denied, nil
}

// chartValue returns the key of rbac.integrations that grants an
// integration's ClusterRole: its name in camel case (envoy-gateway:
// envoyGateway). The message names it rather than the role, whose name
// the chart derives from the release's.
func chartValue(name string) string {
	parts := strings.Split(name, "-")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}
