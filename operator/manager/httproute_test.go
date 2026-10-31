// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/wiring"
	"github.com/inkwall-dev/inkwall/operator/resolver"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

// testHTTPRoutes follows a policy on a Gateway API HTTPRoute: the operator
// runs without the HTTPRoute CRD, notices it once installed, puts the
// route's matches in the bundle and reports a match it can't read. No proxy
// wires HTTPRoutes yet: the policy isn't Programmed.
func testHTTPRoutes(ctx context.Context, t *testing.T, c client.Client) {
	const ns = "gateway"
	cond := func(typ string, st metav1.ConditionStatus, reason, msg string) func() string {
		return func() string {
			var got wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "app"}, &got); err != nil {
				return err.Error()
			}
			cnd := meta.FindStatusCondition(got.Status.Conditions, typ)
			if cnd == nil {
				return "no " + typ
			}
			if cnd.Status != st || cnd.Reason != reason || !strings.Contains(cnd.Message, msg) || cnd.ObservedGeneration != got.Generation {
				return typ + ": " + string(cnd.Status) + " " + cnd.Reason + ": " + cnd.Message
			}
			return ""
		}
	}
	routes := func() string {
		p := findPolicy(current(ctx, t, c), ns+"/app")
		if p == nil {
			return "not in the bundle"
		}
		var got []string
		for _, r := range p.GetRoutes() {
			got = append(got, strings.Join(append([]string{r.GetHost(), bundlev1.PathMatchType_name[int32(r.GetPath().GetType())], r.GetPath().GetValue()}, r.GetMethods()...), " "))
		}
		return strings.Join(got, ", ")
	}

	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	pol := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app"},
		Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "app"}},
		},
	}
	if err := c.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}

	// No HTTPRoute CRD: the operator runs, and says so.
	eventually(t, "Accepted without the CRD", cond(wafv1alpha1.ConditionAccepted, metav1.ConditionFalse,
		resolver.ReasonInvalidRef, "HTTPRoute app not found"))

	// Installed later, then the route.
	if err := testenv.InstallGatewayAPI(env); err != nil {
		t.Fatal(err)
	}
	post := gatewayv1.HTTPMethodPost
	exact, prefix := gatewayv1.PathMatchExact, gatewayv1.PathMatchPathPrefix
	hr := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app"},
		Spec: gatewayv1.HTTPRouteSpec{
			Hostnames: []gatewayv1.Hostname{"app.example.com"},
			Rules: []gatewayv1.HTTPRouteRule{{Matches: []gatewayv1.HTTPRouteMatch{
				{Path: &gatewayv1.HTTPPathMatch{Type: &prefix, Value: new("/api")}},
				{Path: &gatewayv1.HTTPPathMatch{Type: &exact, Value: new("/login")}, Method: &post},
			}}},
		},
	}
	if err := c.Create(ctx, hr); err != nil {
		t.Fatal(err)
	}
	eventually(t, "Accepted", cond(wafv1alpha1.ConditionAccepted, metav1.ConditionTrue, resolver.ReasonAccepted, ""))
	eventually(t, "Programmed=False", cond(wafv1alpha1.ConditionProgrammed, metav1.ConditionFalse,
		wiring.ReasonControllerUnsupported, "HTTPRoute app"))
	eventually(t, "the routes in the bundle", func() string {
		if s := routes(); s != "app.example.com PATH_MATCH_TYPE_PREFIX /api, app.example.com PATH_MATCH_TYPE_EXACT /login POST" {
			return s
		}
		return ""
	})

	// A match the engine can't match on: not accepted, the rule named; the
	// bundle keeps the previous version.
	update(ctx, t, c, hr, func(r *gatewayv1.HTTPRoute) {
		r.Spec.Rules[0].Matches[0].Headers = []gatewayv1.HTTPHeaderMatch{{Name: "X-Canary", Value: "1"}}
	})
	eventually(t, "Accepted=False on an unreadable match", cond(wafv1alpha1.ConditionAccepted, metav1.ConditionFalse,
		resolver.ReasonTargetUnsupported, "HTTPRoute app: spec.rules[0].matches[0]: headers"))
	if s := routes(); !strings.Contains(s, "/login POST") {
		t.Errorf("the previous version must stay in the bundle: %s", s)
	}

	if err := c.Delete(ctx, pol); err != nil {
		t.Fatal(err)
	}
}
