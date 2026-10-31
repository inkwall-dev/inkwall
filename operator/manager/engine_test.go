// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
	"github.com/inkwall-dev/inkwall/pkg/agent"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/policy"
	"github.com/inkwall-dev/inkwall/pkg/request"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
)

// testEngine runs the engine's own bundle client against the operator, as
// the sidecar does: with its projected token, the operator's CA and the
// cluster's public key in files. The web/web policy (block mode, from
// testDistribution) then blocks an attack in the engine.
func testEngine(ctx context.Context, t *testing.T, c client.Client) {
	// testBundles left the cluster suspended.
	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	update(ctx, t, c, cfg, func(cfg *wafv1alpha1.InkwallConfig) { cfg.Spec.Suspend = false })

	var certs, keys corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "inkwall-operator-webhook-tls"}, &certs); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: bundle.SigningKeySecret}, &keys); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := map[string][]byte{
		"ca.crt":      certs.Data["ca.crt"],
		"ed25519.pub": keys.Data[bundle.PublicKeyKey],
		"token":       []byte(token(ctx, t, "edge", "traefik")),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	holder := &policy.Holder{}
	adm := pipeline.NewAdmission(4)
	_, port, _ := net.SplitHostPort(distAddr)
	a, err := agent.New(agent.Config{
		Addr:          "localhost:" + port,
		CAFile:        filepath.Join(dir, "ca.crt"),
		TokenFile:     filepath.Join(dir, "token"),
		PublicKeyFile: filepath.Join(dir, "ed25519.pub"),
		CacheFile:     filepath.Join(dir, "bundle.pb"),
		EngineID:      "traefik-engine",
		PodNamespace:  "edge",
		PodName:       "traefik-engine",
		Compile: func(b *bundlev1.Bundle) (*policy.Set, error) {
			// The deadline isn't under test: a generous one (the CRD
			// allows 1s at most) keeps a loaded machine from turning a
			// verdict into deny/timeout.
			b = proto.Clone(b).(*bundlev1.Bundle)
			for _, p := range b.GetPolicies() {
				p.Timeout = durationpb.New(10 * time.Second)
			}
			return policy.Compile(b, policy.Options{Admission: adm, BodyLimit: 65536})
		},
		Holder:    holder,
		Admission: adm,
		Logger:    slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	actx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = a.Run(actx); close(done) }()
	defer func() { cancel(); <-done }()

	check := func(host, uri string) pipeline.Verdict {
		return holder.Check(ctx, &request.Request{
			Proto: "HTTP/1.1", Method: "GET", Scheme: "https", Host: host, RawURI: uri,
			Headers: http.Header{"User-Agent": {"Mozilla/5.0 inkwall-test"}, "Accept": {"text/html"}},
		})
	}
	const sqli = "/?id=1%27%20OR%20%271%27%3D%271"
	eventually(t, "the engine blocks with the operator's policy", func() string {
		v := check("web.example.com", sqli)
		if v.Action != pipeline.ActionDeny || v.Reason != pipeline.ReasonRule {
			return "got " + v.Action.String() + "/" + v.Reason.String()
		}
		return ""
	})
	if v := check("web.example.com", "/products/42"); v.Action != pipeline.ActionAllow || v.Reason != pipeline.ReasonNone {
		t.Errorf("benign request: %s/%s", v.Action, v.Reason)
	}
	if v := check("unprotected.example.com", sqli); v.Reason != pipeline.ReasonNoPolicy {
		t.Errorf("a host no policy covers: %s/%s", v.Action, v.Reason)
	}

	pol := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "web"}}
	eventually(t, "Enforced by the engine", func() string {
		if err := c.Get(ctx, client.ObjectKeyFromObject(pol), pol); err != nil {
			return err.Error()
		}
		for _, cond := range pol.Status.Conditions {
			if cond.Type == wafv1alpha1.ConditionEnforced {
				if cond.Reason == distribution.ReasonEnforced {
					return ""
				}
				return cond.Reason + ": " + cond.Message
			}
		}
		return "no Enforced condition"
	})
}
