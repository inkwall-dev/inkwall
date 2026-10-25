// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
)

func podRequest(t *testing.T, labels map[string]string) admission.Request {
	t.Helper()
	raw, err := json.Marshal(&corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{GenerateName: "traefik-", Namespace: "traefik", Labels: labels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "traefik", Image: "traefik:v3"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Create, Namespace: "traefik", Object: runtime.RawExtension{Raw: raw},
	}}
}

func injector(t *testing.T, objs ...client.Object) *PodInjector {
	t.Helper()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	return &PodInjector{
		Client:       fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build(),
		Decoder:      admission.NewDecoder(s),
		Image:        "ghcr.io/inkwall-dev/inkwall-engine:0.1.0",
		PullPolicy:   corev1.PullIfNotPresent,
		OperatorAddr: "inkwall-operator.inkwall-system.svc:9445",
		BundleSecret: "inkwall-system/inkwall-bundle",
	}
}

func patched(resp admission.Response) string {
	b, _ := json.Marshal(resp.Patches)
	return string(b)
}

func TestPodInjector(t *testing.T) {
	ctx := context.Background()
	traefik := map[string]string{"app.kubernetes.io/name": "traefik"}

	resp := injector(t).Handle(ctx, podRequest(t, traefik))
	if !resp.Allowed || len(resp.Patches) == 0 {
		t.Fatalf("a Traefik pod: allowed=%v, %d patches", resp.Allowed, len(resp.Patches))
	}
	p := patched(resp)
	for _, want := range []string{"inkwall-engine", "ghcr.io/inkwall-dev/inkwall-engine:0.1.0", "--operator=inkwall-operator.inkwall-system.svc:9445", "forward-auth", "inkwall-trust", "--bundle-secret=inkwall-system/inkwall-bundle"} {
		if !strings.Contains(p, want) {
			t.Errorf("patch lacks %s", want)
		}
	}

	// Traefik deployed with other labels, named in InkwallConfig.
	custom, _, err := integrations.FromConfig([]wafv1alpha1.IntegrationSpec{{Controller: "traefik", Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "edge"}}}})
	if err != nil {
		t.Fatal(err)
	}
	inj := injector(t)
	inj.Integrations = custom
	if resp := inj.Handle(ctx, podRequest(t, map[string]string{"app": "edge"})); len(resp.Patches) == 0 {
		t.Error("a pod of the custom selector was not injected")
	}
	if resp := inj.Handle(ctx, podRequest(t, traefik)); len(resp.Patches) != 0 {
		t.Error("the default labels still match with a custom selector")
	}

	// Another pod (the objectSelector would normally keep it away).
	resp = injector(t).Handle(ctx, podRequest(t, map[string]string{"app": "shop"}))
	if !resp.Allowed || len(resp.Patches) != 0 {
		t.Fatalf("not a proxy pod: allowed=%v, %d patches", resp.Allowed, len(resp.Patches))
	}

	// InkwallConfig sets the image and resources.
	cfg := &wafv1alpha1.InkwallConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       wafv1alpha1.InkwallConfigSpec{Engine: wafv1alpha1.EngineSpec{Image: "registry.example.com/inkwall-engine:pinned"}},
	}
	resp = injector(t, cfg).Handle(ctx, podRequest(t, traefik))
	if !strings.Contains(patched(resp), "registry.example.com/inkwall-engine:pinned") {
		t.Error("InkwallConfig's image not used")
	}
	if strings.Contains(p, "--bootstrap=deny") {
		t.Error("bootstrap deny without InkwallConfig")
	}

	// And the bootstrap mode.
	cfg.Spec.Engine.BootstrapMode = wafv1alpha1.BootstrapDenyAll
	resp = injector(t, cfg).Handle(ctx, podRequest(t, traefik))
	if !strings.Contains(patched(resp), "--bootstrap=deny") {
		t.Error("InkwallConfig's bootstrap mode not used")
	}
}
