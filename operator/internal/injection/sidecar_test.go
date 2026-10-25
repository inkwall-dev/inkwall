// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package injection

import (
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func traefikPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "traefik-1", Labels: map[string]string{"app.kubernetes.io/name": "traefik"}},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "setup"}},
			Containers:     []corev1.Container{{Name: "traefik"}},
			Volumes:        []corev1.Volume{{Name: "data"}},
		},
	}
}

var sidecar = Sidecar{
	Image:        "inkwall-engine:dev",
	PullPolicy:   corev1.PullNever,
	OperatorAddr: "inkwall-operator.inkwall-system.svc:9445",
	BundleSecret: "inkwall-system/inkwall-bundle",
	Args:         []string{"forward-auth"},
}

func TestInject(t *testing.T) {
	pod := traefikPod()
	if !Inject(pod, sidecar) {
		t.Fatal("not injected")
	}
	// A native sidecar, first, so it is up before the proxy and the other
	// init containers.
	engine := pod.Spec.InitContainers[0]
	if engine.Name != ContainerName || engine.RestartPolicy == nil || *engine.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("not a native sidecar first: %+v", engine)
	}
	if pod.Spec.InitContainers[1].Name != "setup" || pod.Spec.Containers[0].Name != "traefik" {
		t.Fatal("the pod's own containers moved")
	}
	if engine.Image != "inkwall-engine:dev" || engine.ImagePullPolicy != corev1.PullNever {
		t.Errorf("image %s %s", engine.Image, engine.ImagePullPolicy)
	}
	for _, want := range []string{
		"forward-auth",
		"--operator=inkwall-operator.inkwall-system.svc:9445",
		"--operator-token=/var/run/secrets/inkwall/token",
		"--operator-ca=/var/run/secrets/inkwall/ca.crt",
		"--bundle-key=/var/run/secrets/inkwall/ed25519.pub",
		"--bundle-cache=/var/run/inkwall/bundle.pb",
		"--trusted-proxies=127.0.0.1/32,::1/128",
		"--bundle-secret=inkwall-system/inkwall-bundle",
		"--kube-token=/var/run/secrets/inkwall/kube-token",
		"--kube-ca=/var/run/secrets/inkwall/kube-ca.crt",
	} {
		if !slices.Contains(engine.Args, want) {
			t.Errorf("args %v lack %s", engine.Args, want)
		}
	}
	if slices.Contains(engine.Args, "--bootstrap=deny") {
		t.Error("bootstrap deny by default")
	}
	if engine.Args[0] != "forward-auth" {
		t.Errorf("the adapter must come first: %v", engine.Args)
	}
	sc := engine.SecurityContext
	if !*sc.RunAsNonRoot || !*sc.ReadOnlyRootFilesystem || *sc.AllowPrivilegeEscalation || sc.Capabilities.Drop[0] != "ALL" {
		t.Errorf("security context %+v", sc)
	}
	if engine.StartupProbe == nil || engine.Resources.Limits.Memory().Cmp(resource.MustParse("512Mi")) != 0 {
		t.Errorf("probes or default resources missing")
	}

	// The token for the operator's audience and the trust ConfigMap, then a
	// token for the API server and its CA (for the bundle Secret), in one
	// read-only directory.
	var secrets *corev1.Volume
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == secretsVolume {
			secrets = &pod.Spec.Volumes[i]
		}
	}
	if secrets == nil || secrets.Projected == nil || len(secrets.Projected.Sources) != 4 {
		t.Fatalf("secrets volume %+v", secrets)
	}
	src := secrets.Projected.Sources
	if src[0].ServiceAccountToken.Audience != "inkwall-operator" || src[1].ConfigMap.Name != TrustConfigMap ||
		src[2].ServiceAccountToken.Audience != "" || src[2].ServiceAccountToken.Path != "kube-token" ||
		src[3].ConfigMap.Name != "kube-root-ca.crt" || src[3].ConfigMap.Items[0].Path != "kube-ca.crt" {
		t.Fatalf("secrets volume sources %+v", src)
	}
	if len(pod.Spec.Volumes) != 4 || pod.Annotations[InjectedAnnotation] != "true" {
		t.Errorf("volumes %d, annotations %v", len(pod.Spec.Volumes), pod.Annotations)
	}

	// Bootstrap deny.
	deny := traefikPod()
	s := sidecar
	s.DenyBeforeBundle = true
	Inject(deny, s)
	if !slices.Contains(deny.Spec.InitContainers[0].Args, "--bootstrap=deny") {
		t.Error("bootstrap deny not passed")
	}

	// Injecting again changes nothing.
	before := pod.DeepCopy()
	if Inject(pod, sidecar) || len(pod.Spec.InitContainers) != len(before.Spec.InitContainers) {
		t.Fatal("injected twice")
	}
}

func TestInjectOptOutAndResources(t *testing.T) {
	pod := traefikPod()
	pod.Annotations = map[string]string{InjectAnnotation: "false"}
	if Inject(pod, sidecar) {
		t.Fatal("injected a pod that opted out")
	}
	// The label too (the webhook doesn't see such pods; a pod created
	// while it was off may still carry it).
	pod = traefikPod()
	pod.Labels[InjectLabel] = "false"
	if Inject(pod, sidecar) || !OptedOut(pod) {
		t.Fatal("injected a pod labeled to opt out")
	}
	// A pod that already has an engine container (e.g. hand-made).
	pod = traefikPod()
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: ContainerName})
	if Inject(pod, sidecar) {
		t.Fatal("injected a pod with an engine")
	}
	s := sidecar
	s.Resources = &corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")}}
	pod = traefikPod()
	Inject(pod, s)
	if pod.Spec.InitContainers[0].Resources.Limits.Memory().Cmp(resource.MustParse("1Gi")) != 0 {
		t.Error("resources not applied")
	}
}
