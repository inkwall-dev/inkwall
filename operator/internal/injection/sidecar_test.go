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
	} {
		if !slices.Contains(engine.Args, want) {
			t.Errorf("args %v lack %s", engine.Args, want)
		}
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

	// The token for the operator's audience and the trust ConfigMap, in one
	// read-only directory.
	var secrets *corev1.Volume
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == secretsVolume {
			secrets = &pod.Spec.Volumes[i]
		}
	}
	if secrets == nil || secrets.Projected == nil || len(secrets.Projected.Sources) != 2 ||
		secrets.Projected.Sources[0].ServiceAccountToken.Audience != "inkwall-operator" ||
		secrets.Projected.Sources[1].ConfigMap.Name != TrustConfigMap {
		t.Fatalf("secrets volume %+v", secrets)
	}
	if len(pod.Spec.Volumes) != 4 || pod.Annotations[InjectedAnnotation] != "true" {
		t.Errorf("volumes %d, annotations %v", len(pod.Spec.Volumes), pod.Annotations)
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
