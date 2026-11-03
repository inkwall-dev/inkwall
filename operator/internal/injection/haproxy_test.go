// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package injection

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	"github.com/inkwall-dev/inkwall/operator/integrations"
)

func haproxyPod(sc *corev1.SecurityContext, mounts ...corev1.VolumeMount) *corev1.Pod {
	return &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{
		{Name: HAProxyContainer, Image: "haproxytech/kubernetes-ingress:3.2.19", SecurityContext: sc, VolumeMounts: mounts},
	}}}
}

func mountPaths(c corev1.Container) []string {
	var out []string
	for _, m := range c.VolumeMounts {
		out = append(out, m.MountPath)
	}
	return out
}

// The controller's container gets the engine's socket and the agent's
// configuration; the engine runs as HAProxy's user.
func TestInjectHAProxy(t *testing.T) {
	pod := haproxyPod(&corev1.SecurityContext{RunAsUser: ptr.To(int64(1000)), RunAsGroup: ptr.To(int64(1000))})
	if !Inject(pod, Sidecar{Image: "engine", Args: integrations.HAProxy.Adapter, SocketDir: integrations.HAProxySocketDir}) {
		t.Fatal("not injected")
	}
	InjectHAProxy(pod)
	got := mountPaths(pod.Spec.Containers[0])
	for _, want := range []string{integrations.HAProxySocketDir, HAProxyAuxPath, HAProxyConfDir} {
		if !slices.Contains(got, want) {
			t.Errorf("HAProxy's mounts %v lack %s", got, want)
		}
	}
	if !slices.Contains(mountPaths(pod.Spec.InitContainers[0]), integrations.HAProxySocketDir) {
		t.Error("the engine doesn't mount the socket directory")
	}
	if !slices.ContainsFunc(pod.Spec.Volumes, func(v corev1.Volume) bool {
		return v.ConfigMap != nil && v.ConfigMap.Name == HAProxyConfigMap
	}) {
		t.Error("no volume for the agent's configuration")
	}
	e := pod.Spec.InitContainers[0].SecurityContext
	if e.RunAsUser == nil || *e.RunAsUser != 1000 || e.RunAsGroup == nil || *e.RunAsGroup != 1000 {
		t.Errorf("engine security context %+v, want HAProxy's user", e)
	}
	if ok, why := HAProxyConfigured(pod); !ok {
		t.Errorf("not configured: %s", why)
	}

	// The pod's own user covers both: the engine keeps its settings.
	pod = haproxyPod(nil)
	Inject(pod, Sidecar{Image: "engine", SocketDir: integrations.HAProxySocketDir})
	InjectHAProxy(pod)
	if pod.Spec.InitContainers[0].SecurityContext.RunAsUser != nil {
		t.Error("the engine's user set without HAProxy's")
	}

	// The container mounts its own auxiliary file: kept, and reported.
	pod = haproxyPod(nil, corev1.VolumeMount{Name: "mine", MountPath: HAProxyAuxPath, SubPath: "aux"})
	Inject(pod, Sidecar{Image: "engine", SocketDir: integrations.HAProxySocketDir})
	InjectHAProxy(pod)
	if n := len(slices.DeleteFunc(mountPaths(pod.Spec.Containers[0]), func(p string) bool { return p != HAProxyAuxPath })); n != 1 {
		t.Errorf("%d mounts at %s", n, HAProxyAuxPath)
	}
	if ok, why := HAProxyConfigured(pod); ok || !strings.Contains(why, "its own") {
		t.Errorf("configured %v: %s", ok, why)
	}
}

// The agent's files name the socket the engine listens on, the message the
// SPOE adapter reads, and the backend event.
func TestHAProxyFiles(t *testing.T) {
	f := HAProxyFiles()
	if !strings.Contains(strings.Join(integrations.HAProxy.Adapter, " "), "unix:"+haproxySocket) ||
		!strings.Contains(f[HAProxyAuxKey], "unix@"+haproxySocket) {
		t.Error("the engine's socket and the agent's backend differ")
	}
	for _, want := range []string{"messages inkwall-request", "event on-backend-http-request", "use-backend inkwall-engine", " probe"} {
		if !strings.Contains(f[HAProxySPOEKey], want) {
			t.Errorf("spoe.conf lacks %q", want)
		}
	}
}
