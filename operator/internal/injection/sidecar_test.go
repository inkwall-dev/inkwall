// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package injection

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
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
		"--bundle-key=/var/run/secrets/inkwall/trusted-keys.pub",
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
	if engine.Resources.Limits.Memory().Cmp(resource.MustParse("512Mi")) != 0 {
		t.Errorf("default resources missing")
	}
	// The proxy starts once the engine is ready: its first bundle applied,
	// or the engine's --bootstrap-timeout (10s) passed, so the proxy takes
	// no traffic before the policy is in place. The startup probe allows
	// for that timeout, with margin for compiling the rules; liveness only
	// asks whether the process is alive, so waiting for a bundle never
	// restarts the engine.
	probePath := func(p *corev1.Probe) string {
		if p == nil || p.HTTPGet == nil || p.HTTPGet.Port.IntValue() != adminPort {
			return ""
		}
		return p.HTTPGet.Path
	}
	if got := probePath(engine.StartupProbe); got != "/readyz" {
		t.Errorf("startup probe %q, want /readyz on the admin port", got)
	}
	if sp := engine.StartupProbe; sp != nil && sp.PeriodSeconds*sp.FailureThreshold < 20 {
		t.Errorf("startup probe gives up after %ds, within the bootstrap timeout plus margin", sp.PeriodSeconds*sp.FailureThreshold)
	}
	if got := probePath(engine.ReadinessProbe); got != "/readyz" {
		t.Errorf("readiness probe %q, want /readyz", got)
	}
	if got := probePath(engine.LivenessProbe); got != "/healthz" {
		t.Errorf("liveness probe %q, want /healthz", got)
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

	// The log level, only when set: pods injected before keep their spec.
	if slices.ContainsFunc(pod.Spec.InitContainers[0].Args, func(a string) bool { return strings.HasPrefix(a, "--log-level") }) {
		t.Error("--log-level passed without a log level")
	}
	quiet := traefikPod()
	Inject(quiet, sidecar.Configured(wafv1alpha1.EngineSpec{LogLevel: wafv1alpha1.LogLevelWarn}))
	if !slices.Contains(quiet.Spec.InitContainers[0].Args, "--log-level=warn") {
		t.Errorf("log level Warn: args %v", quiet.Spec.InitContainers[0].Args)
	}
	// JSON denials, only when asked for (#366).
	if slices.Contains(pod.Spec.InitContainers[0].Args, "--json-denials") {
		t.Error("--json-denials passed without jsonDenials")
	}
	jsonPod := traefikPod()
	Inject(jsonPod, sidecar.Configured(wafv1alpha1.EngineSpec{JSONDenials: true}))
	if !slices.Contains(jsonPod.Spec.InitContainers[0].Args, "--json-denials") {
		t.Errorf("jsonDenials: args %v", jsonPod.Spec.InitContainers[0].Args)
	}
	// Requests by policy, only when asked for (#356).
	if slices.Contains(pod.Spec.InitContainers[0].Args, "--policy-metrics") {
		t.Error("--policy-metrics passed without policyMetrics")
	}
	counted := traefikPod()
	Inject(counted, sidecar.Configured(wafv1alpha1.EngineSpec{PolicyMetrics: true}))
	if !slices.Contains(counted.Spec.InitContainers[0].Args, "--policy-metrics") {
		t.Errorf("policyMetrics: args %v", counted.Spec.InitContainers[0].Args)
	}

	// The InkwallConfig's client IP settings (#364): loopback stays trusted.
	lb := traefikPod()
	one := int32(1)
	s = sidecar.Configured(wafv1alpha1.EngineSpec{ClientIP: &wafv1alpha1.ClientIPSpec{
		TrustedProxies: []wafv1alpha1.CIDR{"10.0.0.0/8", "2001:db8::/32"}, TrustedHops: &one}})
	Inject(lb, s)
	if args := lb.Spec.InitContainers[0].Args; !slices.Contains(args, "--trusted-proxies=127.0.0.1/32,::1/128,10.0.0.0/8,2001:db8::/32") ||
		!slices.Contains(args, "--trusted-hops=1") || slices.Contains(args, "--trusted-proxies=127.0.0.1/32,::1/128") {
		t.Errorf("client IP settings not passed: %v", args)
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

// The engine gets its memory limit from the downward API, to set GOMEMLIMIT
// from it (internal/memlimit).
func TestEngineMemoryLimitEnv(t *testing.T) {
	c, _ := Engine(sidecar)
	i := slices.IndexFunc(c.Env, func(e corev1.EnvVar) bool { return e.Name == "MEMORY_LIMIT" })
	if i < 0 {
		t.Fatalf("no MEMORY_LIMIT in %v", c.Env)
	}
	var ref *corev1.ResourceFieldSelector
	if c.Env[i].ValueFrom != nil {
		ref = c.Env[i].ValueFrom.ResourceFieldRef
	}
	if ref == nil || ref.Resource != "limits.memory" || ref.ContainerName != ContainerName {
		t.Errorf("MEMORY_LIMIT from %v, want the engine container's limits.memory", c.Env[i].ValueFrom)
	}
}
