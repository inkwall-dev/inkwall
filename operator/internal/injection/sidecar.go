// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package injection gets the engine into a proxy's pods (0004 §4.3): a Pod
// webhook adds it as a native sidecar, and a controller provides what the
// sidecar needs in the pod's namespace (the trust ConfigMap) and in the
// operator's (read access to the bundle Secret).
package injection

import (
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	"github.com/inkwall-dev/inkwall/internal/memlimit"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
)

// Names in the pods the engine is injected into.
const (
	ContainerName = "inkwall-engine"
	// TrustConfigMap holds the operator's CA (ca.crt) and the bundle public
	// keys in the pod's namespace: trusted-keys.pub, every key the engine
	// accepts, and ed25519.pub, the active one. All are public. The kubelet
	// updates the mounted files when it changes, and the engine reloads
	// the keys.
	TrustConfigMap = "inkwall-trust"

	secretsVolume = "inkwall-secrets"
	cacheVolume   = "inkwall-cache"
	tmpVolume     = "inkwall-tmp"
	secretsDir    = "/var/run/secrets/inkwall" // #nosec G101 -- a mount path, not a credential
	cacheDir      = "/var/run/inkwall"
	// SocketVolume shares the engine's Unix socket with the proxy
	// (Sidecar.SocketDir).
	SocketVolume = "inkwall-socket"

	// InjectedAnnotation marks a pod the engine was injected into.
	InjectedAnnotation = "waf.inkwall.dev/injected"
	// InjectAnnotation set to "false" on a pod keeps the engine out. As a
	// label (InjectLabel), the Pod webhook isn't even called: the pod
	// starts while the operator is down, when the webhook fails closed.
	InjectAnnotation = "waf.inkwall.dev/inject"
	InjectLabel      = InjectAnnotation

	adminPort = 9480
)

// Sidecar configures the injected engine.
type Sidecar struct {
	Image      string
	PullPolicy corev1.PullPolicy
	// Resources of the engine; empty: the defaults below.
	Resources *corev1.ResourceRequirements
	// OperatorAddr is the distribution server, host:port.
	OperatorAddr string
	// BundleSecret is the bundle Secret, namespace/name, that a new engine
	// reads when the operator is unreachable.
	BundleSecret string
	// TrustedProxies and TrustedHops are the InkwallConfig's
	// spec.engine.clientIP, besides the loopback.
	TrustedProxies []string
	TrustedHops    int
	// DenyBeforeBundle rejects requests until the engine has a bundle.
	DenyBeforeBundle bool
	// LogLevel is the engine's --log-level, empty for its default.
	LogLevel string
	// Args are the adapter's command and its own flags, e.g.
	// ["forward-auth"].
	Args []string
	// SocketDir, when set, is an emptyDir (SocketVolume) mounted in the
	// engine, for a Unix socket the proxy mounts too.
	SocketDir string
	// SocketContainer, with SocketDir, is the proxy's container Inject
	// mounts SocketDir in (istio-proxy).
	SocketContainer string
	// PodAnnotations are set on the pod Inject injects.
	PodAnnotations map[string]string
}

func defaultResources() corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
		// No CPU limit: throttling shows up as tail latency on every
		// request. Memory grows with the number of distinct rule sets:
		// about 20 MiB for the first CRS and 2.1 MiB for each further one.
		// Paranoia levels, thresholds, body limits and exclusions don't
		// make one of their own (1,000 policies over 4 levels and 10 body
		// limits: one rule set, 20 MiB of heap).
		Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("512Mi")},
	}
}

// Configured returns s with an InkwallConfig's engine settings.
func (s Sidecar) Configured(e wafv1alpha1.EngineSpec) Sidecar {
	if e.Image != "" {
		s.Image = e.Image
	}
	s.Resources = e.Resources
	s.DenyBeforeBundle = e.BootstrapMode == wafv1alpha1.BootstrapDenyAll
	s.LogLevel = strings.ToLower(string(e.LogLevel))
	s.TrustedProxies, s.TrustedHops = nil, 0
	if c := e.ClientIP; c != nil {
		for _, p := range c.TrustedProxies {
			s.TrustedProxies = append(s.TrustedProxies, string(p))
		}
		if c.TrustedHops != nil {
			s.TrustedHops = int(*c.TrustedHops)
		}
	}
	return s
}

// HasEngine reports whether pod has the engine container.
func HasEngine(pod *corev1.Pod) bool {
	for _, c := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		if c.Name == ContainerName {
			return true
		}
	}
	return false
}

// HasSocket reports whether pod's container mounts the engine's socket
// directory, as Inject mounts it in a SocketContainer.
func HasSocket(pod *corev1.Pod, container string) bool {
	for _, c := range pod.Spec.Containers {
		if c.Name == container {
			return slices.ContainsFunc(c.VolumeMounts, func(m corev1.VolumeMount) bool { return m.Name == SocketVolume })
		}
	}
	return false
}

// MountSocket mounts the engine's socket directory in s.SocketContainer, if
// pod has that container and it doesn't mount it yet. It reports whether it
// changed pod: another webhook (Istio's injector) may rewrite the container
// after Inject.
func MountSocket(pod *corev1.Pod, s Sidecar) bool {
	if s.SocketDir == "" || s.SocketContainer == "" || !HasEngine(pod) || HasSocket(pod, s.SocketContainer) {
		return false
	}
	changed := false
	for i := range pod.Spec.Containers {
		if c := &pod.Spec.Containers[i]; c.Name == s.SocketContainer {
			c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: SocketVolume, MountPath: s.SocketDir})
			changed = true
		}
	}
	return changed
}

// Inject adds the engine to pod as a native sidecar (an init container
// with restartPolicy Always, so it starts before the proxy and stops after
// it), and the volumes it needs, and mounts the socket's directory in the
// SocketContainer. It reports false, changing nothing, for a pod that
// already has the engine or opted out.
func Inject(pod *corev1.Pod, s Sidecar) bool {
	if OptedOut(pod) || pod.Annotations[InjectedAnnotation] == "true" {
		return false
	}
	for _, c := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		if c.Name == ContainerName {
			return false
		}
	}

	engine, volumes := Engine(s)
	// First, so the engine is up before the proxy and any other init
	// container that needs traffic inspected.
	pod.Spec.InitContainers = append([]corev1.Container{engine}, pod.Spec.InitContainers...)
	pod.Spec.Volumes = append(pod.Spec.Volumes, volumes...)
	MountSocket(pod, s)
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[InjectedAnnotation] = "true"
	for k, v := range s.PodAnnotations {
		pod.Annotations[k] = v
	}
	return true
}

// Engine returns the engine container, a native sidecar (an init container
// with restartPolicy Always), and the volumes it needs: what Inject adds to
// a pod, and what a proxy with its own pod template takes (Envoy Gateway's
// EnvoyProxy).
func Engine(s Sidecar) (corev1.Container, []corev1.Volume) {
	args := append(slices.Clone(s.Args),
		"--operator="+s.OperatorAddr,
		"--operator-ca="+secretsDir+"/ca.crt",
		"--operator-token="+secretsDir+"/token",
		"--bundle-key="+secretsDir+"/trusted-keys.pub",
		"--bundle-cache="+cacheDir+"/bundle.pb",
		fmt.Sprintf("--admin-listen=:%d", adminPort),
		// The proxy is the engine's peer, on the loopback; its
		// X-Forwarded-For carries the client, after the load balancers'
		// entries the InkwallConfig trusts.
		"--trusted-proxies="+strings.Join(append([]string{"127.0.0.1/32", "::1/128"}, s.TrustedProxies...), ","),
	)
	if s.TrustedHops > 0 {
		args = append(args, fmt.Sprintf("--trusted-hops=%d", s.TrustedHops))
	}
	if s.BundleSecret != "" {
		args = append(args,
			"--bundle-secret="+s.BundleSecret,
			"--kube-token="+secretsDir+"/kube-token",
			"--kube-ca="+secretsDir+"/kube-ca.crt",
		)
	}
	if s.DenyBeforeBundle {
		args = append(args, "--bootstrap=deny")
	}
	if s.LogLevel != "" {
		args = append(args, "--log-level="+s.LogLevel)
	}

	resources := defaultResources()
	if s.Resources != nil {
		resources = *s.Resources
	}
	probe := func(path string) *corev1.Probe {
		return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
			Path: path, Port: intstr.FromInt32(adminPort),
		}}}
	}
	startup := probe("/readyz")
	startup.PeriodSeconds, startup.FailureThreshold = 1, 30
	engine := corev1.Container{
		Name:            ContainerName,
		Image:           s.Image,
		ImagePullPolicy: s.PullPolicy,
		Args:            args,
		Env: []corev1.EnvVar{
			fieldEnv("POD_NAME", "metadata.name"),
			fieldEnv("POD_NAMESPACE", "metadata.namespace"),
			fieldEnv("NODE_NAME", "spec.nodeName"),
			// The engine sets GOMEMLIMIT to 90% of it, unless GOMEMLIMIT
			// is set.
			{Name: memlimit.Env, ValueFrom: &corev1.EnvVarSource{ResourceFieldRef: &corev1.ResourceFieldSelector{
				ContainerName: ContainerName, Resource: "limits.memory"}}},
		},
		Ports: []corev1.ContainerPort{{Name: "inkwall-admin", ContainerPort: adminPort}},
		// The proxy starts once the engine is up.
		StartupProbe:   startup,
		ReadinessProbe: probe("/readyz"),
		LivenessProbe:  probe("/healthz"),
		Resources:      resources,
		SecurityContext: &corev1.SecurityContext{
			RunAsNonRoot:             ptr.To(true),
			ReadOnlyRootFilesystem:   ptr.To(true),
			AllowPrivilegeEscalation: ptr.To(false),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: secretsVolume, MountPath: secretsDir, ReadOnly: true},
			{Name: cacheVolume, MountPath: cacheDir},
			// Coraza checks at startup that it can create files in /tmp.
			{Name: tmpVolume, MountPath: "/tmp"},
		},
		RestartPolicy: ptr.To(corev1.ContainerRestartPolicyAlways),
	}
	volumes := []corev1.Volume{
		{Name: secretsVolume, VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
			Sources: []corev1.VolumeProjection{
				{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
					Audience: distribution.Audience, ExpirationSeconds: ptr.To(int64(3600)), Path: "token",
				}},
				{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: TrustConfigMap}}},
				// For the bundle Secret: a token for the API server's own
				// audience, and its CA (kube-root-ca.crt is in every
				// namespace). The proxy's own token mount, if any, isn't
				// the engine's: webhooks run after the ServiceAccount
				// admission plugin mounts it.
				{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
					ExpirationSeconds: ptr.To(int64(3600)), Path: "kube-token",
				}},
				{ConfigMap: &corev1.ConfigMapProjection{
					LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"},
					Items:                []corev1.KeyToPath{{Key: "ca.crt", Path: "kube-ca.crt"}},
				}},
			},
		}}},
		{Name: cacheVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: tmpVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{
			SizeLimit: ptr.To(resource.MustParse("16Mi")),
		}}},
	}
	if s.SocketDir != "" {
		engine.VolumeMounts = append(engine.VolumeMounts, corev1.VolumeMount{Name: SocketVolume, MountPath: s.SocketDir})
		volumes = append(volumes, corev1.Volume{Name: SocketVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
	}
	return engine, volumes
}

// OptedOut reports whether pod keeps the engine out, with the annotation
// or the label.
func OptedOut(pod *corev1.Pod) bool {
	return pod.Annotations[InjectAnnotation] == "false" || pod.Labels[InjectLabel] == "false"
}

func fieldEnv(name, path string) corev1.EnvVar {
	return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: path}}}
}
