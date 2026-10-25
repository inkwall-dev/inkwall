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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
)

// Names in the pods the engine is injected into.
const (
	ContainerName = "inkwall-engine"
	// TrustConfigMap holds the operator's CA (ca.crt) and the bundle public
	// key (ed25519.pub) in the pod's namespace; both are public.
	TrustConfigMap = "inkwall-trust"

	secretsVolume = "inkwall-secrets"
	cacheVolume   = "inkwall-cache"
	tmpVolume     = "inkwall-tmp"
	secretsDir    = "/var/run/secrets/inkwall" // #nosec G101 -- a mount path, not a credential
	cacheDir      = "/var/run/inkwall"

	// InjectedAnnotation marks a pod the engine was injected into.
	InjectedAnnotation = "waf.inkwall.dev/injected"
	// InjectAnnotation set to "false" on a pod keeps the engine out.
	InjectAnnotation = "waf.inkwall.dev/inject"

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
	// DenyBeforeBundle rejects requests until the engine has a bundle.
	DenyBeforeBundle bool
	// Args are the adapter's command and its own flags, e.g.
	// ["forward-auth"].
	Args []string
}

func defaultResources() corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
		// No CPU limit: throttling shows up as tail latency on every
		// request. Memory grows with the number of distinct rule sets
		// (~4 MiB each).
		Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("512Mi")},
	}
}

// Inject adds the engine to pod as a native sidecar (an init container
// with restartPolicy Always, so it starts before the proxy and stops after
// it), and the volumes it needs. It reports false, changing nothing, for a
// pod that already has the engine or opted out.
func Inject(pod *corev1.Pod, s Sidecar) bool {
	if pod.Annotations[InjectAnnotation] == "false" || pod.Annotations[InjectedAnnotation] == "true" {
		return false
	}
	for _, c := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		if c.Name == ContainerName {
			return false
		}
	}

	args := append(slices.Clone(s.Args),
		"--operator="+s.OperatorAddr,
		"--operator-ca="+secretsDir+"/ca.crt",
		"--operator-token="+secretsDir+"/token",
		"--bundle-key="+secretsDir+"/ed25519.pub",
		"--bundle-cache="+cacheDir+"/bundle.pb",
		fmt.Sprintf("--admin-listen=:%d", adminPort),
		// The proxy is the engine's peer, on the loopback; its
		// X-Forwarded-For carries the client.
		"--trusted-proxies=127.0.0.1/32,::1/128",
	)
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
	// First, so the engine is up before the proxy and any other init
	// container that needs traffic inspected.
	pod.Spec.InitContainers = append([]corev1.Container{engine}, pod.Spec.InitContainers...)
	pod.Spec.Volumes = append(pod.Spec.Volumes,
		corev1.Volume{Name: secretsVolume, VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
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
		corev1.Volume{Name: cacheVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		corev1.Volume{Name: tmpVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{
			SizeLimit: ptr.To(resource.MustParse("16Mi")),
		}}},
	)
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[InjectedAnnotation] = "true"
	return true
}

func fieldEnv(name, path string) corev1.EnvVar {
	return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: path}}}
}
