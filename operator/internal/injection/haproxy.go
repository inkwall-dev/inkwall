// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package injection

import (
	"slices"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	"github.com/inkwall-dev/inkwall/operator/integrations"
)

// The HAProxy Kubernetes Ingress Controller's pods get, besides the engine,
// the SPOE agent's configuration (0002 §6.4): the agent's backend in the
// controller's auxiliary configuration file, which the controller loads
// after its own, and spoe.conf, which each protected Ingress's backend
// loads with its filter. Both come from HAProxyConfigMap, which the
// injection controller keeps in the pod's namespace.
const (
	// HAProxyConfigMap holds HAProxyAuxKey and HAProxySPOEKey.
	HAProxyConfigMap = "inkwall-haproxy"
	HAProxyAuxKey    = "haproxy-aux.cfg"
	HAProxySPOEKey   = "spoe.conf"
	// HAProxyAuxPath is where the controller looks for its auxiliary
	// configuration file.
	HAProxyAuxPath = "/usr/local/etc/haproxy/haproxy-aux.cfg"
	// HAProxyConfDir holds spoe.conf in the controller's container.
	HAProxyConfDir = "/usr/local/etc/inkwall"
	// HAProxySPOEConf is spoe.conf's path, which the filter names.
	HAProxySPOEConf = HAProxyConfDir + "/" + HAProxySPOEKey
	// HAProxyContainer is the controller's container in its Helm chart.
	HAProxyContainer = "kubernetes-ingress-controller"
	// HAProxyConfigAnnotation on an injected pod says whether its HAProxy
	// got the agent's configuration: "mounted", or why not.
	HAProxyConfigAnnotation = "waf.inkwall.dev/haproxy-config"
	// HAProxyConfigMounted is HAProxyConfigAnnotation's value when it did.
	HAProxyConfigMounted = "mounted"

	haproxyConfigVolume = "inkwall-haproxy"
	haproxySocket       = integrations.HAProxySocketDir + "/spoe.sock"
)

// ResponseMessagesFlag tells the engine of an HAProxy pod that HAProxy
// sends the responses of the requests whose policies inspect them (since
// 0.6.0): it keeps those requests for their responses.
const ResponseMessagesFlag = "--response-messages"

// HAProxyResponsesScope is spoe.conf's scope for the backends whose
// policies inspect responses: its request message tells the engine their
// responses follow, and its group sends them (0006 §4).
const HAProxyResponsesScope = "inkwall-responses"

// HAProxyResponseGroup is the SPOE group that sends a response.
const HAProxyResponseGroup = "inkwall-response"

// spoeScope is one scope of spoe.conf: the agent named name, whose request
// message says whether the request's response follows.
func spoeScope(name string, responses bool) string {
	vars := "action status request_id error grpc_status grpc_message grpc_content_type probe"
	groups, respond, group := "", "bool(0)", ""
	if responses {
		vars += " responses response_failure response_action response_status"
		groups, respond = "    groups "+HAProxyResponseGroup+"\n", "bool(1)"
		group = `
spoe-message inkwall-response
    args status=status headers=res.hdrs_bin body=res.body key=var(txn.inkwall.responses) failure=var(txn.inkwall.response_failure)

spoe-group ` + HAProxyResponseGroup + `
    messages inkwall-response
`
	}
	return `[` + name + `]
spoe-agent ` + name + `
    messages inkwall-request
` + groups + `    option var-prefix inkwall
    option set-on-error error
    timeout processing 1500ms
    use-backend inkwall-engine
    register-var-names ` + vars + `

spoe-message inkwall-request
    args method=method path=pathq version=req.ver headers=req.hdrs_bin body=req.body ip=src https=ssl_fc responses=` + respond + `
    event on-backend-http-request
` + group
}

// HAProxyFiles are HAProxyConfigMap's data: the agent's backend, on the
// engine's socket, with HELLO health checks (option spop-check), so a
// stopped engine is marked down at once; and the SPOE configuration, in
// two scopes: inkwall, for the backends whose policies don't inspect
// responses, and HAProxyResponsesScope, for those that do, which also
// sends the response (HAProxyResponseGroup) and registers its variables.
// Each sends the message the engine reads when a backend's http-request
// rules are about to run, telling it whether the response follows, so the
// engine keeps only the requests whose responses come. timeout processing
// is the largest inspection deadline (1s) plus 500ms: the engine decides a
// slow request itself, with its failure mode.
func HAProxyFiles() map[string]string {
	return map[string]string{
		HAProxyAuxKey: `# Managed by the Inkwall operator: the engine's SPOE agent (0002 §6.4).
defaults inkwall
    mode spop
    timeout connect 5s
    timeout server 3m

backend inkwall-engine from inkwall
    option spop-check
    server engine unix@` + haproxySocket + ` check inter 1s
`,
		HAProxySPOEKey: "# Managed by the Inkwall operator: the engine's SPOE agent (0002 §6.4).\n" +
			spoeScope("inkwall", false) + "\n" + spoeScope(HAProxyResponsesScope, true),
	}
}

// HAProxyResponsesReady reports whether an injected HAProxy controller
// pod's engine keeps requests for their responses (ResponseMessagesFlag),
// and if not, why. Pods injected before 0.6.0, or with a pinned engine
// that doesn't know the flag, don't: HAProxy mustn't send them responses.
func HAProxyResponsesReady(pod *corev1.Pod) (bool, string) {
	for _, c := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		if c.Name == ContainerName {
			if slices.Contains(c.Args, ResponseMessagesFlag) {
				return true, ""
			}
			break
		}
	}
	return false, "its engine runs without " + ResponseMessagesFlag
}

// InjectHAProxy gives an HAProxy controller pod, which Inject gave the
// engine, the engine's socket and the agent's configuration in its HAProxy
// container, and runs the engine as HAProxy's user when the container sets
// one, so HAProxy may connect to the socket. A pod whose container mounts
// its own auxiliary file keeps it: the agent's backend is then missing, and
// HAProxyConfigAnnotation says so.
func InjectHAProxy(pod *corev1.Pod) {
	i := slices.IndexFunc(pod.Spec.Containers, func(c corev1.Container) bool { return c.Name == HAProxyContainer })
	if i < 0 {
		i = 0
	}
	if len(pod.Spec.Containers) == 0 {
		return
	}
	c := &pod.Spec.Containers[i]
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: SocketVolume, MountPath: integrations.HAProxySocketDir})
	status := HAProxyConfigMounted
	if slices.ContainsFunc(c.VolumeMounts, func(m corev1.VolumeMount) bool {
		return m.MountPath == HAProxyAuxPath || m.MountPath == HAProxyConfDir
	}) {
		status = "the container mounts its own " + HAProxyAuxPath + " or " + HAProxyConfDir
	} else {
		c.VolumeMounts = append(c.VolumeMounts,
			corev1.VolumeMount{Name: haproxyConfigVolume, MountPath: HAProxyAuxPath, SubPath: HAProxyAuxKey, ReadOnly: true},
			corev1.VolumeMount{Name: haproxyConfigVolume, MountPath: HAProxyConfDir, ReadOnly: true},
		)
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: haproxyConfigVolume, VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: HAProxyConfigMap}},
		}})
	}
	pod.Annotations[HAProxyConfigAnnotation] = status

	// The engine creates its socket for its own user; HAProxy, as another
	// user, couldn't connect. The pod's runAsUser covers both containers.
	if sc := c.SecurityContext; sc != nil && sc.RunAsUser != nil && *sc.RunAsUser != 0 {
		for j := range pod.Spec.InitContainers {
			e := &pod.Spec.InitContainers[j]
			if e.Name != ContainerName {
				continue
			}
			if e.SecurityContext == nil {
				e.SecurityContext = &corev1.SecurityContext{}
			}
			e.SecurityContext.RunAsUser = ptr.To(*sc.RunAsUser)
			if sc.RunAsGroup != nil {
				e.SecurityContext.RunAsGroup = ptr.To(*sc.RunAsGroup)
			}
		}
	}
}

// HAProxyConfigured reports whether an injected HAProxy controller pod's
// HAProxy has the agent's configuration, and if not, why.
func HAProxyConfigured(pod *corev1.Pod) (bool, string) {
	switch v := pod.Annotations[HAProxyConfigAnnotation]; v {
	case HAProxyConfigMounted:
		return true, ""
	case "":
		return false, "it has no configuration for the engine's SPOE agent (injected by an operator before HAProxy support?)"
	default:
		return false, v
	}
}
