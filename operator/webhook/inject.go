// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"encoding/json"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// MutatingConfigName is the MutatingWebhookConfiguration of the Pod
// webhook; the certificate rotator injects its CA bundle.
const MutatingConfigName = "inkwall-operator-mutating"

// InjectPath is the Pod webhook's path.
const InjectPath = "/mutate-v1-pod"

// PodWebhookName is the Pod webhook in MutatingConfigName, for Traefik's
// pods; HAProxyPodWebhookName, the same handler for the HAProxy
// Kubernetes Ingress Controller's, and IstioIngressPodWebhookName for
// Istio's ingress gateways' (a webhook has one objectSelector). Istio's
// own injector rewrites its pods too: that webhook is called again
// (reinvocationPolicy IfNeeded) to mount the engine's socket in
// istio-proxy if that mount was lost.
const (
	PodWebhookName             = "pods.waf.inkwall.dev"
	HAProxyPodWebhookName      = "haproxy.pods.waf.inkwall.dev"
	IstioIngressPodWebhookName = "istio-ingress.pods.waf.inkwall.dev"
)

// PodWebhooks are the Pod webhooks, each with its integration.
var PodWebhooks = map[string]string{
	PodWebhookName:             integrations.Traefik.Name,
	HAProxyPodWebhookName:      integrations.HAProxy.Name,
	IstioIngressPodWebhookName: integrations.IstioIngress.Name,
}

// The Pod webhooks only see pods of known proxies (objectSelector), at
// creation. They are installed failing open (Ignore): a proxy pod starts even
// when the operator is down, runs without the engine and is reported until
// restarted. The operator switches it to Fail while a policy is in block
// mode (injection.FailurePolicyReconciler). A pod labeled
// waf.inkwall.dev/inject: "false" is never sent to it, so it starts even
// then: the way out when the operator is down and the proxy must scale.
//
// +kubebuilder:webhookconfiguration:mutating=true,name=inkwall-operator-mutating
// +kubebuilder:webhook:path=/mutate-v1-pod,mutating=true,failurePolicy=ignore,sideEffects=None,groups="",resources=pods,verbs=create,versions=v1,name=pods.waf.inkwall.dev,admissionReviewVersions=v1,timeoutSeconds=2,reinvocationPolicy=Never,patch=`{"objectSelector":{"matchLabels":{"app.kubernetes.io/name":"traefik"},"matchExpressions":[{"key":"waf.inkwall.dev/inject","operator":"NotIn","values":["false"]}]}}`
// +kubebuilder:webhook:path=/mutate-v1-pod,mutating=true,failurePolicy=ignore,sideEffects=None,groups="",resources=pods,verbs=create,versions=v1,name=haproxy.pods.waf.inkwall.dev,admissionReviewVersions=v1,timeoutSeconds=2,reinvocationPolicy=Never,patch=`{"objectSelector":{"matchLabels":{"app.kubernetes.io/name":"kubernetes-ingress"},"matchExpressions":[{"key":"waf.inkwall.dev/inject","operator":"NotIn","values":["false"]}]}}`
// +kubebuilder:webhook:path=/mutate-v1-pod,mutating=true,failurePolicy=ignore,sideEffects=None,groups="",resources=pods,verbs=create,versions=v1,name=istio-ingress.pods.waf.inkwall.dev,admissionReviewVersions=v1,timeoutSeconds=2,reinvocationPolicy=IfNeeded,patch=`{"objectSelector":{"matchLabels":{"istio":"ingressgateway"},"matchExpressions":[{"key":"waf.inkwall.dev/inject","operator":"NotIn","values":["false"]}]}}`

// PodInjector adds the engine to proxy pods.
type PodInjector struct {
	// Client reads the InkwallConfig.
	Client client.Reader
	// Decoder decodes pods.
	Decoder admission.Decoder
	// Image and PullPolicy are the engine's, unless InkwallConfig sets one.
	Image      string
	PullPolicy corev1.PullPolicy
	// PullSecrets are added to the pod's imagePullSecrets.
	PullSecrets []string
	// OperatorAddr is the distribution server engines connect to.
	OperatorAddr string
	// Integrations recognise proxy pods; nil: the defaults.
	Integrations *integrations.Selectors
	// Namespaces are the proxy namespaces: a pod elsewhere isn't a proxy
	// pod, whatever its labels (the webhook's namespaceSelector leaves it
	// out already).
	Namespaces integrations.Namespaces
	// Disabled are the integrations the operator may not wire, by name
	// (0004 §7): their pods don't get the engine.
	Disabled map[string]string
	// BundleSecret is the bundle Secret, namespace/name, engines read when
	// the operator is unreachable.
	BundleSecret string
}

var _ admission.Handler = (*PodInjector)(nil)

// Handle injects the engine into a pod of a known proxy.
func (p *PodInjector) Handle(ctx context.Context, req admission.Request) admission.Response {
	var pod corev1.Pod
	if err := p.Decoder.Decode(req, &pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	integ := p.Integrations.ForPod(pod.Labels)
	if integ == nil || !p.Namespaces.Has(req.Namespace) {
		return admission.Allowed("not a proxy pod")
	}
	if p.Disabled[integ.Name] != "" {
		return admission.Allowed("the " + integ.Name + " integration is disabled")
	}
	s := injection.Sidecar{Image: p.Image, PullPolicy: p.PullPolicy, PullSecrets: p.PullSecrets, OperatorAddr: p.OperatorAddr, BundleSecret: p.BundleSecret, Args: integ.Adapter}
	haproxy := integ.Name == integrations.HAProxy.Name
	if haproxy {
		// HAProxy sends the engine the responses of the backends whose
		// policies inspect them (spoe.conf's inkwall-responses scope).
		s.SocketDir, s.ResponseMessages = integrations.HAProxySocketDir, true
	}
	if integ.SocketContainer != "" {
		s.SocketDir, s.SocketContainer = integrations.EnvoySocketDir, integ.SocketContainer
	}
	s.PodAnnotations = integ.PodAnnotations
	var cfg wafv1alpha1.InkwallConfig
	switch err := p.Client.Get(ctx, types.NamespacedName{Name: "default"}, &cfg); {
	case err == nil:
		s = s.Configured(cfg.Spec.Engine)
		if left := s.LeftOut(); len(left) > 0 {
			// The InkwallConfig's EngineConfigured condition says so too.
			log.FromContext(ctx).Info("injecting the pinned engine without settings its version may not know", "image", s.Image, "settings", left)
		}
	case !apierrors.IsNotFound(err):
		// The pod still gets the engine, with the operator's defaults:
		// better than none, and the webhook may be failing closed.
		log.FromContext(ctx).Error(err, "reading the InkwallConfig; injecting the engine with the defaults", "namespace", req.Namespace)
	}
	mutated := pod.DeepCopy()
	if !injection.Inject(mutated, s) && !injection.MountSocket(mutated, s) {
		return admission.Allowed("already injected, or opted out")
	}
	if haproxy {
		injection.InjectHAProxy(mutated)
	}
	raw, err := json.Marshal(mutated)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	log.FromContext(ctx).Info("engine injected", "integration", integ.Name, "namespace", req.Namespace, "pod", pod.GenerateName+pod.Name)
	return admission.PatchResponseFromRaw(req.Object.Raw, raw)
}
