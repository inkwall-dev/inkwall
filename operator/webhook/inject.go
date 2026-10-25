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

// The Pod webhook only sees pods of known proxies (objectSelector), at
// creation. It fails open: a proxy pod must start even when the operator is
// down; it then runs without the engine and is reported until restarted.
//
// +kubebuilder:webhookconfiguration:mutating=true,name=inkwall-operator-mutating
// +kubebuilder:webhook:path=/mutate-v1-pod,mutating=true,failurePolicy=ignore,sideEffects=None,groups="",resources=pods,verbs=create,versions=v1,name=pods.waf.inkwall.dev,admissionReviewVersions=v1,timeoutSeconds=2,reinvocationPolicy=Never,patch=`{"objectSelector":{"matchLabels":{"app.kubernetes.io/name":"traefik"}}}`

// PodInjector adds the engine to proxy pods.
type PodInjector struct {
	// Client reads the InkwallConfig.
	Client client.Reader
	// Decoder decodes pods.
	Decoder admission.Decoder
	// Image and PullPolicy are the engine's, unless InkwallConfig sets one.
	Image      string
	PullPolicy corev1.PullPolicy
	// OperatorAddr is the distribution server engines connect to.
	OperatorAddr string
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
	integ := integrations.ForPod(pod.Labels)
	if integ == nil {
		return admission.Allowed("not a proxy pod")
	}
	s := injection.Sidecar{Image: p.Image, PullPolicy: p.PullPolicy, OperatorAddr: p.OperatorAddr, BundleSecret: p.BundleSecret, Args: integ.Adapter}
	var cfg wafv1alpha1.InkwallConfig
	switch err := p.Client.Get(ctx, types.NamespacedName{Name: "default"}, &cfg); {
	case err == nil:
		if cfg.Spec.Engine.Image != "" {
			s.Image = cfg.Spec.Engine.Image
		}
		s.Resources = cfg.Spec.Engine.Resources
		s.DenyBeforeBundle = cfg.Spec.Engine.BootstrapMode == wafv1alpha1.BootstrapDenyAll
	case !apierrors.IsNotFound(err):
		// Fail open, as the webhook does: the pod starts without the engine.
		log.FromContext(ctx).Error(err, "reading the InkwallConfig; the pod starts without the engine", "namespace", req.Namespace)
		return admission.Allowed("InkwallConfig unreadable")
	}
	mutated := pod.DeepCopy()
	if !injection.Inject(mutated, s) {
		return admission.Allowed("already injected, or opted out")
	}
	raw, err := json.Marshal(mutated)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	log.FromContext(ctx).Info("engine injected", "integration", integ.Name, "namespace", req.Namespace, "pod", pod.GenerateName+pod.Name)
	return admission.PatchResponseFromRaw(req.Object.Raw, raw)
}
