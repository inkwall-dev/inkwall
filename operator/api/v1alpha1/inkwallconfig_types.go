// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterMode is where a cluster's policy comes from (0002 §4.1).
// +kubebuilder:validation:Enum=Standalone;GitOps;Managed
type ClusterMode string

const (
	// ModeStandalone takes policy from the CRDs, with no control plane.
	ModeStandalone ClusterMode = "Standalone"
	// ModeGitOps takes policy from the CRDs and mirrors it, read-only, to
	// the control plane.
	ModeGitOps ClusterMode = "GitOps"
	// ModeManaged takes policy from the control plane, which the operator
	// writes as CRDs; edits by anyone else are rejected.
	ModeManaged ClusterMode = "Managed"
)

// AdapterKind is how a proxy hands requests to the engine (0006).
// +kubebuilder:validation:Enum=ExtProc;ExtAuthz;LuaPlugin;AuthURL;ForwardAuth;SPOE;Module
type AdapterKind string

// The adapter kinds.
const (
	AdapterExtProc     AdapterKind = "ExtProc"
	AdapterExtAuthz    AdapterKind = "ExtAuthz"
	AdapterLuaPlugin   AdapterKind = "LuaPlugin"
	AdapterAuthURL     AdapterKind = "AuthURL"
	AdapterForwardAuth AdapterKind = "ForwardAuth"
	AdapterSPOE        AdapterKind = "SPOE"
	AdapterModule      AdapterKind = "Module"
)

// BootstrapMode is what an engine does with requests before it has a policy
// bundle (0004 §4.6).
// +kubebuilder:validation:Enum=AllowAll;DenyAll
type BootstrapMode string

// The bootstrap modes.
const (
	// BootstrapAllowAll lets requests through uninspected: availability
	// first.
	BootstrapAllowAll BootstrapMode = "AllowAll"
	// BootstrapDenyAll rejects them with 503.
	BootstrapDenyAll BootstrapMode = "DenyAll"
)

// InkwallConfigSpec is the cluster-wide configuration.
// +kubebuilder:validation:XValidation:rule="!has(self.mode) || self.mode == 'Standalone' || has(self.controlPlane)",message="controlPlane is required in GitOps and Managed mode"
type InkwallConfigSpec struct {
	// Mode is where policy comes from: Standalone (the CRDs), GitOps (the
	// CRDs, mirrored to the control plane) or Managed (the control plane).
	// +kubebuilder:default=Standalone
	// +optional
	Mode ClusterMode `json:"mode,omitempty"`

	// ControlPlane is the control plane to connect to. Required in GitOps
	// and Managed mode, ignored in Standalone.
	// +optional
	ControlPlane *ControlPlane `json:"controlPlane,omitempty"`

	// Engine configures the engine sidecars the operator injects.
	// +optional
	Engine EngineSpec `json:"engine,omitempty"`

	// Integrations pins how a proxy controller is wired. Controllers are
	// discovered without an entry here; an entry overrides the workload
	// selector or the adapter for one controller.
	// +listType=map
	// +listMapKey=controller
	// +kubebuilder:validation:MaxItems=32
	// +optional
	Integrations []IntegrationSpec `json:"integrations,omitempty"`

	// Suspend switches every engine to allow-all within seconds, without
	// removing anything: the emergency switch (0004 §5).
	// +optional
	Suspend bool `json:"suspend,omitempty"`
}

// ControlPlane is the connection to the optional control plane.
type ControlPlane struct {
	// Endpoint is the control plane's gRPC address, as grpcs://host:port.
	// +kubebuilder:validation:Pattern=`^grpcs://[^/\s]+$`
	// +kubebuilder:validation:MaxLength=512
	Endpoint string `json:"endpoint"`

	// EnrollmentSecretRef is the Secret holding the enrollment token.
	EnrollmentSecretRef SecretReference `json:"enrollmentSecretRef"`
}

// EngineSpec configures the engine sidecars.
type EngineSpec struct {
	// Image is the engine image. Empty means the image released with this
	// operator version.
	// +kubebuilder:validation:MaxLength=512
	// +optional
	Image string `json:"image,omitempty"`

	// Resources of the engine container. Setting no CPU limit is
	// recommended: CPU throttling shows up as tail latency on every request.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// SocketDir is the directory, shared with the proxy container, that
	// holds the engine's Unix sockets.
	// +kubebuilder:default="/var/run/inkwall"
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:XValidation:rule="self.startsWith('/')",message="socketDir must be an absolute path"
	// +optional
	SocketDir string `json:"socketDir,omitempty"`

	// BootstrapMode is what a new engine does with requests when it has no
	// bundle yet: no cached bundle, the bundle Secret unreadable and the
	// operator unreachable. It waits up to 10 seconds for one before its
	// proxy takes traffic, then allows (AllowAll) or rejects (DenyAll) the
	// requests until a bundle arrives. Applies to pods injected from then
	// on.
	// +kubebuilder:default=AllowAll
	// +optional
	BootstrapMode BootstrapMode `json:"bootstrapMode,omitempty"`
}

// IntegrationSpec overrides discovery for one proxy controller.
type IntegrationSpec struct {
	// Controller is the integration name, such as traefik or ingress-nginx.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Controller string `json:"controller"`

	// Selector matches the controller's proxy pods, when they don't carry
	// the controller's default labels. It must select by something (an
	// empty selector would match every pod). The operator restarts to
	// apply a change; pods already running are injected when they restart.
	// +kubebuilder:validation:XValidation:rule="(has(self.matchLabels) && size(self.matchLabels) > 0) || (has(self.matchExpressions) && size(self.matchExpressions) > 0)",message="selector must not be empty: it would select every pod"
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// Adapter is how the proxy hands requests to the engine, when the
	// controller supports several.
	// +optional
	Adapter AdapterKind `json:"adapter,omitempty"`
}

// InkwallConfigStatus is the cluster view.
type InkwallConfigStatus struct {
	// ObservedGeneration is the generation the status describes.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions describe the configuration's state.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// InkwallConfig is the cluster-wide Inkwall configuration. There is one,
// named default.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=inkwall
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'",message="the InkwallConfig must be named default"
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Suspended",type=boolean,JSONPath=`.spec.suspend`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type InkwallConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec InkwallConfigSpec `json:"spec,omitempty"`
	// +optional
	Status InkwallConfigStatus `json:"status,omitempty"`
}

// InkwallConfigList is a list of InkwallConfig.
//
// +kubebuilder:object:root=true
type InkwallConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []InkwallConfig `json:"items"`
}
