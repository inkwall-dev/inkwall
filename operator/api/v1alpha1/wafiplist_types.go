// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IPListEntry is one address or CIDR prefix of a WAFIPList.
type IPListEntry struct {
	// CIDR is an IPv4 or IPv6 prefix (203.0.113.0/24, 2001:db8::/32) or
	// address.
	CIDR CIDR `json:"cidr"`

	// Description says what the entry is, for people.
	// +kubebuilder:validation:MaxLength=256
	// +optional
	Description string `json:"description,omitempty"`
}

// WAFIPListSpec is a list of client addresses.
type WAFIPListSpec struct {
	// Entries are the list's addresses and prefixes.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10000
	Entries []IPListEntry `json:"entries"`
}

// WAFIPList is a list of client addresses that WAFPolicies in its
// namespace allow or deny (spec.ipLists). The client address is the one the
// engine resolves: see docs/client-ip.md.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=inkwall,shortName=wafip
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type WAFIPList struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec WAFIPListSpec `json:"spec"`
}

// WAFIPListList is a list of WAFIPList.
//
// +kubebuilder:object:root=true
type WAFIPListList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WAFIPList `json:"items"`
}
