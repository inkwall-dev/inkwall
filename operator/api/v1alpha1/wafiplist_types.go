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

// The rule, not the schema, makes entries required, so that another source of
// addresses (a URL the operator fetches) only relaxes the rule.

// WAFIPListSpec is a list of client addresses.
// +kubebuilder:validation:XValidation:rule="has(self.entries)",message="entries is required"
type WAFIPListSpec struct {
	// Entries are the list's addresses and prefixes. Required. Up to
	// 10,000, but the object must also fit etcd's request limit (1.5 MiB by
	// default): 10,000 entries fit without descriptions, about 4,500 with
	// 256-byte ones; split a longer list into several WAFIPLists. A CIDR
	// listed twice draws a warning: v1 keys the entries by cidr
	// (listType=map) and refuses it.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10000
	// +listType=atomic
	// +optional
	Entries []IPListEntry `json:"entries,omitempty"`
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
