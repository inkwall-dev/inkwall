// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package rbac holds the operator's RBAC, generated from its
// kubebuilder:rbac markers (make generate).
package rbac

import _ "embed"

// Roles is role.yaml: the operator's ClusterRole and Role, and one
// ClusterRole per integration (inkwall-operator-<integration>), which the
// chart can leave out.
//
//go:embed role.yaml
var Roles []byte
