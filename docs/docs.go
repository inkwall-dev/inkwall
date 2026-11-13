// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package docs embeds the user documentation of this version, which
// inkwallctl mcp serves to AI assistants as resources (docs/mcp.md).
package docs

import "embed"

// FS holds the guides (docs/*.md), as of the build.
//
//go:embed *.md
var FS embed.FS
