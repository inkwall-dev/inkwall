// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package buildinfo reports what a binary was built from, for the commands'
// version subcommand and --version flag.
package buildinfo

import (
	"cmp"
	"fmt"
	"runtime"
	"runtime/debug"
)

// Info is what a binary was built from.
type Info struct {
	// Version is the release version (stamped with -ldflags at release
	// builds, without "v"), else the module version Go recorded (a tag,
	// for go install), else "(devel)" or "unknown".
	Version string
	// Commit is the Git commit (vcs.revision, or stamped with -ldflags
	// where the build has no .git, as for the images), else "unknown".
	Commit string
	// Modified: built from a checkout with local changes.
	Modified bool
	// Go is the Go version the binary was built with; Platform is
	// GOOS/GOARCH.
	Go, Platform string
}

// Get reports the running binary; version and commit are the -ldflags
// values (empty when not stamped), which win over the build info.
func Get(version, commit string) Info {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		bi = nil
	}
	return fromBuildInfo(bi, version, commit)
}

func fromBuildInfo(bi *debug.BuildInfo, version, commit string) Info {
	info := Info{Version: version, Commit: commit, Go: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH}
	if bi != nil {
		info.Version = cmp.Or(info.Version, bi.Main.Version)
		info.Go = cmp.Or(bi.GoVersion, info.Go)
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				info.Commit = cmp.Or(info.Commit, s.Value)
			case "vcs.modified":
				info.Modified = s.Value == "true"
			}
		}
	}
	info.Version = cmp.Or(info.Version, "unknown")
	info.Commit = cmp.Or(info.Commit, "unknown")
	return info
}

// String is what the version subcommand prints for the command name.
func (i Info) String(name string) string {
	modified := ""
	if i.Modified {
		modified = " (modified)"
	}
	return fmt.Sprintf("%s %s\ncommit: %s%s\ngo: %s %s\n", name, i.Version, i.Commit, modified, i.Go, i.Platform)
}
