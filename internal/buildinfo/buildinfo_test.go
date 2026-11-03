// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package buildinfo

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func TestFromBuildInfo(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	built := func(main string, settings ...debug.BuildSetting) *debug.BuildInfo {
		return &debug.BuildInfo{GoVersion: "go1.27.3", Main: debug.Module{Path: "github.com/inkwall-dev/inkwall", Version: main}, Settings: settings}
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	for _, tc := range []struct {
		name             string
		bi               *debug.BuildInfo
		ldVersion, ldSHA string
		want             Info
	}{{
		name: "go install at a tag",
		bi:   built("v0.3.1", debug.BuildSetting{Key: "vcs.revision", Value: sha}),
		want: Info{Version: "v0.3.1", Commit: sha, Go: "go1.27.3", Platform: platform},
	}, {
		name:      "release: the ldflags win",
		bi:        built("v0.3.1-0.20261101000000-0123456789ab", debug.BuildSetting{Key: "vcs.revision", Value: sha}),
		ldVersion: "0.3.1",
		want:      Info{Version: "0.3.1", Commit: sha, Go: "go1.27.3", Platform: platform},
	}, {
		name:      "image: no VCS stamp, the commit from the ldflags",
		bi:        built("(devel)"),
		ldVersion: "0.3.1", ldSHA: sha,
		want: Info{Version: "0.3.1", Commit: sha, Go: "go1.27.3", Platform: platform},
	}, {
		name: "go build in a checkout with local changes",
		bi: built("(devel)", debug.BuildSetting{Key: "vcs.revision", Value: sha},
			debug.BuildSetting{Key: "vcs.modified", Value: "true"}),
		want: Info{Version: "(devel)", Commit: sha, Modified: true, Go: "go1.27.3", Platform: platform},
	}, {
		name: "no build info",
		want: Info{Version: "unknown", Commit: "unknown", Go: runtime.Version(), Platform: platform},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := fromBuildInfo(tc.bi, tc.ldVersion, tc.ldSHA); got != tc.want {
				t.Errorf("got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestString(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	for _, tc := range []struct {
		info Info
		want string
	}{{
		info: Info{Version: "v0.3.1", Commit: sha, Go: "go1.27.3", Platform: "linux/amd64"},
		want: "inkwallctl v0.3.1\ncommit: " + sha + "\ngo: go1.27.3 linux/amd64\n",
	}, {
		info: Info{Version: "(devel)", Commit: sha, Modified: true, Go: "go1.27.3", Platform: "darwin/arm64"},
		want: "inkwallctl (devel)\ncommit: " + sha + " (modified)\ngo: go1.27.3 darwin/arm64\n",
	}} {
		if got := tc.info.String("inkwallctl"); got != tc.want {
			t.Errorf("got\n%s\nwant\n%s", got, tc.want)
		}
	}
	// What a binary built by go test prints.
	if got := Get("", "").String("x"); !strings.HasPrefix(got, "x ") || !strings.Contains(got, "\ngo: "+runtime.Version()) {
		t.Errorf("Get: %q", got)
	}
}
