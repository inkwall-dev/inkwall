// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command versionsbump bumps the versions under test in hack/versions.env
// (#393) to their latest upstream releases: each entry after a "# source:"
// comment, from
//
//	# source: github-release OWNER/REPO          (its latest release's tag)
//	# source: helm-chart INDEX_URL CHART [KEY]   (the chart's newest stable version; KEY gets its appVersion)
//	# source: docker-tag IMAGE PREFIX            (the newest PREFIX.N tag on Docker Hub)
//
// It rewrites the file, the docs' paragraphs marked <!-- versions: KEY -->
// (make docs-check holds them to the file) and the raw Envoy sample's
// image, and prints one line per bump. The weekly workflow
// (.github/workflows/versions.yaml) opens a PR with the changes.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// source is where an entry's latest version comes from.
type source struct {
	kind string   // github-release, helm-chart or docker-tag
	args []string // its arguments
}

// entry is a KEY=value line, and its source if any.
type entry struct {
	key, value string
	line       int
	src        *source
}

// parse reads the versions file.
func parse(text string) []entry {
	var out []entry
	var src *source
	for i, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(t, "# source:"); ok {
			f := strings.Fields(rest)
			if len(f) > 0 {
				src = &source{kind: f[0], args: f[1:]}
			}
			continue
		}
		if strings.HasPrefix(t, "#") || t == "" {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		out = append(out, entry{key: k, value: v, line: i, src: src})
		src = nil
	}
	return out
}

// fetcher answers what the latest versions are.
type fetcher interface {
	githubRelease(repo string) (string, error)
	helmChart(index, chart string) (version, appVersion string, err error)
	dockerTag(image, prefix string) (string, error)
}

// bumps works out the new values: key → value.
func bumps(entries []entry, f fetcher) (map[string]string, error) {
	out := map[string]string{}
	for _, e := range entries {
		if e.src == nil {
			continue
		}
		var v string
		var err error
		switch a := e.src.args; e.src.kind {
		case "github-release":
			if len(a) != 1 {
				return nil, fmt.Errorf("%s: github-release takes OWNER/REPO", e.key)
			}
			v, err = f.githubRelease(a[0])
		case "helm-chart":
			if len(a) < 2 {
				return nil, fmt.Errorf("%s: helm-chart takes INDEX_URL CHART [KEY]", e.key)
			}
			var app string
			v, app, err = f.helmChart(a[0], a[1])
			if err == nil && len(a) > 2 && app != "" {
				out[a[2]] = app
			}
		case "docker-tag":
			if len(a) != 2 {
				return nil, fmt.Errorf("%s: docker-tag takes IMAGE PREFIX", e.key)
			}
			v, err = f.dockerTag(a[0], a[1])
		default:
			return nil, fmt.Errorf("%s: unknown source %q", e.key, e.src.kind)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.key, err)
		}
		out[e.key] = v
	}
	return out, nil
}

// apply rewrites the versions file with the new values.
func apply(text string, values map[string]string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		k, _, ok := strings.Cut(line, "=")
		if v, bump := values[k]; ok && bump && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			lines[i] = k + "=" + v
		}
	}
	return strings.Join(lines, "\n")
}

var markerRE = regexp.MustCompile(`^\s*<!--\s*versions:\s*([A-Z0-9_ ]+?)\s*-->\s*$`)

// applyDoc replaces, in the paragraphs marked for a key, its old value
// with the new one, with and without a leading "v".
func applyDoc(text string, changed map[string][2]string) string {
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		m := markerRE.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		for j := i + 1; j < len(lines) && strings.TrimSpace(lines[j]) != ""; j++ {
			for _, key := range strings.Fields(m[1]) {
				if c, ok := changed[key]; ok {
					lines[j] = strings.ReplaceAll(lines[j], c[0], c[1])
					if old, nw := strings.TrimPrefix(c[0], "v"), strings.TrimPrefix(c[1], "v"); old != c[0] && nw != c[1] {
						lines[j] = regexp.MustCompile(`(^|[^v.\d])`+regexp.QuoteMeta(old)+`\b`).ReplaceAllString(lines[j], "${1}"+nw)
					}
				}
			}
		}
	}
	return strings.Join(lines, "\n")
}

func main() {
	file := flag.String("file", "hack/versions.env", "the versions file")
	dry := flag.Bool("n", false, "print the bumps, change nothing")
	flag.Parse()
	raw, err := os.ReadFile(*file)
	if err != nil {
		fail(err)
	}
	entries := parse(string(raw))
	values, err := bumps(entries, web{client: &http.Client{Timeout: 30 * time.Second}})
	if err != nil {
		fail(err)
	}
	changed := map[string][2]string{}
	for _, e := range entries {
		if v, ok := values[e.key]; ok && v != e.value {
			changed[e.key] = [2]string{e.value, v}
			fmt.Printf("%s: %s -> %s\n", e.key, e.value, v)
		}
	}
	if len(changed) == 0 || *dry {
		return
	}
	if err := os.WriteFile(*file, []byte(apply(string(raw), values)), 0o644); err != nil { // #nosec G306 G703 -- the caller's flag, a tracked text file
		fail(err)
	}
	docs, err := exec.Command("git", "ls-files", "*.md").Output()
	if err != nil {
		fail(err)
	}
	for _, p := range strings.Fields(string(docs)) {
		rewrite(p, func(s string) string { return applyDoc(s, changed) })
	}
	if c, ok := changed["ENVOY_VERSION"]; ok {
		rewrite(filepath.Join("examples", "raw-envoy", "kubernetes.yaml"), func(s string) string {
			return strings.ReplaceAll(s, "envoyproxy/envoy:"+c[0], "envoyproxy/envoy:"+c[1])
		})
	}
}

func rewrite(p string, f func(string) string) {
	raw, err := os.ReadFile(p) // #nosec G304 -- tracked files
	if err != nil {
		fail(err)
	}
	if out := f(string(raw)); out != string(raw) {
		if err := os.WriteFile(p, []byte(out), 0o644); err != nil { // #nosec G306 -- a tracked text file
			fail(err)
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "versionsbump:", err)
	os.Exit(1)
}

// web fetches from GitHub, chart repositories and Docker Hub.
type web struct{ client *http.Client }

func (w web) get(url string, v any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if t := os.Getenv("GITHUB_TOKEN"); t != "" && strings.HasPrefix(url, "https://api.github.com/") {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if strings.HasSuffix(url, ".yaml") {
		return yaml.Unmarshal(body, v)
	}
	return json.Unmarshal(body, v)
}

func (w web) githubRelease(repo string) (string, error) {
	var r struct {
		TagName string `json:"tag_name"`
	}
	err := w.get("https://api.github.com/repos/"+repo+"/releases/latest", &r)
	return r.TagName, err
}

func (w web) helmChart(index, chart string) (string, string, error) {
	var idx struct {
		Entries map[string][]struct {
			Version    string `json:"version"`
			AppVersion string `json:"appVersion"`
		} `json:"entries"`
	}
	if err := w.get(strings.TrimSuffix(index, "/")+"/index.yaml", &idx); err != nil {
		return "", "", err
	}
	best, app := "", ""
	for _, e := range idx.Entries[chart] {
		if stable(e.Version) && (best == "" || less(best, e.Version)) {
			best, app = e.Version, e.AppVersion
		}
	}
	if best == "" {
		return "", "", fmt.Errorf("no stable version of chart %s", chart)
	}
	return best, app, nil
}

func (w web) dockerTag(image, prefix string) (string, error) {
	var page struct {
		Results []struct {
			Name string `json:"name"`
		} `json:"results"`
	}
	if err := w.get("https://hub.docker.com/v2/repositories/library/"+image+"/tags?page_size=100&name="+prefix+".", &page); err != nil {
		return "", err
	}
	re := regexp.MustCompile(`^` + regexp.QuoteMeta(prefix) + `\.\d+$`)
	var tags []string
	for _, r := range page.Results {
		if re.MatchString(r.Name) {
			tags = append(tags, r.Name)
		}
	}
	if len(tags) == 0 {
		return "", fmt.Errorf("no %s:%s.N tag", image, prefix)
	}
	slices.SortFunc(tags, func(a, b string) int {
		if less(a, b) {
			return -1
		}
		return 1
	})
	return tags[len(tags)-1], nil
}

// stable: digits and dots only, after an optional "v".
func stable(v string) bool {
	return regexp.MustCompile(`^v?\d+(\.\d+)*$`).MatchString(v)
}

// less compares dotted versions numerically.
func less(a, b string) bool {
	pa, pb := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := range max(len(pa), len(pb)) {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}
