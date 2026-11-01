// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
)

var (
	migrateIngresses     = filepath.Join("testdata", "migrate", "ingresses.yaml")
	migrateGlobal        = filepath.Join("testdata", "migrate", "global.yaml")
	migrateHTTPRoutes    = filepath.Join("testdata", "migrate", "httproutes.yaml")
	migrateIngressRoutes = filepath.Join("testdata", "migrate", "ingressroutes.yaml")
)

// TestMigrateGolden converts real-world annotation sets; the golden files
// hold the exit code, the YAML and the summary.
func TestMigrateGolden(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		// Something can't be migrated: exit 1.
		{"ingresses", []string{"-f", migrateIngresses}, 1},
		{"global", []string{"-f", migrateGlobal}, 0},
		{"ingress-class", []string{"-f", migrateIngresses, "--controller-configmap", "web/none", "--ingress-class", "traefik"}, 0},
		{"httproute", []string{"-f", migrateIngresses, "-f", migrateHTTPRoutes, "--target", "httproute"}, 1},
		{"ingressroute", []string{"-f", migrateIngresses, "-f", migrateIngressRoutes, "--target", "ingressroute"}, 1},
		// What ingress-nginx treats specially: canary Ingresses, @streq,
		// ProcessPartial and phases.
		{"canary", []string{"-f", filepath.Join("testdata", "migrate", "canary.yaml")}, 0},
		{"streq", []string{"-f", filepath.Join("testdata", "migrate", "streq.yaml")}, 1},
		{"partial", []string{"-f", filepath.Join("testdata", "migrate", "partial.yaml")}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, append([]string{"migrate", "ingress-nginx"}, tc.args...)...)
			if code != tc.code {
				t.Errorf("exit %d, want %d; stderr:\n%s", code, tc.code, errOut)
			}
			golden(t, filepath.Join("migrate", tc.name+".golden"), fmt.Sprintf("exit %d\n%s--- stderr\n%s", code, out, errOut))
		})
	}
}

// TestMigrateRoundTrip checks the objects with inkwallctl test: the
// verdicts follow the ingress-nginx settings.
func TestMigrateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if code, out, errOut := runCLI(t, "migrate", "ingress-nginx", "-f", migrateIngresses, "--output", dir); code != 1 || out != "" {
		t.Fatalf("migrate: exit %d, stdout %q, stderr:\n%s", code, out, errOut)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, filepath.Base(f))
	}
	want := []string{"blog-blog.yaml", "clusterwafruleset-owasp-crs-v4.yaml", "files-cloud.yaml", "shop-api.yaml", "shop-shop.yaml"}
	if !slices.Equal(names, want) {
		t.Fatalf("files %v, want %v", names, want)
	}
	code, out, errOut := runCLI(t, "test", "--policy", dir, "--ingress", migrateIngresses,
		"--request", filepath.Join("testdata", "migrate", "requests.http"))
	if code != 0 {
		t.Fatalf("test: exit %d, stderr:\n%s", code, errOut)
	}
	golden(t, filepath.Join("migrate", "roundtrip.golden"), out)
	verdicts := strings.Split(strings.TrimSpace(out), "\n")
	for i, want := range []string{"deny", "allow", "deny", "log", "deny", "allow"} {
		if !strings.HasPrefix(verdicts[i], want) {
			t.Errorf("request %d: %q, want %s", i+1, verdicts[i], want)
		}
	}
}

// TestMigrateStrictRoundTrip replays, against the migrated objects,
// requests ingress-nginx denied: a canary Ingress's own settings, an
// @streq path ending in *, and ProcessPartial must not let them through.
func TestMigrateStrictRoundTrip(t *testing.T) {
	sqli := "1%27%20or%201=1--"
	// A 70 KB form: over the engine's default limit, under ingress-nginx's.
	body := "a=" + strings.Repeat("x", 70000) + "&q=" + sqli
	form := fmt.Sprintf("POST /submit HTTP/1.1\nHost: shop.example.com\nContent-Type: application/x-www-form-urlencoded\nContent-Length: %d\n\n%s", len(body), body)
	for _, tc := range []struct {
		name, requests string
		code           int
	}{
		{"canary", "GET /?q=" + sqli + " HTTP/1.1\nHost: shop.example.com\n\n", 0},
		{"streq", "GET /staticfoo/x?q=" + sqli + " HTTP/1.1\nHost: shop.example.com\n\n", 1},
		{"partial", form, 0},
	} {
		// Each is denied by the main Ingress's policy, shop/web.
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			in := filepath.Join("testdata", "migrate", tc.name+".yaml")
			if code, _, errOut := runCLI(t, "migrate", "ingress-nginx", "-f", in, "--output", dir); code != tc.code {
				t.Fatalf("migrate: exit %d, stderr:\n%s", code, errOut)
			}
			code, out, errOut := runCLI(t, "test", "--policy", dir, "--ingress", in,
				"--request", writeFile(t, "requests.http", tc.requests))
			if code != 0 || !strings.HasPrefix(out, "deny") || !strings.Contains(out, "policy=shop/web ") {
				t.Errorf("test: exit %d, want a deny as ingress-nginx's:\n%s%s", code, out, errOut)
			}
		})
	}
}

// TestMigrateIngressRouteRoundTrip retargets the policies to the
// IngressRoutes replacing the Ingresses: inkwallctl test routes the
// requests through them to the same verdicts.
func TestMigrateIngressRouteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if code, _, errOut := runCLI(t, "migrate", "ingress-nginx", "-f", migrateIngresses, "-f", migrateIngressRoutes,
		"--target", "ingressroute", "--output", dir); code != 1 {
		t.Fatalf("migrate: exit %d, stderr:\n%s", code, errOut)
	}
	for _, name := range []string{"shop-shop", "shop-api", "blog-blog", "files-cloud"} {
		var p wafv1alpha1.WAFPolicy
		readPolicy(t, filepath.Join(dir, name+".yaml"), &p)
		if len(p.Spec.TargetRefs) != 1 || p.Spec.TargetRefs[0].Kind != "IngressRoute" || p.Spec.TargetRefs[0].Group != "traefik.io" {
			t.Errorf("%s: targetRefs %+v, want its IngressRoute", name, p.Spec.TargetRefs)
		}
	}
	code, out, errOut := runCLI(t, "test", "--policy", dir, "--ingress", migrateIngressRoutes,
		"--request", filepath.Join("testdata", "migrate", "requests.http"))
	if code != 0 {
		t.Fatalf("test: exit %d, stderr:\n%s", code, errOut)
	}
	// The same verdicts as through the Ingresses.
	golden(t, filepath.Join("migrate", "roundtrip.golden"), out)
}

// TestMigrateHTTPRouteRoundTrip retargets the policies to the HTTPRoutes
// replacing the Ingresses: inkwallctl test routes the requests through
// them, and through the Ingresses of the policies left on them, to the
// same verdicts.
func TestMigrateHTTPRouteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if code, _, errOut := runCLI(t, "migrate", "ingress-nginx", "-f", migrateIngresses, "-f", migrateHTTPRoutes,
		"--target", "httproute", "--output", dir); code != 1 {
		t.Fatalf("migrate: exit %d, stderr:\n%s", code, errOut)
	}
	for _, tc := range []struct {
		file string
		want []wafv1alpha1.TargetRef
	}{
		{"shop-shop", []wafv1alpha1.TargetRef{{Group: httpRouteGroup, Kind: "HTTPRoute", Name: "shop"}}},
		{"shop-api", []wafv1alpha1.TargetRef{{Group: httpRouteGroup, Kind: "HTTPRoute", Name: "api", SectionName: "api"}}},
		{"blog-blog", []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "blog"}}},
	} {
		var p wafv1alpha1.WAFPolicy
		readPolicy(t, filepath.Join(dir, tc.file+".yaml"), &p)
		if !slices.Equal(p.Spec.TargetRefs, tc.want) {
			t.Errorf("%s: targetRefs %+v, want %+v", tc.file, p.Spec.TargetRefs, tc.want)
		}
	}
	code, out, errOut := runCLI(t, "test", "--policy", dir, "--ingress", migrateHTTPRoutes, "--ingress", migrateIngresses,
		"--request", filepath.Join("testdata", "migrate", "requests.http"))
	if code != 0 {
		t.Fatalf("test: exit %d, stderr:\n%s", code, errOut)
	}
	golden(t, filepath.Join("migrate", "roundtrip.golden"), out)
}

// readPolicy reads the WAFPolicy, the last object of a migrated file.
func readPolicy(t *testing.T, file string, p *wafv1alpha1.WAFPolicy) {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	docs := strings.Split(string(raw), "---\n")
	if err := yaml.UnmarshalStrict([]byte(docs[len(docs)-1]), p); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
}

// TestRetarget covers how Ingresses are matched to their replacing routes.
func TestRetarget(t *testing.T) {
	prefix := gatewayv1.PathMatchPathPrefix
	exact := gatewayv1.PathMatchExact
	get := gatewayv1.HTTPMethodGet
	route := func(name string, hosts []string, rules ...gatewayv1.HTTPRouteRule) gatewayv1.HTTPRoute {
		hr := gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name}}
		for _, h := range hosts {
			hr.Spec.Hostnames = append(hr.Spec.Hostnames, gatewayv1.Hostname(h))
		}
		hr.Spec.Rules = rules
		return hr
	}
	rule := func(name string, typ *gatewayv1.PathMatchType, path string) gatewayv1.HTTPRouteRule {
		r := gatewayv1.HTTPRouteRule{Matches: []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: typ, Value: &path}}}}
		if name != "" {
			n := gatewayv1.SectionName(name)
			r.Name = &n
		}
		return r
	}
	ingress := func(paths ...string) *networkingv1.Ingress {
		ing := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app"}}
		pt := networkingv1.PathTypePrefix
		var hp []networkingv1.HTTPIngressPath
		for _, p := range paths {
			hp = append(hp, networkingv1.HTTPIngressPath{Path: p, PathType: &pt})
		}
		ing.Spec.Rules = []networkingv1.IngressRule{{Host: "a.example.com",
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: hp}}}}
		return ing
	}
	withGet := rule("", &prefix, "/")
	withGet.Matches[0].Method = &get
	for _, tc := range []struct {
		name   string
		ing    *networkingv1.Ingress
		routes []gatewayv1.HTTPRoute
		want   string // the targets, "Kind/name/section ..."
		todo   int
	}{
		{name: "same host and path", ing: ingress("/"),
			routes: []gatewayv1.HTTPRoute{route("r", []string{"a.example.com"}, rule("", &prefix, "/"))},
			want:   "HTTPRoute/r/"},
		{name: "trailing slash", ing: ingress("/api/"),
			routes: []gatewayv1.HTTPRoute{route("r", []string{"a.example.com"}, rule("", &prefix, "/api"))},
			want:   "HTTPRoute/r/"},
		{name: "one path per route", ing: ingress("/a", "/b"),
			routes: []gatewayv1.HTTPRoute{
				route("ra", []string{"a.example.com"}, rule("", &prefix, "/a")),
				route("rb", []string{"a.example.com"}, rule("", &prefix, "/b")),
			},
			want: "HTTPRoute/ra/ HTTPRoute/rb/"},
		{name: "named rule of a wider route", ing: ingress("/a"),
			routes: []gatewayv1.HTTPRoute{route("r", []string{"a.example.com"}, rule("a", &prefix, "/a"), rule("b", &prefix, "/b"))},
			want:   "HTTPRoute/r/a"},
		{name: "unnamed rule of a wider route", ing: ingress("/a"),
			routes: []gatewayv1.HTTPRoute{route("r", []string{"a.example.com"}, rule("", &prefix, "/a"), rule("b", &prefix, "/b"))},
			want:   "Ingress/app/", todo: 1},
		{name: "partly covered", ing: ingress("/a", "/b"),
			routes: []gatewayv1.HTTPRoute{route("r", []string{"a.example.com"}, rule("", &prefix, "/a"))},
			want:   "HTTPRoute/r/", todo: 1},
		{name: "other host", ing: ingress("/"),
			routes: []gatewayv1.HTTPRoute{route("r", []string{"b.example.com"}, rule("", &prefix, "/"))},
			want:   "Ingress/app/", todo: 1},
		{name: "any host", ing: ingress("/"),
			routes: []gatewayv1.HTTPRoute{route("r", nil, rule("", &prefix, "/"))},
			want:   "Ingress/app/", todo: 1},
		{name: "exact instead of prefix", ing: ingress("/a"),
			routes: []gatewayv1.HTTPRoute{route("r", []string{"a.example.com"}, rule("", &exact, "/a"))},
			want:   "Ingress/app/", todo: 1},
		{name: "method", ing: ingress("/"),
			routes: []gatewayv1.HTTPRoute{route("r", []string{"a.example.com"}, withGet)},
			want:   "Ingress/app/", todo: 1},
		{name: "other namespace", ing: ingress("/"),
			routes: []gatewayv1.HTTPRoute{func() gatewayv1.HTTPRoute {
				hr := route("r", []string{"a.example.com"}, rule("", &prefix, "/"))
				hr.Namespace = "other"
				return hr
			}()},
			want: "Ingress/app/", todo: 1},
		{name: "too many targets", ing: ingress("/0", "/1", "/2", "/3", "/4", "/5", "/6", "/7", "/8", "/9", "/a", "/b", "/c", "/d", "/e", "/f", "/g"),
			routes: func() []gatewayv1.HTTPRoute {
				var out []gatewayv1.HTTPRoute
				for _, p := range "0123456789abcdefg" {
					out = append(out, route("r"+string(p), []string{"a.example.com"}, rule("", &prefix, "/"+string(p))))
				}
				return out
			}(),
			want: "HTTPRoute/r0/ HTTPRoute/r1/ HTTPRoute/r2/ HTTPRoute/r3/ HTTPRoute/r4/ HTTPRoute/r5/ HTTPRoute/r6/ HTTPRoute/r7/ HTTPRoute/r8/ HTTPRoute/r9/ HTTPRoute/ra/ HTTPRoute/rb/ HTTPRoute/rc/ HTTPRoute/rd/ HTTPRoute/re/ HTTPRoute/rf/",
			todo: 2},
		{name: "ingress without paths", ing: &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app"}},
			want: "Ingress/app/", todo: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &migration{namespace: "ns", name: "app", policy: &wafv1alpha1.WAFPolicy{
				Spec: wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "app"}}}}}
			newReplacements("HTTPRoute", tc.routes, nil).retarget(m, tc.ing)
			var got []string
			for _, r := range m.policy.Spec.TargetRefs {
				got = append(got, r.Kind+"/"+r.Name+"/"+r.SectionName)
			}
			var lines []string
			for _, it := range m.items {
				lines = append(lines, fmt.Sprintf("%d %s", it.kind, it.text))
			}
			if strings.Join(got, " ") != tc.want || m.todos() != tc.todo {
				t.Errorf("targets %v and %d TODO, want %s and %d:\n%s", got, m.todos(), tc.want, tc.todo, strings.Join(lines, "\n"))
			}
		})
	}
}

func ingressWith(annotations map[string]string) *networkingv1.Ingress {
	full := map[string]string{}
	for k, v := range annotations {
		full["nginx.ingress.kubernetes.io/"+k] = v
	}
	return &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app", Annotations: full}}
}

// TestMigrateIngress covers each annotation and directive.
func TestMigrateIngress(t *testing.T) {
	on := map[string]string{annEnable: "true", annCRS: "true"}
	snippet := func(s string) map[string]string {
		return map[string]string{annEnable: "true", annCRS: "true", annSnippet: s}
	}
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		global      nginxGlobal
		// want is the policy's spec as YAML; "" for no policy.
		want    string
		ruleSet string // the WAFRuleSet's SecLang, without comments
		// wantExclusions, if set, is the number of exclusions, instead of
		// comparing the spec with want.
		wantExclusions int
		todo           int
		contains       string // in an item's text
	}{
		{name: "nothing", annotations: nil},
		{name: "default detect", annotations: on,
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "invalid boolean", annotations: map[string]string{annEnable: "yes"},
			contains: "not a boolean"},
		{name: "crs without modsecurity", annotations: map[string]string{annCRS: "true"},
			contains: "ModSecurity is off"},
		{name: "modsecurity without rules", annotations: map[string]string{annEnable: "true"},
			contains: "no rules"},
		{name: "engine on", annotations: snippet("SecRuleEngine On"),
			want: "mode: Block\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "engine off", annotations: snippet("SecRuleEngine Off"),
			contains: "inspects nothing"},
		{name: "engine unset", annotations: map[string]string{annEnable: "true", annSnippet: "Include " + nginxCRSConf},
			want:     "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n",
			contains: "no SecRuleEngine"},
		{name: "recommended include", annotations: map[string]string{annEnable: "true", annSnippet: "SecRuleEngine On\nInclude " + nginxRecommendedConf + "\nInclude " + nginxCRSConf},
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "transaction id", annotations: map[string]string{annEnable: "true", annCRS: "true", annTransactionID: "$request_id"},
			want:     "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n",
			contains: "transaction ID"},
		{name: "paranoia v3", annotations: snippet(`SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=3"`),
			want: "mode: Detect\nruleSets:\n- paranoiaLevel: 3\n  ref:\n    kind: ClusterWAFRuleSet\n    name: owasp-crs-v4\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "paranoia out of range", annotations: snippet(`SecAction "id:900000,phase:1,nolog,pass,setvar:tx.paranoia_level=5"`),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1},
		{name: "detection paranoia", annotations: snippet(`SecAction "id:900000,phase:1,nolog,pass,setvar:tx.detection_paranoia_level=2"`),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1},
		{name: "paranoia without crs", annotations: map[string]string{annEnable: "true", annSnippet: `SecAction "id:900000,phase:1,pass,nolog,setvar:tx.paranoia_level=2"`},
			contains: "CRS is not loaded"},
		{name: "remove by id", annotations: snippet("SecRuleRemoveById 942100 942200"),
			want: "exclusions:\n- ruleIDs:\n  - 942100\n  - 942200\nmode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "remove range", annotations: snippet("SecRuleRemoveById 942000-942999"),
			want:    "mode: Detect\nruleSets:\n- ref:\n    kind: ClusterWAFRuleSet\n    name: owasp-crs-v4\n- ref:\n    kind: WAFRuleSet\n    name: app-modsecurity\ntargetRefs:\n- kind: Ingress\n  name: app\n",
			ruleSet: "SecRuleRemoveById 942000-942999\n"},
		{name: "update target", annotations: snippet(`SecRuleUpdateTargetById 942100 "!ARGS:a|!ARGS:b"`),
			want: "exclusions:\n- ruleIDs:\n  - 942100\n  when:\n    argument: a\n- ruleIDs:\n  - 942100\n  when:\n    argument: b\nmode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "update target cookie", annotations: snippet(`SecRuleUpdateTargetById 942100 "!REQUEST_COOKIES:session"`),
			ruleSet: "SecRuleUpdateTargetById 942100 \"!REQUEST_COOKIES:session\"\n",
			want:    "mode: Detect\nruleSets:\n- ref:\n    kind: ClusterWAFRuleSet\n    name: owasp-crs-v4\n- ref:\n    kind: WAFRuleSet\n    name: app-modsecurity\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "ctl exact path", annotations: snippet(`SecRule REQUEST_FILENAME "@streq /login" "id:1,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:password"`),
			want: "exclusions:\n- ruleIDs:\n  - 942100\n  when:\n    argument: password\n    path: /login\nmode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "ctl phase 2", annotations: snippet(`SecRule REQUEST_URI "@beginsWith /api/" "id:1,phase:2,pass,nolog,ctl:ruleRemoveById=942100"`),
			want:     "exclusions:\n- ruleIDs:\n  - 942100\n  when:\n    path: /api/*\nmode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n",
			contains: "phase 2"},
		{name: "ctl streq on uri", annotations: snippet(`SecRule REQUEST_URI "@streq /login" "id:1,phase:1,pass,ctl:ruleRemoveById=942100"`),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1},
		{name: "ctl range", annotations: snippet(`SecRule REQUEST_FILENAME "@beginsWith /api" "id:1,phase:1,pass,ctl:ruleRemoveById=941100-941130"`),
			want:     "exclusions:\n- ruleIDs:\n  - 941100\n  - 941101\n  - 941110\n  - 941120\n  - 941130\n  when:\n    path: /api*\nmode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n",
			contains: "941100-941130 (5 rules) expanded"},
		{name: "ctl target range", annotations: snippet(`SecRule REQUEST_FILENAME "@streq /login" "id:1,phase:1,pass,ctl:ruleRemoveTargetById=941100-941101;ARGS:q"`),
			want: "exclusions:\n- ruleIDs:\n  - 941100\n  - 941101\n  when:\n    argument: q\n    path: /login\nmode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "ctl range outside the crs", annotations: snippet(`SecRule REQUEST_FILENAME "@beginsWith /api" "id:1,phase:1,pass,ctl:ruleRemoveById=1-942999"`),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1, contains: "outside the CRS"},
		{name: "ctl range without rules", annotations: snippet(`SecRule REQUEST_FILENAME "@beginsWith /api" "id:1,phase:1,pass,ctl:ruleRemoveById=941102-941109"`),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1},
		{name: "ctl range reversed", annotations: snippet(`SecRule REQUEST_FILENAME "@beginsWith /api" "id:1,phase:1,pass,ctl:ruleRemoveById=942999-942000"`),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1},
		{name: "ctl large range", annotations: snippet(`SecRule REQUEST_FILENAME "@beginsWith /api" "id:1,phase:1,pass,ctl:ruleRemoveById=942000-942999"`),
			wantExclusions: 2},
		{name: "ctl with deny", annotations: snippet(`SecRule REQUEST_FILENAME "@beginsWith /api" "id:1,phase:1,deny,ctl:ruleRemoveById=942100"`),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1},
		{name: "ctl path with a query", annotations: snippet(`SecRule REQUEST_FILENAME "@beginsWith /a?b" "id:1,phase:1,pass,ctl:ruleRemoveById=942100"`),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1},
		{name: "ctl without phase", annotations: snippet(`SecRule REQUEST_FILENAME "@beginsWith /api/" "id:1,pass,nolog,ctl:ruleRemoveById=942100"`),
			want:     "exclusions:\n- ruleIDs:\n  - 942100\n  when:\n    path: /api/*\nmode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n",
			contains: "phase 2"},
		{name: "ctl streq with a star", annotations: snippet(`SecRule REQUEST_FILENAME "@streq /static*" "id:1,phase:1,pass,nolog,ctl:ruleEngine=Off"`),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1, contains: "literally"},
		{name: "process partial", annotations: map[string]string{annEnable: "true", annCRS: "true", annSnippet: "SecRuleEngine On\nInclude " + nginxRecommendedConf + "\nSecRequestBodyLimitAction ProcessPartial"},
			want:     "body:\n  maxBytes: 10485760\n  onOversize: Allow\nmode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n",
			contains: "capped"},
		{name: "process partial with a limit", annotations: snippet("SecRequestBodyLimit 1048576\nSecRequestBodyLimitAction ProcessPartial"),
			want: "body:\n  maxBytes: 1048576\n  onOversize: Allow\nmode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "recommended include after body", annotations: snippet("SecRequestBodyLimit 1048576\nSecRequestBodyLimitAction ProcessPartial\nInclude " + nginxRecommendedConf),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1, contains: "resets"},
		{name: "recommended include before body", annotations: snippet("Include " + nginxRecommendedConf + "\nSecRequestBodyLimit 1048576"),
			want: "body:\n  maxBytes: 1048576\nmode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "process partial without a known limit", annotations: snippet("SecRequestBodyLimitAction ProcessPartial"),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1, contains: "unknown"},
		{name: "nginx modsecurity directives", annotations: map[string]string{annEnable: "true", annCRS: "true", "configuration-snippet": "more_set_headers \"X: y\";\nmodsecurity_rules 'SecRuleRemoveById 942100';"},
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1, contains: "nginx's ModSecurity directives"},
		{name: "nginx snippet without modsecurity", annotations: map[string]string{annEnable: "true", annCRS: "true", "server-snippet": "location /x { return 404; }"},
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "global nginx modsecurity directives", global: nginxGlobal{nginxSnippets: []string{"ConfigMap http-snippet"}, source: "ConfigMap"},
			todo: 1},
		{name: "canary", annotations: map[string]string{annEnable: "true", annCRS: "true", annCanary: "true"},
			contains: "canary Ingress"},
		{name: "canary invalid", annotations: map[string]string{annEnable: "true", annCRS: "true", annCanary: "yes"},
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "body", annotations: snippet("SecRequestBodyAccess Off\nSecRequestBodyLimit 1048576\nSecRequestBodyLimitAction Reject"),
			want: "body:\n  inspect: false\n  maxBytes: 1048576\n  onOversize: Deny\nmode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "custom rule", annotations: map[string]string{annEnable: "true", annSnippet: `SecRuleEngine On
SecRule ARGS:debug "@streq true" "id:1100,phase:1,deny,status:403"`},
			want:    "mode: Block\nruleSets:\n- ref:\n    kind: WAFRuleSet\n    name: app-modsecurity\ntargetRefs:\n- kind: Ingress\n  name: app\n",
			ruleSet: "SecRule ARGS:debug \"@streq true\" \"id:1100,phase:1,deny,status:403\"\n"},
		{name: "rule id taken by the crs", annotations: snippet(`SecRule ARGS "@streq x" "id:942100,phase:1,deny"`),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1},
		{name: "custom ctl rule", annotations: snippet(`SecRule REQUEST_HEADERS:Host "@streq a" "id:1,phase:1,pass,nolog,ctl:ruleRemoveById=942100"`),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1},
		{name: "unsupported directives", annotations: snippet("SecRequestBodyNoFilesLimit 1\nSecResponseBodyAccess On\nInclude /x.conf\nSecAuditLog /dev/stdout"),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 3},
		{name: "unbalanced quotes", annotations: snippet(`SecRule ARGS "@rx a`),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1},
		{name: "global", global: nginxGlobal{enable: true, crs: true, snippet: "SecRuleEngine On", source: "ConfigMap"},
			want: "mode: Block\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "global without snippet", global: nginxGlobal{enable: true, crs: true, source: "ConfigMap"},
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
		{name: "global opt out", annotations: map[string]string{annEnable: "false"}, global: nginxGlobal{enable: true, crs: true, source: "ConfigMap"},
			contains: "turns ModSecurity off"},
		{name: "global with own crs", annotations: map[string]string{annCRS: "true"}, global: nginxGlobal{enable: true, source: "ConfigMap"},
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := migrateIngress(ingressWith(tc.annotations), tc.global, "nginx.ingress.kubernetes.io")
			if m == nil {
				if tc.want != "" || tc.contains != "" {
					t.Fatal("no result")
				}
				return
			}
			var got string
			if m.policy != nil {
				b, err := yaml.Marshal(m.policy.Spec)
				if err != nil {
					t.Fatal(err)
				}
				got = string(b)
			}
			var lines []string
			found := tc.contains == ""
			for _, it := range m.items {
				lines = append(lines, fmt.Sprintf("%d %s: %s", it.kind, it.source, it.text))
				found = found || strings.Contains(it.text, tc.contains)
			}
			if tc.wantExclusions != 0 {
				if n := len(m.policy.Spec.Exclusions); n != tc.wantExclusions {
					t.Errorf("%d exclusions, want %d", n, tc.wantExclusions)
				}
			} else if got != tc.want {
				t.Errorf("policy spec:\n%s\nwant:\n%s\nitems:\n%s", got, tc.want, strings.Join(lines, "\n"))
			}
			if n := m.todos(); n != tc.todo {
				t.Errorf("%d TODO items, want %d:\n%s", n, tc.todo, strings.Join(lines, "\n"))
			}
			if !found {
				t.Errorf("no item says %q:\n%s", tc.contains, strings.Join(lines, "\n"))
			}
			var rules string
			if m.ruleSet != nil {
				for _, l := range strings.SplitAfter(m.ruleSet.Spec.Source.SecLang, "\n") {
					if !strings.HasPrefix(l, "#") {
						rules += l
					}
				}
			}
			if rules != tc.ruleSet {
				t.Errorf("rule set %q, want %q", rules, tc.ruleSet)
			}
		})
	}
}

func TestMigrateCluster(t *testing.T) {
	class := "nginx"
	client := fake.NewClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ingress-nginx", Name: "ingress-nginx-controller"},
			Data:       map[string]string{cmEnable: "true", cmCRS: "true", cmSnippet: "SecRuleEngine On"},
		},
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "web"},
			Spec:       networkingv1.IngressSpec{IngressClassName: &class},
		},
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: "b", Name: "web"},
			Spec:       networkingv1.IngressSpec{IngressClassName: &class},
		},
	)
	var gotContext string
	orig := newKubeClient
	t.Cleanup(func() { newKubeClient = orig })
	newKubeClient = func(_, context string) (kubeClient, error) {
		gotContext = context
		return kubeClient{core: client.CoreV1(), networking: client.NetworkingV1()}, nil
	}

	code, out, errOut := runCLI(t, "migrate", "ingress-nginx", "--cluster", "--context", "prod", "--namespace", "a")
	if code != 0 || gotContext != "prod" {
		t.Fatalf("exit %d, context %q, stderr:\n%s", code, gotContext, errOut)
	}
	var p wafv1alpha1.WAFPolicy
	if err := yaml.UnmarshalStrict([]byte(out), &p); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	if p.Namespace != "a" || p.Spec.Mode != wafv1alpha1.PolicyBlock {
		t.Errorf("policy %s/%s mode %s, want a/web Block", p.Namespace, p.Name, p.Spec.Mode)
	}
	for _, a := range client.Actions() {
		if a.GetVerb() != "get" && a.GetVerb() != "list" {
			t.Errorf("the cluster was changed: %v", a)
		}
	}

	// No ConfigMap: only the annotations count.
	code, _, errOut = runCLI(t, "migrate", "ingress-nginx", "--cluster", "--controller-configmap", "x/y")
	if code != 0 || !strings.Contains(errOut, "no ConfigMap x/y") || !strings.Contains(errOut, "2 Ingress(es) read: 0 WAFPolicy") {
		t.Errorf("exit %d, stderr:\n%s", code, errOut)
	}
}

// TestMigrateClusterRoutes reads the HTTPRoutes from the cluster, with
// the dynamic client; a cluster without the CRD has none.
func TestMigrateClusterRoutes(t *testing.T) {
	class := "nginx"
	pt := networkingv1.PathTypePrefix
	client := fake.NewClientset(&networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "web", Annotations: map[string]string{
			"nginx.ingress.kubernetes.io/enable-modsecurity":      "true",
			"nginx.ingress.kubernetes.io/enable-owasp-core-rules": "true",
		}},
		Spec: networkingv1.IngressSpec{IngressClassName: &class, Rules: []networkingv1.IngressRule{{Host: "a.example.com",
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{Path: "/", PathType: &pt}}}}}}},
	})
	route := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata":   map[string]any{"namespace": "a", "name": "web-route"},
		"spec":       map[string]any{"hostnames": []any{"a.example.com"}, "rules": []any{map[string]any{}}},
	}}
	httpRoutes := schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "httproutes"}
	ingressRoutes := integrations.TraefikIngressRouteGVK.GroupVersion().WithResource("ingressroutes")
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{httpRoutes: "HTTPRouteList", ingressRoutes: "IngressRouteList"}, route)
	dyn.PrependReactor("list", "ingressroutes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(ingressRoutes.GroupResource(), "")
	})
	orig := newKubeClient
	t.Cleanup(func() { newKubeClient = orig })
	newKubeClient = func(_, _ string) (kubeClient, error) {
		return kubeClient{core: client.CoreV1(), networking: client.NetworkingV1(), dynamic: dyn}, nil
	}

	code, out, errOut := runCLI(t, "migrate", "ingress-nginx", "--cluster", "--target", "httproute")
	if code != 0 || !strings.Contains(out, "kind: HTTPRoute\n    name: web-route\n") {
		t.Errorf("exit %d, stdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	for _, a := range dyn.Actions() {
		if a.GetVerb() != "list" {
			t.Errorf("the cluster was changed: %v", a)
		}
	}

	// Without the CRD: the policy keeps the Ingress.
	code, out, errOut = runCLI(t, "migrate", "ingress-nginx", "--cluster", "--target", "ingressroute")
	if code != 1 || !strings.Contains(errOut, "the cluster has no ingressroutes.traefik.io") || !strings.Contains(out, "kind: Ingress\n") {
		t.Errorf("exit %d, stdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
}

func TestMigrateFlags(t *testing.T) {
	for _, args := range [][]string{
		{"migrate"},
		{"migrate", "traefik"},
		{"migrate", "ingress-nginx"},
		{"migrate", "ingress-nginx", "-f", migrateIngresses, "--cluster"},
		{"migrate", "ingress-nginx", "-f", migrateIngresses, "--context", "x"},
		{"migrate", "ingress-nginx", "-f", migrateIngresses, "--controller-configmap", "nginx"},
		{"migrate", "ingress-nginx", "-f", migrateIngresses, "extra"},
		{"migrate", "ingress-nginx", "-f", "testdata/migrate/missing.yaml"},
		{"migrate", "ingress-nginx", "-f", migrateIngresses, "--target", "gateway"},
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code, _, _ := runCLI(t, "migrate", "ingress-nginx", "-h"); code != 0 {
		t.Errorf("-h: exit %d", code)
	}
}

// TestMigrateStdin reads the objects from stdin, as kubectl get -o yaml
// piped in, in a List.
func TestMigrateStdin(t *testing.T) {
	list := `apiVersion: v1
kind: List
items:
- apiVersion: networking.k8s.io/v1
  kind: Ingress
  metadata:
    name: web
    annotations:
      nginx.ingress.kubernetes.io/enable-modsecurity: "true"
      nginx.ingress.kubernetes.io/enable-owasp-core-rules: "true"
  spec:
    ingressClassName: nginx
- apiVersion: v1
  kind: Service
  metadata:
    name: web
`
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = w.WriteString(list)
		_ = w.Close()
	}()
	stdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = stdin })
	code, out, errOut := runCLI(t, "migrate", "ingress-nginx", "-f", "-", "--namespace", "shop")
	if code != 0 || !strings.Contains(out, "namespace: shop") || !strings.Contains(errOut, "Service shop/web skipped") {
		t.Errorf("exit %d, stdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
}

// TestGlobalNginxSnippets finds nginx's ModSecurity directives in the
// ConfigMap's nginx snippets.
func TestGlobalNginxSnippets(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ingress-nginx", Name: "c"}, Data: map[string]string{
		"http-snippet":     "modsecurity on;\nmodsecurity_rules_file /etc/nginx/extra.conf;",
		"server-snippet":   "gzip on;",
		"location-snippet": "# not modsecurity",
	}}
	got := globalSettings(cm, io.Discard).nginxSnippets
	if want := []string{"ConfigMap ingress-nginx/c http-snippet"}; !slices.Equal(got, want) {
		t.Errorf("nginx snippets %q, want %q", got, want)
	}
}
