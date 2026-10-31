// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/yaml"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

var (
	migrateIngresses = filepath.Join("testdata", "migrate", "ingresses.yaml")
	migrateGlobal    = filepath.Join("testdata", "migrate", "global.yaml")
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
		want     string
		ruleSet  string // the WAFRuleSet's SecLang, without comments
		todo     int
		contains string // in an item's text
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
		{name: "ctl range", annotations: snippet(`SecRule REQUEST_FILENAME "@beginsWith /api" "id:1,phase:1,pass,ctl:ruleRemoveById=942000-942999"`),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1},
		{name: "ctl with deny", annotations: snippet(`SecRule REQUEST_FILENAME "@beginsWith /api" "id:1,phase:1,deny,ctl:ruleRemoveById=942100"`),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1},
		{name: "ctl path with a query", annotations: snippet(`SecRule REQUEST_FILENAME "@beginsWith /a?b" "id:1,phase:1,pass,ctl:ruleRemoveById=942100"`),
			want: "mode: Detect\ntargetRefs:\n- kind: Ingress\n  name: app\n", todo: 1},
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
			if got != tc.want {
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
