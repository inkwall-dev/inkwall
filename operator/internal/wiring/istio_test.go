// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

const userOverlay = `# the user's
spec:
  replicas: 2
  template:
    spec:
      initContainers:
      - name: user-init
        image: busybox
      containers:
      - name: istio-proxy
        resources:
          requests: {cpu: 50m}
`

// overlayOf is a ConfigMap's deployment overlay, parsed.
func overlayOf(t *testing.T, cm *corev1.ConfigMap) map[string]any {
	t.Helper()
	var o map[string]any
	if err := yaml.Unmarshal([]byte(cm.Data[istioOverlay]), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

// The engine goes first among the init containers, its volumes and the
// socket's mount in istio-proxy after the user's; again, nothing changes;
// removed, the user's overlay is back as it was, comments and all.
func TestWithIstioSidecar(t *testing.T) {
	s := injection.Sidecar{Image: "inkwall-engine:test", OperatorAddr: "inkwall-operator.inkwall-system.svc:9445", BundleSecret: "inkwall-system/inkwall-bundle",
		Args: []string{"ext-proc", "--listen=unix:" + envoySocket}, SocketDir: "/var/run/inkwall-socket"}
	for _, tc := range []struct {
		name string
		data map[string]string
	}{
		{"the user's overlay", map[string]string{istioOverlay: userOverlay, "service": "spec: {type: NodePort}\n"}},
		{"no overlay", map[string]string{"service": "spec: {type: NodePort}\n"}},
		{"no data", nil},
	} {
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "custom"}, Data: tc.data}
		orig := cm.DeepCopy()
		if changed, err := withIstioSidecar(cm, s, true); err != nil || !changed {
			t.Fatalf("%s: add: %v %v", tc.name, changed, err)
		}
		o := overlayOf(t, cm)
		inits := names(&unstructured.Unstructured{Object: o}, istioInitPath...)
		if !strings.HasPrefix(inits, injection.ContainerName) {
			t.Errorf("%s: init containers %s", tc.name, inits)
		}
		if got := names(&unstructured.Unstructured{Object: o}, istioVolumesPath...); !strings.HasSuffix(got, "inkwall-secrets,inkwall-cache,inkwall-tmp,inkwall-socket") {
			t.Errorf("%s: volumes %s", tc.name, got)
		}
		containers, _, _ := unstructured.NestedSlice(o, istioContainersPath...)
		if len(containers) != 1 {
			t.Fatalf("%s: containers %v", tc.name, containers)
		}
		proxy := containers[0].(map[string]any)
		mounts, _ := proxy["volumeMounts"].([]any)
		if proxy["name"] != istioProxy || len(mounts) != 1 || mounts[0].(map[string]any)["mountPath"] != "/var/run/inkwall-socket" {
			t.Errorf("%s: istio-proxy %v", tc.name, proxy)
		}
		if tc.name == "the user's overlay" {
			if r, _, _ := unstructured.NestedFloat64(o, "spec", "replicas"); r != 2 || !strings.HasSuffix(inits, ",user-init") || proxy["resources"] == nil {
				t.Errorf("%s: the user's fields: %v", tc.name, o)
			}
		}
		if cm.Labels[istioSidecarLabel] != "true" || cm.Data["service"] != orig.Data["service"] {
			t.Errorf("%s: labels %v, data %v", tc.name, cm.Labels, cm.Data)
		}

		// As the API server returns it: unchanged.
		if changed, err := withIstioSidecar(cm, s, true); err != nil || changed {
			t.Errorf("%s: again: %v %v", tc.name, changed, err)
		}
		// A new engine image changes it.
		s2 := s
		s2.Image = "inkwall-engine:new"
		if changed, _ := withIstioSidecar(cm.DeepCopy(), s2, true); !changed {
			t.Errorf("%s: a new image didn't change it", tc.name)
		}

		if changed, err := withIstioSidecar(cm, injection.Sidecar{}, false); err != nil || !changed {
			t.Fatalf("%s: remove: %v %v", tc.name, changed, err)
		}
		if a, b := jsonOf(cm.Data), jsonOf(orig.Data); a != b && !(len(cm.Data) == 0 && len(orig.Data) == 0) {
			t.Errorf("%s: removed:\n%s\nwant\n%s", tc.name, a, b)
		}
		if len(cm.Labels) > 0 || len(cm.Annotations) > 0 {
			t.Errorf("%s: left %v %v", tc.name, cm.Labels, cm.Annotations)
		}
		// Not the operator's: nothing to remove.
		if changed, _ := withIstioSidecar(cm, injection.Sidecar{}, false); changed {
			t.Errorf("%s: removed twice", tc.name)
		}
	}

	// The user changed their overlay meanwhile: only the operator's entries
	// go, theirs stay.
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "custom"}, Data: map[string]string{istioOverlay: userOverlay}}
	if _, err := withIstioSidecar(cm, s, true); err != nil {
		t.Fatal(err)
	}
	o := overlayOf(t, cm)
	_ = unstructured.SetNestedField(o, int64(3), "spec", "replicas")
	raw, _ := yaml.Marshal(o)
	cm.Data[istioOverlay] = string(raw)
	if _, err := withIstioSidecar(cm, injection.Sidecar{}, false); err != nil {
		t.Fatal(err)
	}
	o = overlayOf(t, cm)
	if r, _, _ := unstructured.NestedFloat64(o, "spec", "replicas"); r != 3 || names(&unstructured.Unstructured{Object: o}, istioInitPath...) != "user-init" ||
		strings.Contains(cm.Data[istioOverlay], "inkwall") {
		t.Errorf("edited overlay: %s", cm.Data[istioOverlay])
	}

	// An overlay that doesn't parse is reported, not overwritten.
	bad := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "bad"}, Data: map[string]string{istioOverlay: "spec: [unclosed"}}
	if _, err := withIstioSidecar(bad, s, true); err == nil || !strings.Contains(err.Error(), "edge/bad") {
		t.Errorf("bad overlay: %v", err)
	}
}

// istioTestRoute is a route with rules, some named.
func istioTestRoute(ns, name string, rules ...string) *gatewayv1.HTTPRoute {
	hr := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: gatewayv1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gw", Namespace: new(gatewayv1.Namespace("edge"))}}},
	}}
	for _, r := range rules {
		rule := gatewayv1.HTTPRouteRule{}
		if r != "" {
			rule.Name = new(gatewayv1.SectionName(r))
		}
		hr.Spec.Rules = append(hr.Spec.Rules, rule)
	}
	return hr
}

// Istio names a rule's Envoy routes after the rule, or namespace.route.index.
func TestEnvoyRoutes(t *testing.T) {
	hr := istioTestRoute("shop", "app", "", "admin", "")
	whole := &istioRoute{route: hr, sections: []string{""}}
	if got := strings.Join(whole.envoyRoutes(), " "); got != "shop.app.0 admin shop.app.2" {
		t.Errorf("whole route: %s", got)
	}
	one := &istioRoute{route: hr, sections: []string{"admin"}}
	if got := strings.Join(one.envoyRoutes(), " "); got != "admin" {
		t.Errorf("one rule: %s", got)
	}

	// Another route of the Gateway with a rule of the same name: refused.
	gw := types.NamespacedName{Namespace: "edge", Name: "gw"}
	st := &envoyState{
		routes: map[types.NamespacedName]*gatewayv1.HTTPRoute{
			{Namespace: "shop", Name: "app"}:   hr,
			{Namespace: "shop", Name: "other"}: istioTestRoute("shop", "other", "admin"),
		},
		gateways: map[types.NamespacedName]*gatewayv1.Gateway{gw: {ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "gw"}, Spec: gatewayv1.GatewaySpec{GatewayClassName: "istio"}}},
		classes:  map[string]*types.NamespacedName{"istio": nil},
	}
	if why := st.sharedRuleName(one, gw); !strings.Contains(why, "rule admin of HTTPRoute app has the name of a rule of HTTPRoute shop/other") {
		t.Errorf("shared: %q", why)
	}
	// A rule of its own route isn't another's; unnamed ones never collide.
	if why := st.sharedRuleName(&istioRoute{route: hr, sections: []string{""}}, gw); why == "" {
		t.Error("the whole route has admin too")
	}
	st.routes[types.NamespacedName{Namespace: "shop", Name: "other"}] = istioTestRoute("shop", "other", "", "public")
	if why := st.sharedRuleName(whole, gw); why != "" {
		t.Errorf("no shared name: %q", why)
	}
}

// The EnvoyFilter: the engine's cluster, a disabled filter per route,
// enabled on its protected rules, the buffer limit when a body is held;
// detect mode doesn't wait and streams the body.
func TestEnvoyFilter(t *testing.T) {
	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "gw", UID: "uid-gw"}}
	block := &istioRoute{route: istioTestRoute("shop", "app", "web", ""), sections: []string{""},
		routeSettings: routeSettings{body: true, maxBody: 64 << 10, timeout: time.Second}}
	detect := &istioRoute{route: istioTestRoute("blog", "posts", "read"), sections: []string{"read"},
		routeSettings: routeSettings{body: true, maxBody: 64 << 10, timeout: 250 * time.Millisecond, failOpen: true, detect: true}}
	f := envoyFilter(gw, []*istioRoute{block, detect})
	if f.GetNamespace() != "edge" || f.GetName() != "inkwall-waf-gw" || !isManaged(f) || f.GetOwnerReferences()[0].UID != "uid-gw" ||
		f.GetAnnotations()[istioRoutes] != "shop/app,blog/posts" || targetGateway(f) != "gw" {
		t.Fatalf("metadata %v", f.Object["metadata"])
	}
	patches, _, _ := unstructured.NestedSlice(f.Object, "spec", "configPatches")
	var kinds []string
	for _, p := range patches {
		kinds = append(kinds, p.(map[string]any)["applyTo"].(string))
	}
	if got := strings.Join(kinds, " "); got != "CLUSTER HTTP_FILTER HTTP_ROUTE HTTP_ROUTE HTTP_FILTER HTTP_ROUTE LISTENER" {
		t.Fatalf("patches %s", got)
	}
	spec := jsonOf(f.Object["spec"])
	for _, want := range []string{
		`"pipe":{"path":"/var/run/inkwall-socket/extproc.sock"}`,
		`"name":"inkwall.ext_proc.shop.app"`, `"disabled":true`,
		`"request_body_mode":"BUFFERED_PARTIAL"`, `"message_timeout":"1.500s"`, `"failure_mode_allow":false`,
		`"route":{"name":"web"}`, `"route":{"name":"shop.app.1"}`, `"route":{"name":"read"}`,
		`"name":"inkwall.ext_proc.blog.posts"`, `"request_body_mode":"STREAMED"`, `"observability_mode":true`, `"message_timeout":"0.750s"`,
		`"response_header_mode":"SKIP"`, `"request_attributes":["request.protocol"]`,
		`"per_connection_buffer_limit_bytes":10485760`, `"workloadSelector":{"labels":{"gateway.networking.k8s.io/gateway-name":"gw"}}`,
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("no %s in\n%s", want, spec)
		}
	}
	// Only detect: no buffer limit.
	if spec := jsonOf(envoyFilter(gw, []*istioRoute{detect}).Object["spec"]); strings.Contains(spec, "per_connection_buffer_limit_bytes") {
		t.Errorf("a buffer limit in detect mode: %s", spec)
	}
}

func TestTooOld(t *testing.T) {
	pod := func(image string) *corev1.Pod {
		return &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: istioProxy, Image: image}}}}
	}
	for image, want := range map[string]string{
		"docker.io/istio/proxyv2:1.24.3":                 "1.24",
		"docker.io/istio/proxyv2:1.31.3":                 "",
		"gcr.io/istio-release/proxyv2:1.25.0-distroless": "",
		"registry.example/proxy:custom":                  "",
	} {
		if got := tooOld(pod(image)); got != want {
			t.Errorf("%s: %q, want %q", image, got, want)
		}
	}
}

// Unwired: the operator's EnvoyFilters and ConfigMaps go, the user's
// ConfigMap loses the engine, a Gateway that names the operator's
// ConfigMap names none again; an Envoy Gateway Gateway is left to its
// integration.
func TestIstioUnwire(t *testing.T) {
	ctx := context.Background()
	s := scheme()
	_ = gatewayv1.Install(s)
	sc := injection.Sidecar{Image: "inkwall-engine:test", Args: []string{"ext-proc"}, SocketDir: "/var/run/inkwall-socket"}
	m := envoyMapper().(*meta.DefaultRESTMapper)
	m.Add(EnvoyFilterGVK, meta.RESTScopeNamespace)

	theirs := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "params"}, Data: map[string]string{istioOverlay: userOverlay}}
	if _, err := withIstioSidecar(theirs, sc, true); err != nil {
		t.Fatal(err)
	}
	userGW := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "custom"}, Spec: gatewayv1.GatewaySpec{
		GatewayClassName: "istio", Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Kind: "ConfigMap", Name: "params"}},
	}}
	ours := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: envoyName("plain"), Labels: managedLabels()}}
	ours.Labels[istioSidecarLabel] = "true"
	if _, err := withIstioSidecar(ours, sc, true); err != nil {
		t.Fatal(err)
	}
	plain := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "plain", Annotations: map[string]string{istioMark: envoyName("plain")}},
		Spec: gatewayv1.GatewaySpec{GatewayClassName: "istio", Infrastructure: &gatewayv1.GatewayInfrastructure{
			ParametersRef: &gatewayv1.LocalParametersReference{Kind: "ConfigMap", Name: envoyName("plain")}}}}
	// Envoy Gateway's mark, on its own Gateway.
	eg := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "eg", Annotations: map[string]string{sidecarMark: envoyName("eg")}},
		Spec: gatewayv1.GatewaySpec{GatewayClassName: "eg", Infrastructure: &gatewayv1.GatewayInfrastructure{
			ParametersRef: &gatewayv1.LocalParametersReference{Group: "gateway.envoyproxy.io", Kind: "EnvoyProxy", Name: envoyName("eg")}}}}
	ef := envoyFilter(plain, []*istioRoute{{route: istioTestRoute("shop", "app", ""), sections: []string{""}}})
	userEF := newObject(EnvoyFilterGVK, "edge", "lua")
	userEF.SetLabels(nil)

	c := fake.NewClientBuilder().WithScheme(s).WithRESTMapper(m).WithObjects(theirs, userGW, ours, plain, eg, ef, userEF).Build()
	in := &Istio{Client: c, APIReader: c}
	if ok, err := in.Wired(ctx, Target{Kind: httpRouteKind, Key: types.NamespacedName{Namespace: "shop", Name: "app"}}); err != nil || !ok {
		t.Errorf("Wired: %v %v", ok, err)
	}
	n, err := in.Unwire(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if n["EnvoyFilter"] != 1 || n["ConfigMap"] != 2 || n["Gateway"] != 1 {
		t.Errorf("counts %v", n)
	}
	if ok, err := in.Wired(ctx, Target{Kind: httpRouteKind, Key: types.NamespacedName{Namespace: "shop", Name: "app"}}); err != nil || ok {
		t.Errorf("Wired after unwiring: %v %v", ok, err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(ours), &corev1.ConfigMap{}); !apierrors.IsNotFound(err) {
		t.Errorf("the operator's ConfigMap: %v", err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(userEF), userEF); err != nil {
		t.Errorf("the user's EnvoyFilter: %v", err)
	}
	var cm corev1.ConfigMap
	if err := c.Get(ctx, client.ObjectKeyFromObject(theirs), &cm); err != nil || cm.Data[istioOverlay] != userOverlay || len(cm.Labels) > 0 || len(cm.Annotations) > 0 {
		t.Errorf("the user's ConfigMap: %v %v %v %v", err, cm.Data, cm.Labels, cm.Annotations)
	}
	var gw gatewayv1.Gateway
	if err := c.Get(ctx, client.ObjectKeyFromObject(plain), &gw); err != nil || gw.Spec.Infrastructure != nil || len(gw.Annotations) > 0 {
		t.Errorf("Gateway plain: %v %+v %v", err, gw.Spec.Infrastructure, gw.Annotations)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(eg), &gw); err != nil || gw.Annotations[sidecarMark] == "" || gw.Spec.Infrastructure.ParametersRef == nil {
		t.Errorf("Envoy Gateway's Gateway: %v %+v %v", err, gw.Spec.Infrastructure, gw.Annotations)
	}
}
