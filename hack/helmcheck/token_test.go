// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package helmcheck

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

const tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount"

// The operator's ServiceAccount token, which can read the bundle signing
// key's Secret, is mounted into the operator's container only: not into
// the geoipupdate sidecar, which has internet egress. The kubelet's own
// mount is off, and the chart's carries what the kubelet's would: a token,
// the cluster's CA and the namespace. The kind end-to-end test runs the
// operator with it.
func TestServiceAccountToken(t *testing.T) {
	chart := os.Getenv("CHART")
	if chart == "" {
		t.Skip("CHART not set: run make helm-lint")
	}
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("no helm")
	}
	for _, args := range [][]string{
		nil,
		{"--set", "geo.geoipupdate.enabled=true", "--set", "geo.geoipupdate.secretName=maxmind"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			pod := deployment(t, chart, args...).Spec.Template.Spec
			if a := pod.AutomountServiceAccountToken; a == nil || *a {
				t.Errorf("automountServiceAccountToken = %v, want false", a)
			}
			var vol *corev1.Volume
			for i := range pod.Volumes {
				if pod.Volumes[i].Name == "kube-api-access" {
					vol = &pod.Volumes[i]
				}
			}
			if vol == nil || vol.Projected == nil {
				t.Fatal("no projected kube-api-access volume")
			}
			var token, ca, ns bool
			for _, src := range vol.Projected.Sources {
				switch {
				case src.ServiceAccountToken != nil:
					token = src.ServiceAccountToken.Path == "token" && src.ServiceAccountToken.Audience == ""
				case src.ConfigMap != nil:
					ca = src.ConfigMap.Name == "kube-root-ca.crt" && len(src.ConfigMap.Items) == 1 &&
						src.ConfigMap.Items[0] == corev1.KeyToPath{Key: "ca.crt", Path: "ca.crt"}
				case src.DownwardAPI != nil:
					ns = len(src.DownwardAPI.Items) == 1 && src.DownwardAPI.Items[0].Path == "namespace" &&
						src.DownwardAPI.Items[0].FieldRef != nil && src.DownwardAPI.Items[0].FieldRef.FieldPath == "metadata.namespace"
				}
			}
			if !token || !ca || !ns {
				t.Errorf("kube-api-access: token %t, ca.crt %t, namespace %t; want all: %+v", token, ca, ns, vol.Projected.Sources)
			}

			containers := append(append([]corev1.Container{}, pod.InitContainers...), pod.Containers...)
			sidecar := false
			for _, c := range containers {
				var mounted bool
				for _, m := range c.VolumeMounts {
					if m.Name == "kube-api-access" || strings.HasPrefix(tokenPath, strings.TrimSuffix(m.MountPath, "/")) && m.MountPath != "/" {
						mounted = m.Name == "kube-api-access" && m.MountPath == tokenPath && m.ReadOnly
						if c.Name != "operator" {
							t.Errorf("container %s mounts %s at %s: want the token in the operator's container only", c.Name, m.Name, m.MountPath)
						}
					}
				}
				if c.Name == "operator" && !mounted {
					t.Errorf("the operator's container doesn't mount kube-api-access read-only at %s: %+v", tokenPath, c.VolumeMounts)
				}
				if c.Name == "geoipupdate" {
					sidecar = true
					if !strings.Contains(c.Image, "@sha256:") {
						t.Errorf("geoipupdate image %s: want it pinned by digest", c.Image)
					}
				}
			}
			if want := args != nil; sidecar != want {
				t.Errorf("geoipupdate sidecar: %t, want %t", sidecar, want)
			}
		})
	}
}

// deployment renders the chart and returns the operator's Deployment.
func deployment(t *testing.T, chart string, args ...string) *appsv1.Deployment {
	t.Helper()
	args = append([]string{"template", "inkwall", chart, "--namespace", "inkwall-system", "--show-only", "templates/deployment.yaml"}, args...)
	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm %s: %v: %s", strings.Join(args, " "), err, out)
	}
	var d appsv1.Deployment
	if err := yaml.UnmarshalStrict(out, &d); err != nil {
		t.Fatalf("the Deployment: %v", err)
	}
	return &d
}
