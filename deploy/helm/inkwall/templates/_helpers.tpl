{{/*
Copyright 2026 The Inkwall Authors
SPDX-License-Identifier: Apache-2.0
*/}}

{{- define "inkwall.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "inkwall.operator.name" -}}
{{- printf "%s-operator" (include "inkwall.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "inkwall.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: inkwall
{{- end -}}

{{- define "inkwall.operator.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: operator
{{- end -}}

{{- define "inkwall.operator.labels" -}}
{{ include "inkwall.labels" . }}
app.kubernetes.io/component: operator
{{- end -}}

{{- define "inkwall.serviceAccountName" -}}
{{- default (include "inkwall.operator.name" .) .Values.serviceAccount.name -}}
{{- end -}}

{{- define "inkwall.operator.image" -}}
{{- printf "%s:%s" .Values.operator.image.repository (default .Chart.AppVersion .Values.operator.image.tag) -}}
{{- end -}}

{{- define "inkwall.engine.image" -}}
{{- printf "%s:%s" .Values.engine.image.repository (default .Chart.AppVersion .Values.engine.image.tag) -}}
{{- end -}}

{{/* The webhook Service, named in the serving certificate. */}}
{{- define "inkwall.webhook.service" -}}
{{- printf "%s-webhook" (include "inkwall.operator.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* The distribution Service engines connect to, named in the certificate. */}}
{{- define "inkwall.distribution.service" -}}
{{- include "inkwall.operator.name" . -}}
{{- end -}}

{{- define "inkwall.webhook.secret" -}}
{{- printf "%s-webhook-tls" (include "inkwall.operator.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
The generated objects in files/ (copied there by `make generate`), as a list
of dicts. Argument: the file's path in the chart.
*/}}
{{- define "inkwall.generated" -}}
{{- $docs := list -}}
{{- range splitList "\n---\n" (printf "\n%s" (.root.Files.Get .path)) -}}
{{- $doc := fromYaml . -}}
{{- if $doc.kind -}}
{{- $docs = append $docs $doc -}}
{{- end -}}
{{- end -}}
{{- toJson $docs -}}
{{- end -}}

{{/* The control plane's CA bundle, and the enrollment token Secret. */}}
{{- define "inkwall.controlPlane.ca" -}}
{{- printf "%s-control-plane-ca" (include "inkwall.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "inkwall.controlPlane.enrollment" -}}
{{- printf "%s-enrollment" (include "inkwall.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- /*
controlPlane values, defaulted: an upgrade with --reuse-values from a release
whose values had no controlPlane (0.1.0) has none. Use with fromYaml.
*/}}
{{- define "inkwall.controlPlane.values" -}}
{{- toYaml (mergeOverwrite (dict "caBundle" "" "enrollmentToken" "" "eventsBufferMiB" 64) (deepCopy (.Values.controlPlane | default dict))) }}
{{- end }}

{{/*
The proxy namespaces (injection.proxyNamespaces), comma-separated. The
default list when the value is missing, as after helm upgrade
--reuse-values from an older chart.
*/}}
{{- define "inkwall.proxyNamespaces" -}}
{{- $ns := (.Values.injection | default dict).proxyNamespaces -}}
{{- if kindIs "invalid" $ns -}}
{{- $ns = list "traefik" "kube-system" -}}
{{- end -}}
{{- if kindIs "slice" $ns -}}
{{- $ns = compact $ns -}}
{{- end -}}
{{- if or (not (kindIs "slice" $ns)) (empty $ns) -}}
{{- fail "injection.proxyNamespaces must list the namespaces the proxies run in, or \"*\" for every namespace" -}}
{{- end -}}
{{- join "," $ns -}}
{{- end -}}

{{/*
Fails the render when pods that already run the Inkwall engine are in a
namespace injection.proxyNamespaces doesn't list: upgrading would leave
their routes unwired, uninspected. The namespaces are those of the
ServiceAccounts the operator granted the bundle (the RoleBinding
inkwall-bundle-reader). lookup finds nothing when Helm can't ask the
cluster (helm template, Argo CD): then there is no check.
*/}}
{{- define "inkwall.checkProxyNamespaces" -}}
{{- $listed := splitList "," (include "inkwall.proxyNamespaces" .) -}}
{{- if not (has "*" $listed) -}}
{{- $grant := lookup "rbac.authorization.k8s.io/v1" "RoleBinding" .Release.Namespace "inkwall-bundle-reader" -}}
{{- $outside := list -}}
{{- range $subject := (dig "subjects" list $grant) -}}
{{- $ns := $subject.namespace | default "" -}}
{{- if and $ns (not (has $ns $listed)) (not (has $ns $outside)) -}}
{{- range $pod := (dig "items" list (lookup "v1" "Pod" $ns "")) -}}
{{- $engine := eq (dig "metadata" "annotations" "waf.inkwall.dev/injected" "" $pod) "true" -}}
{{- range $c := concat (dig "spec" "initContainers" list $pod) (dig "spec" "containers" list $pod) -}}
{{- if eq $c.name "inkwall-engine" -}}{{- $engine = true -}}{{- end -}}
{{- end -}}
{{- if and $engine (not (has $ns $outside)) -}}{{- $outside = append $outside $ns -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- with sortAlpha $outside -}}
{{- fail (printf "pods with the Inkwall engine run in namespace(s) %s, which injection.proxyNamespaces doesn't list: add them (--set 'injection.proxyNamespaces={%s}') or set '*' to keep the old behaviour" (join "," .) (join "," (concat $listed .))) -}}
{{- end -}}
{{- end -}}
{{- end -}}
