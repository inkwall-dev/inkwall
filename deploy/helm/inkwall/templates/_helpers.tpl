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
