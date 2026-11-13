#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Renders the Helm chart with rbac.integrations and checks each
# integration's ClusterRole and binding: granted by default (true), also
# without the values (helm upgrade --reuse-values from 0.2), and with auto
# (which grants every role when Helm can't ask the cluster, as here); left
# out when turned off; the operator's pod lists the integrations granted, so
# it restarts when they change; and the Pod webhook selects no pod without
# Traefik's. hack/kind/upgrade.sh checks auto against a cluster. Then checks
# that long release names don't give two objects the same name, and that the
# proxy namespaces reach the operator's flag and the Pod webhook.
set -euo pipefail

cd "$(dirname "$0")/.."

CHART=${CHART:-deploy/helm/inkwall}
fail=0

# check <want: the granted integrations, comma-separated> [helm flags...]
check() {
  local want=$1 out roles expected annotation
  shift
  out=$(helm template inkwall "$CHART" --namespace inkwall-system "$@")
  roles=$(awk '/^kind: ClusterRole(Binding)?$/ {k=$2; getline; getline; if ($2 ~ /^inkwall-operator-/) print k, $2}' <<<"$out" | sort | tr '\n' ' ')
  expected=$(for name in ${want//,/ }; do
    echo "ClusterRole inkwall-operator-$name"
    echo "ClusterRoleBinding inkwall-operator-$name"
  done | sort | tr '\n' ' ')
  annotation=$(sed -n 's/^ *waf.inkwall.dev\/integrations: "\(.*\)"$/\1/p' <<<"$out")
  if [[ "$roles" != "$expected" || "$annotation" != "$want" ]]; then
    echo "helm template $*: roles [$roles], annotation \"$annotation\"; want [$expected], \"$want\"" >&2
    fail=1
  fi
}

check envoy-gateway,haproxy,istio,istio-ingress,traefik
check envoy-gateway,haproxy,istio,istio-ingress,traefik --set rbac=null
check envoy-gateway,haproxy,istio,istio-ingress,traefik --set rbac.integrations=null
check envoy-gateway,haproxy,istio,istio-ingress,traefik --set rbac.integrations.traefik=auto --set rbac.integrations.envoyGateway=auto --set rbac.integrations.istio=auto --set rbac.integrations.haproxy=auto --set rbac.integrations.istioIngress=auto
check envoy-gateway,haproxy,istio,istio-ingress,traefik --set rbac.integrations.traefik=auto --set rbac.integrations.envoyGateway=true
check envoy-gateway,haproxy,istio,istio-ingress,traefik --set-string rbac.integrations.traefik=true
check haproxy,istio,istio-ingress,traefik --set rbac.integrations.envoyGateway=false
check envoy-gateway,haproxy,istio-ingress,traefik --set rbac.integrations.istio=false
check envoy-gateway,haproxy,istio,traefik --set rbac.integrations.istioIngress=false
check envoy-gateway,haproxy,istio,istio-ingress --set rbac.integrations.traefik=false
check envoy-gateway,istio,istio-ingress,traefik --set rbac.integrations.haproxy=false
check "" --set rbac.integrations.traefik=false --set rbac.integrations.envoyGateway=false --set rbac.integrations.istio=false --set rbac.integrations.haproxy=false --set rbac.integrations.istioIngress=false

if out=$(helm template inkwall "$CHART" --namespace inkwall-system --set rbac.integrations.traefik=yes 2>&1) ||
  ! grep -q "/rbac/integrations/traefik': value must be one of 'auto', 'true', 'false'" <<<"$out"; then
  echo "rbac.integrations.traefik=yes: want an error, got: $out" >&2
  fail=1
fi

# The Pod webhooks' objectSelectors: Traefik's, HAProxy's and Istio's
# ingress gateway pods, or none without the integration's role.
# selector WEBHOOK [helm flags...]: a Pod webhook's objectSelector, on one
# line. awk reads all of helm's output (no exit): stopping early would fail
# helm with SIGPIPE under pipefail.
selector() {
  local name=$1
  shift
  helm template inkwall "$CHART" --namespace inkwall-system "$@" |
    awk -v name="name: $name" 'done {next} $0 ~ "^ *" name "$" {on=1; next} on && /reinvocationPolicy/ {done=1; next} on && /objectSelector/ {p=1} p' | tr -s ' \n' ' '
}
# selects WEBHOOK LABEL VALUE: its default selector, and none without the role.
selects() {
  local webhook=$1 label=$2 key=$3 sel
  sel=$(selector "$webhook")
  if ! grep -q "$label" <<<"$sel"; then
    echo "$webhook objectSelector: $sel; want pods labelled $label" >&2
    fail=1
  fi
  sel=$(selector "$webhook" --set "rbac.integrations.$key=false")
  if grep -q "$label" <<<"$sel" || ! grep -q 'operator: Exists' <<<"$sel" || ! grep -q 'operator: DoesNotExist' <<<"$sel"; then
    echo "$webhook objectSelector without its role: $sel; want none" >&2
    fail=1
  fi
}
selects pods.waf.inkwall.dev 'app.kubernetes.io/name: traefik' traefik
selects haproxy.pods.waf.inkwall.dev 'app.kubernetes.io/name: kubernetes-ingress' haproxy
selects istio-ingress.pods.waf.inkwall.dev 'istio: ingressgateway' istioIngress

# The base ClusterRole is always there, without the integrations' writes.
out=$(helm template inkwall "$CHART" --namespace inkwall-system --set rbac.integrations.traefik=false --set rbac.integrations.envoyGateway=false --set rbac.integrations.istio=false --set rbac.integrations.haproxy=false --set rbac.integrations.istioIngress=false)
base=$(awk '/^kind: ClusterRole$/ {getline; getline; if ($2 == "inkwall-operator") on=1; next} /^---/ {on=0} on' <<<"$out")
if [[ -z "$base" ]] || grep -E 'middlewares|envoyproxies|envoyfilters' <<<"$base" >/dev/null; then
  echo "the base ClusterRole is missing, or has an integration's rules:" >&2
  echo "$base" >&2
  fail=1
fi

# Names are cut to 63 characters: a long release name (Helm allows 53) must
# keep the suffixes that tell the operator's objects apart.
for release in abcdefghijabcdefghijabcdefghijabcdefghijabcdef abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabc; do
  names=$(helm template "$release" "$CHART" --namespace inkwall-system |
    awk '/^kind:/ {k=$2} /^metadata:/ {m=1; next} m && /^  name:/ {print k, $2; m=0}')
  if dups=$(sort <<<"$names" | uniq -d) && [[ -n "$dups" ]]; then
    echo "release $release (${#release} characters): objects share a name:" >&2
    echo "$dups" >&2
    fail=1
  fi
  if [[ $(grep -c -e '^ClusterRole ' -e '^Service ' <<<"$names") != 8 ]]; then
    echo "release $release: want 6 ClusterRoles and 2 Services, got:" >&2
    echo "$names" >&2
    fail=1
  fi
done

# The proxy namespaces: the operator's flag and the Pod webhook's
# namespaceSelector, by default, from the value, and also without it (helm
# upgrade --reuse-values from 0.2); none with "*"; an error when empty.
# proxy [helm flags...]: the --proxy-namespaces flag, and the Pod webhook's
# namespaceSelector on one line.
proxy() {
  local out
  out=$(helm template inkwall "$CHART" --namespace inkwall-system "$@")
  printf '%s|' "$(sed -n 's/^ *- --proxy-namespaces=//p' <<<"$out")"
  awk '/name: pods.waf.inkwall.dev/ {on=1; next} on && /objectSelector/ {exit} on && /namespaceSelector/ {p=1} p' <<<"$out" |
    tr -s ' \n' ' ' | sed 's/^ *//; s/ *$//'
}
want="traefik,kube-system,envoy-gateway-system,istio-ingress,istio-system,haproxy-controller|namespaceSelector: matchExpressions: - key: kubernetes.io/metadata.name operator: In values: - envoy-gateway-system - haproxy-controller - istio-ingress - istio-system - kube-system - traefik"
for flags in "" "--set injection.proxyNamespaces=null"; do
  # shellcheck disable=SC2086
  if [[ $(proxy $flags) != "$want" ]]; then
    echo "proxy namespaces ($flags): $(proxy $flags); want $want" >&2
    fail=1
  fi
done
got=$(proxy --set "injection.proxyNamespaces={ingress}")
if [[ $got != "ingress|namespaceSelector: matchExpressions: - key: kubernetes.io/metadata.name operator: In values: - ingress" ]]; then
  echo "proxy namespaces {ingress}: $got" >&2
  fail=1
fi
got=$(proxy --set "injection.proxyNamespaces={*}")
if [[ $got != "*|" ]]; then
  echo "proxy namespaces {*}: $got; want every namespace, no namespaceSelector" >&2
  fail=1
fi
if out=$(helm template inkwall "$CHART" --namespace inkwall-system --set "injection.proxyNamespaces={}" 2>&1) ||
  ! grep -q 'injection.proxyNamespaces must list' <<<"$out"; then
  echo "injection.proxyNamespaces={}: want an error, got: $out" >&2
  fail=1
fi

# The monitoring kit (#381): nothing by default; the Prometheus Operator's
# objects only when the cluster serves monitoring.coreos.com/v1 (here, as
# --api-versions tells helm template) or when forced; the dashboard
# ConfigMap needs no CRD.
# monitoring <want: kinds, sorted, space-separated> [helm flags...]
monitoring() {
  local want=$1 got
  shift
  got=$(helm template inkwall "$CHART" --namespace inkwall-system "$@" |
    awk '/^kind: (ServiceMonitor|PodMonitor|PrometheusRule)$/ {print $2} /^  name: inkwall-operator-(dashboard|metrics)$/ {print $2}' |
    LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')
  if [[ "$got" != "$want" ]]; then
    echo "monitoring ($*): [$got], want [$want]" >&2
    fail=1
  fi
}
all=(--set metrics.serviceMonitor.enabled=true --set metrics.podMonitor.enabled=true --set metrics.prometheusRule.enabled=true --set metrics.dashboard.enabled=true)
monitoring ""
monitoring "" --api-versions monitoring.coreos.com/v1
monitoring "" --set metrics=null
monitoring "inkwall-operator-dashboard" "${all[@]}"
monitoring "PodMonitor PrometheusRule ServiceMonitor inkwall-operator-dashboard inkwall-operator-metrics" "${all[@]}" --api-versions monitoring.coreos.com/v1
monitoring "PodMonitor PrometheusRule ServiceMonitor inkwall-operator-dashboard inkwall-operator-metrics" "${all[@]}" --set metrics.forceMonitoringObjects=true
monitoring "PodMonitor" --set metrics.podMonitor.enabled=true --api-versions monitoring.coreos.com/v1
# The engines' PodMonitor covers the proxy namespaces, or every one.
out=$(helm template inkwall "$CHART" --namespace inkwall-system --set metrics.podMonitor.enabled=true --api-versions monitoring.coreos.com/v1 --set "injection.proxyNamespaces={*}")
# Not awk | grep -q: grep stopping early fails awk's write (pipefail).
podmonitor=$(awk '/^kind: PodMonitor$/,0' <<<"$out")
if ! grep -q '^    any: true$' <<<"$podmonitor"; then
  echo "PodMonitor with proxyNamespaces {*}: want namespaceSelector any: true" >&2
  fail=1
fi
# The alerts' runbooks are this release's docs.
out=$(helm template inkwall "$CHART" --namespace inkwall-system --set metrics.prometheusRule.enabled=true --api-versions monitoring.coreos.com/v1)
version=$(sed -n 's/^appVersion: "\(.*\)"$/\1/p' "$CHART/Chart.yaml")
if grep -q 'blob/main/' <<<"$out" || ! grep -q "blob/v$version/docs/monitoring.md#inkwallenginedisconnected" <<<"$out"; then
  echo "PrometheusRule: runbook_url must point at v$version's docs" >&2
  fail=1
fi
# NetworkPolicies (#387): none by default; the operator's ingress, with the
# distribution server open to the proxy namespaces (or every namespace with
# "*"); webhookFrom and metricsFrom; egress only when asked.
# netpol [helm flags...]: the NetworkPolicies, on one line.
netpol() {
  helm template inkwall "$CHART" --namespace inkwall-system "$@" |
    awk '/^kind: NetworkPolicy$/ {on=1} /^---$/ {on=0} on' | grep -v '^ *#' | tr -s ' \n' ' '
}
if [[ -n $(netpol) ]]; then
  echo "NetworkPolicies by default: $(netpol); want none" >&2
  fail=1
fi
# expect DESCRIPTION WANT [helm flags...]: the policies contain WANT.
expect() {
  local what=$1 want=$2 got
  shift 2
  got=$(netpol --set networkPolicy.enabled=true "$@")
  if ! grep -qF -- "$want" <<<"$got"; then
    echo "NetworkPolicy, $what: no \"$want\" in: $got" >&2
    fail=1
  fi
}
expect "distribution from the proxy namespaces" "- ports: - {port: distribution, protocol: TCP} from: - namespaceSelector: matchExpressions: - key: kubernetes.io/metadata.name operator: In values: - envoy-gateway-system - haproxy-controller - istio-ingress - istio-system - kube-system - traefik - ports:"
expect "distribution from every namespace" "- {port: distribution, protocol: TCP} from: - namespaceSelector: {} - ports:" --set "injection.proxyNamespaces={*}"
expect "webhook from anywhere" "ingress: - ports: - {port: webhook, protocol: TCP} - ports: - {port: probes, protocol: TCP}"
expect "webhook from the API server" "- {port: webhook, protocol: TCP} from: - ipBlock: cidr: 10.0.0.10/32" --set 'networkPolicy.webhookFrom[0].ipBlock.cidr=10.0.0.10/32'
expect "metrics from anywhere" "- ports: - {port: metrics, protocol: TCP} "
expect "metrics from Prometheus' namespace" "- {port: metrics, protocol: TCP} from: - namespaceSelector: matchLabels: kubernetes.io/metadata.name: monitoring" --set 'networkPolicy.metricsFrom[0].namespaceSelector.matchLabels.kubernetes\.io/metadata\.name=monitoring'
if grep -q 'policyTypes: \[Egress\]' <<<"$(netpol --set networkPolicy.enabled=true)"; then
  echo "NetworkPolicy: egress without networkPolicy.egress.enabled" >&2
  fail=1
fi
expect "egress" "policyTypes: [Egress] egress: - ports: - {port: 53, protocol: UDP} - {port: 53, protocol: TCP} - ports: - {port: 443, protocol: TCP} - {port: 6443, protocol: TCP} - ports: - port: 443 to: - ipBlock: cidr: 203.0.113.10/32" \
  --set networkPolicy.egress.enabled=true --set 'networkPolicy.egress.extra[0].to[0].ipBlock.cidr=203.0.113.10/32' --set 'networkPolicy.egress.extra[0].ports[0].port=443'
expect "egress to the API server's addresses" "- {port: 6443, protocol: TCP} to: - ipBlock: {cidr: 172.18.0.2/32}" --set networkPolicy.egress.enabled=true --set 'networkPolicy.egress.apiServerCIDRs={172.18.0.2/32}'
# values.schema.json (#386): a typo'd key, a wrong type and a value outside
# an enum fail the render, naming the value.
# rejects WANT [helm flags...]: helm template fails with WANT in its error.
rejects() {
  local want=$1 out
  shift
  if out=$(helm template inkwall "$CHART" --namespace inkwall-system "$@" 2>&1) || ! grep -qF -- "$want" <<<"$out"; then
    echo "helm template $*: want an error with \"$want\", got: $(head -5 <<<"$out")" >&2
    fail=1
  fi
}
rejects "additional properties 'integration' not allowed" --set rbac.integration.traefik=true
rejects "additional properties 'replica' not allowed" --set operator.replica=2
rejects "additional properties 'imageRegistry' not allowed" --set imageRegistry=registry.example.com
rejects "/rbac/integrations/traefik" --set rbac.integrations.traefik=yes
rejects "value must be one of 'rotate', 'certManager'" --set webhook.certs.mode=certmanager
rejects "value must be one of 'Always', 'IfNotPresent', 'Never'" --set engine.image.pullPolicy=always
rejects "/operator/replicas': got string, want integer" --set operator.replicas=two
rejects "/engine/image/digest" --set engine.image.digest=latest
rejects "additional properties 'enable' not allowed" --set networkPolicy.enable=true
rejects "/networkPolicy/enabled': got string, want boolean" --set-string networkPolicy.enabled=yes
rejects "/networkPolicy/egress/apiServerCIDRs/0" --set 'networkPolicy.egress.apiServerCIDRs={10.0.0.1}'
rejects "/networkPolicy/webhookFrom': got string, want array" --set networkPolicy.webhookFrom=apiserver
# Values a parent chart shares under global are its own.
if ! helm template inkwall "$CHART" --namespace inkwall-system --set global.storageClass=fast >/dev/null; then
  echo "global.storageClass: want it allowed (global is shared with parent charts)" >&2
  fail=1
fi

# Secure metrics (#430): off by default, and without the values (helm
# upgrade --reuse-values from 0.5): no TokenReview/SubjectAccessReview role,
# no flag, a plain-HTTP ServiceMonitor. On: the roles, --metrics-secure, a
# ServiceMonitor over HTTPS with Prometheus' token; certManager adds a
# Certificate for the metrics Service, mounted, which the ServiceMonitor
# verifies. The NetworkPolicy's metrics port is the same.
# secure WANT... -- [helm flags...]: the render contains each WANT
# (WANT starting with ! : doesn't).
secure() {
  local wants=() out w
  while [[ $1 != -- ]]; do
    wants+=("$1")
    shift
  done
  shift
  out=$(helm template inkwall "$CHART" --namespace inkwall-system --set metrics.serviceMonitor.enabled=true --set metrics.forceMonitoringObjects=true "$@")
  for w in "${wants[@]}"; do
    if [[ $w == !* ]]; then
      if grep -qF -- "${w#!}" <<<"$out"; then
        echo "secure metrics ($*): want no \"${w#!}\"" >&2
        fail=1
      fi
    elif ! grep -qF -- "$w" <<<"$out"; then
      echo "secure metrics ($*): no \"$w\"" >&2
      fail=1
    fi
  done
}
off=('!metrics-auth' '!metrics-reader' '!--metrics-secure' '!scheme: https' '!bearerTokenFile' '!metrics-tls')
secure "${off[@]}" --
secure "${off[@]}" -- --set metrics.secure=null
secure "${off[@]}" -- --set metrics.secure.certs.mode=certManager
secure 'name: inkwall-operator-metrics-auth' 'resources: [tokenreviews]' 'resources: [subjectaccessreviews]' \
  'kind: ClusterRoleBinding' 'name: inkwall-operator-metrics-reader' 'nonResourceURLs: [/metrics]' '- --metrics-secure' \
  'scheme: https' 'bearerTokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token' 'insecureSkipVerify: true' \
  '!--metrics-cert-dir' '!metrics-tls' '!kind: Certificate' -- --set metrics.secure.enabled=true
secure '- --metrics-cert-dir=/metrics-certs' 'mountPath: /metrics-certs' 'secretName: inkwall-operator-metrics-tls' \
  'kind: Certificate' '- inkwall-operator-metrics.inkwall-system.svc' 'name: inkwall-operator-metrics-selfsigned' \
  'serverName: inkwall-operator-metrics.inkwall-system.svc' 'key: ca.crt' '!insecureSkipVerify' \
  -- --set metrics.secure.enabled=true --set metrics.secure.certs.mode=certManager
secure 'kind: ClusterIssuer' '!metrics-selfsigned' -- --set metrics.secure.enabled=true --set metrics.secure.certs.mode=certManager \
  --set metrics.secure.certs.certManager.issuerRef.kind=ClusterIssuer --set metrics.secure.certs.certManager.issuerRef.name=corp
expect "metrics from anywhere, secure" "- ports: - {port: metrics, protocol: TCP} " --set metrics.secure.enabled=true
if out=$(helm template inkwall "$CHART" --namespace inkwall-system --set metrics.secure.certs.mode=vault 2>&1) ||
  ! grep -q "metrics/secure/certs/mode': value must be one of 'selfSigned', 'certManager'" <<<"$out"; then
  echo "metrics.secure.certs.mode=vault: want an error, got: $out" >&2
  fail=1
fi

# Images (#386): global.imageRegistry replaces the registry, a digest the tag;
# global.imagePullSecrets go on the operator's pods and the unwire Job's,
# and to the operator for the pods it injects the engine into.
# images [helm flags...]: the operator's images, --engine-image, the pull
# secrets flag and the pods' imagePullSecrets, one line.
images() {
  local out
  out=$(helm template inkwall "$CHART" --namespace inkwall-system "$@")
  { grep -E '^ *image: |--engine-image|^ *imagePullSecrets:|^ *- name: (mirror|regcred)$' <<<"$out" || true; } | tr -s ' \n' ' ' | sed 's/^ //; s/ $//'
}
version=$(sed -n 's/^appVersion: "\(.*\)"$/\1/p' "$CHART/Chart.yaml")
digest=sha256:$(printf '%064d' 0)
want="image: ghcr.io/inkwall-dev/inkwall-operator:$version - --engine-image=ghcr.io/inkwall-dev/inkwall-engine:$version - --engine-image-pull-policy=IfNotPresent image: ghcr.io/inkwall-dev/inkwall-operator:$version"
if [[ $(images) != "$want" ]]; then
  echo "images: $(images); want $want" >&2
  fail=1
fi
want="imagePullSecrets: - name: mirror - name: regcred image: registry.example.com/mirror/inkwall-dev/inkwall-operator:$version - --engine-image=registry.example.com/mirror/inkwall-dev/inkwall-engine@$digest - --engine-image-pull-policy=IfNotPresent - --engine-image-pull-secrets=mirror,regcred imagePullSecrets: - name: mirror - name: regcred image: registry.example.com/mirror/inkwall-dev/inkwall-operator:$version"
got=$(images --set global.imageRegistry=registry.example.com/mirror/ --set engine.image.digest="$digest" --set 'global.imagePullSecrets[0]=mirror' --set 'global.imagePullSecrets[1].name=regcred')
if [[ $got != "$want" ]]; then
  echo "images with a registry, a digest and pull secrets: $got; want $want" >&2
  fail=1
fi
# A repository without a registry gets it prepended.
got=$(images --set global.imageRegistry=mirror.example.com --set operator.image.repository=inkwall/operator --set operator.image.tag=dev)
if ! grep -q 'image: mirror.example.com/inkwall/operator:dev' <<<"$got"; then
  echo "images with a registry and a repository without one: $got" >&2
  fail=1
fi

# The operator's extra env, volumes, mounts and topology spread (#386).
out=$(helm template inkwall "$CHART" --namespace inkwall-system \
  --set 'operator.extraEnv[0].name=HTTPS_PROXY' --set 'operator.extraEnv[0].value=http://proxy:3128' \
  --set 'operator.extraVolumes[0].name=ca' --set 'operator.extraVolumes[0].configMap.name=corporate-ca' \
  --set 'operator.extraVolumeMounts[0].name=ca' --set 'operator.extraVolumeMounts[0].mountPath=/etc/ssl/corporate' \
  -f - <<'EOF'
operator:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
      labelSelector:
        matchLabels:
          app.kubernetes.io/instance: '{{ .Release.Name }}'
EOF
)
deployment=$(awk '/^kind: Deployment$/,/^---$/' <<<"$out")
for want in 'name: HTTPS_PROXY' 'value: http://proxy:3128' 'name: corporate-ca' 'mountPath: /etc/ssl/corporate' \
  'topologyKey: topology.kubernetes.io/zone' 'app.kubernetes.io/instance: inkwall$'; do
  if ! grep -q -- "$want" <<<"$deployment"; then
    echo "operator extras: no \"$want\" in the Deployment" >&2
    fail=1
  fi
done

exit $fail
