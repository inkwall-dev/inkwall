# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# shellcheck disable=SC2154 # work, CLUSTER, KUBECTL, HELM, IMAGE: the sourcing script's

# The battle test's stacks (#600), sourced by hack/kind/soak.sh and
# hack/kind/response-load.sh: every proxy Inkwall protects, each with the
# same app behind it and a WAFPolicy in Block mode on its route, reachable
# from this host on a NodePort of the kind node (no port-forward, so traffic
# keeps flowing while the API server is down):
#
#   traefik        Traefik (its chart), an Ingress
#   envoy-gateway  Envoy Gateway, a Gateway and an HTTPRoute
#   istio          Istio's Gateway API Gateway, an HTTPRoute
#   haproxy        the HAProxy Kubernetes Ingress Controller, an Ingress
#   raw-envoy      examples/raw-envoy (Envoy with the engine next to it),
#                  its Ingress (only the policy reads it)
#   standalone     the engine's reverse proxy in front of the app, in the
#                  app's pod (no operator: block mode, the CRS's defaults)
#
# Each proxy runs one replica, in its own namespace (bt-<proxy>; raw-envoy:
# raw-envoy, the sample's), which hack/kind/operator.sh makes a proxy
# namespace. Next to the protected route, an unprotected one to the same app
# (another host; raw Envoy: a virtual host with the filter off; standalone:
# the app's own Service) is the baseline of the latency runs.
#
# The app is nginx: every answer carries X-Soak-App (STACK_APP_HEADER),
# so an answer the app gave tells itself from one the proxy or the engine
# gave; /small.html (about 1 KB) and /page.html (about 15 KB) are HTML
# pages (response inspection reads their bodies); any other path answers
# 200 "ok" to any method.
#
# A stack_pre_policy PROXY function, if the sourcing script defines one, runs
# before each policy is applied. Needs, from the sourcing script: the repository root as the working
# directory, hack/versions.env sourced, CLUSTER, KUBECTL, HELM, IMAGE (the
# engine image, loaded by make kind-operator) and work (a temporary
# directory), and hack/kind/lib.sh for ok and fail. stacks_cleanup removes
# what stacks_up created, unless KEEP=1.

# shellcheck disable=SC2034 # read by the sourcing scripts
STACK_PROXIES=(traefik envoy-gateway istio haproxy raw-envoy standalone)
STACK_APP_HEADER=X-Soak-App
# The policies' extra spec lines (indented YAML under spec), set by the
# sourcing script before stacks_up or stack_policy.
STACK_POLICY_SPEC=${STACK_POLICY_SPEC:-}
# The engine's flags of the standalone proxy, besides its upstream.
STACK_STANDALONE_ARGS=${STACK_STANDALONE_ARGS:---mode=block}
# The HAProxy controller's image, as hack/kind/haproxy-e2e.sh's.
STACK_HAPROXY_IMAGE_TAG=3.2.19
STACK_ISTIO_REPO=https://blob.istio.io/istio-release/charts

stack_ns() {
  case $1 in
  raw-envoy) echo raw-envoy ;;
  *) echo "bt-$1" ;;
  esac
}
stack_host() {
  case $1 in
  raw-envoy) echo app.example.com ;;
  *) echo "$1.bt.example.com" ;;
  esac
}
stack_open_host() { echo "open.$(stack_host "$1")"; }
# stack_pods PROXY: the label selector of the proxy's pods (in stack_ns).
stack_pods() {
  case $1 in
  traefik) echo app.kubernetes.io/name=traefik ;;
  envoy-gateway) echo gateway.envoyproxy.io/owning-gateway-name=bt ;;
  istio) echo gateway.networking.k8s.io/gateway-name=bt ;;
  haproxy) echo app.kubernetes.io/name=kubernetes-ingress ;;
  raw-envoy) echo app.kubernetes.io/name=raw-envoy ;;
  standalone) echo app=bt-standalone ;;
  esac
}
# stack_has_operator PROXY: its engines take their policy from the
# operator, whose status reports it.
stack_has_operator() { [[ $1 != standalone ]]; }
# stack_claims PROXY: the condition by which the policy claims its
# protection: Ready, or Enforced for raw Envoy, which the operator doesn't
# wire (Programmed is False, ControllerUnsupported).
stack_claims() { if [[ $1 == raw-envoy ]]; then echo Enforced; else echo Ready; fi; }
# stack_responses PROXY: whether its policy can inspect responses
# (Traefik's forward-auth never sends them).
stack_responses() { [[ $1 != traefik ]]; }

stacks_node_ip() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CLUSTER-control-plane"; }

# stack_url PROXY [open]: the base URL of the proxy's (or, with open, the
# baseline's) NodePort.
stack_url() {
  local ns svc port
  ns=$(stack_ns "$1")
  case $1 in
  traefik) svc=bt-traefik port=80 ;;
  envoy-gateway) svc=$("${KUBECTL[@]}" -n "$ns" get svc -l "$(stack_pods envoy-gateway),gateway.envoyproxy.io/owning-gateway-namespace=$ns" -o jsonpath='{.items[0].metadata.name}') port=80 ;;
  istio) svc=bt-istio port=80 ;;
  haproxy) svc=haproxy-kubernetes-ingress port=80 ;;
  raw-envoy) svc=envoy-nodeport port=80 ;;
  standalone)
    svc=proxy port=80
    if [[ ${2:-} == open ]]; then svc=app; fi
    ;;
  esac
  local node_port
  node_port=$("${KUBECTL[@]}" -n "$ns" get svc "$svc" -o jsonpath="{.spec.ports[?(@.port==$port)].nodePort}")
  echo "http://$(stacks_node_ip):$node_port"
}

# stack_policy PROXY [SPEC]: applies the proxy's policy, "app" in its
# namespace, with STACK_POLICY_SPEC (or SPEC) added.
stack_policy() {
  local p=$1 ns target
  ns=$(stack_ns "$p")
  case $p in
  envoy-gateway | istio) target='{group: gateway.networking.k8s.io, kind: HTTPRoute, name: app}' ;;
  *) target='{kind: Ingress, name: app}' ;;
  esac
  local spec=${2-$STACK_POLICY_SPEC}
  for _ in $(seq 60); do
    if "${KUBECTL[@]}" apply --server-side --force-conflicts -f - >/dev/null 2>&1 <<YAML; then return 0; fi
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: app, namespace: $ns}
spec:
  targetRefs: [$target]
  mode: Block
  timeout: 1s
$spec
YAML
    # The webhook may not answer yet (just after the operator restarts).
    sleep 1
  done
  echo "stack_policy $p: not applied" >&2
  return 1
}

# stack_condition PROXY TYPE FIELD: a condition of the proxy's policy.
stack_condition() {
  "${KUBECTL[@]}" -n "$(stack_ns "$1")" get wafpolicy app -o jsonpath="{.status.conditions[?(@.type==\"$2\")].$3}" 2>/dev/null
}
# stack_claimed PROXY: the policy claims its protection, for its current
# generation.
stack_claimed() {
  local s
  s=$("${KUBECTL[@]}" -n "$(stack_ns "$1")" get wafpolicy app -o json 2>/dev/null) || return 1
  jq -e --arg c "$(stack_claims "$1")" '.metadata.generation as $g |
    any(.status.conditions[]?; .type == $c and .status == "True" and .observedGeneration == $g)' <<<"$s" >/dev/null
}

# stack_code PROXY PATH [open]: the status the proxy answers for PATH, and
# "app" when the app answered it: "200 app", "403 -".
stack_code() {
  local host
  host=$(stack_host "$1")
  [[ ${3:-} == open ]] && host=$(stack_open_host "$1")
  curl -s -o /dev/null -m 5 -D - -H "Host: $host" "$(stack_url "$1" "${3:-}")$2" 2>/dev/null |
    awk -v h="$(tr '[:upper:]' '[:lower:]' <<<"$STACK_APP_HEADER")" '
      NR == 1 { code = $2 } tolower($1) == h ":" { app = 1 }
      END { printf "%s %s\n", (code ? code : "000"), (app ? "app" : "-") }'
}
stack_serves() { [[ $(stack_code "$1" /products?id=42 "${2:-}") == "200 app" ]]; }
stack_blocks() { [[ $(stack_code "$1" '/?id=1%27%20OR%20%271%27%3D%271') == "403 -" ]]; }

# stacks_app NAMESPACE: the app, its pages and its Service.
stacks_app() {
  local ns=$1 small page
  small=$(printf '<p>Order %04d: shipped.</p>\n' $(seq 1 30))
  page=$(printf '<tr><td>Product %04d</td><td>A sturdy oak table, 120 x 80 cm.</td><td>249.00</td></tr>\n' $(seq 1 180))
  "${KUBECTL[@]}" -n "$ns" create configmap app-pages --from-literal=small.html="<html><body>$small</body></html>" \
    --from-literal=page.html="<html><body><table>$page</table></body></html>" --dry-run=client -o yaml |
    "${KUBECTL[@]}" apply -f - >/dev/null
  "${KUBECTL[@]}" -n "$ns" create configmap app-conf --dry-run=client -o yaml --from-literal=default.conf="$(
    cat <<CONF
server {
  listen 8080;
  add_header $STACK_APP_HEADER 1 always;
  location = /small.html { root /pages; }
  location = /page.html { root /pages; }
  location / { default_type text/plain; return 200 "ok\n"; }
}
CONF
  )" | "${KUBECTL[@]}" apply -f - >/dev/null
}
# The app's container and volumes, for a pod spec (indented 6 and 6).
stacks_app_container() {
  cat <<YAML
        - name: app
          image: nginx:1.27-alpine
          ports: [{name: http, containerPort: 8080}]
          readinessProbe: {httpGet: {path: /small.html, port: 8080}}
          volumeMounts:
            - {name: app-pages, mountPath: /pages}
            - {name: app-conf, mountPath: /etc/nginx/conf.d}
YAML
}
stacks_app_volumes() {
  cat <<YAML
        - {name: app-pages, configMap: {name: app-pages}}
        - {name: app-conf, configMap: {name: app-conf}}
YAML
}
stacks_app_deployment() {
  local ns=$1
  "${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: $ns}
spec:
  selector: {matchLabels: {app: bt-app}}
  template:
    metadata: {labels: {app: bt-app}}
    spec:
      containers:
$(stacks_app_container)
      volumes:
$(stacks_app_volumes)
---
apiVersion: v1
kind: Service
metadata: {name: app, namespace: $ns}
spec:
  selector: {app: bt-app}
  ports: [{name: http, port: 80, targetPort: http}]
YAML
}

stacks_gateway_api_installed=false
stacks_eg_crds_installed=false
stacks_istio_installed=false
stacks_crs_created=false
stacks_created=()

stacks_gateway_api() {
  if ! "${KUBECTL[@]}" get crd gateways.gateway.networking.k8s.io >/dev/null 2>&1; then
    curl -fsSL "https://github.com/kubernetes-sigs/gateway-api/releases/download/$GATEWAY_API_VERSION/standard-install.yaml" >"$work/gateway-api.yaml"
    stacks_gateway_api_installed=true
    "${KUBECTL[@]}" apply --server-side --force-conflicts -f "$work/gateway-api.yaml" >/dev/null
  fi
}

# stack_up PROXY: installs the proxy, the app and the routes, and applies
# the policy (stack_wait waits for them).
stack_up() {
  local p=$1 ns
  ns=$(stack_ns "$p")
  [[ " ${stacks_created[*]} " == *" $p "* ]] || stacks_created+=("$p")
  echo "== $p"
  "${KUBECTL[@]}" create namespace "$ns" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
  stacks_app "$ns"
  case $p in
  traefik)
    stacks_app_deployment "$ns"
    cat >"$work/traefik-values.yaml" <<YAML
ingressClass: {enabled: true, isDefaultClass: false, name: bt-traefik}
providers:
  kubernetesIngress: {ingressClass: bt-traefik}
  # The operator's Middleware is a Traefik CRD.
  kubernetesCRD: {ingressClass: bt-traefik}
  kubernetesGateway: {enabled: false}
gateway: {enabled: false}
ports:
  websecure: {expose: {default: false}}
service: {spec: {type: NodePort}}
YAML
    "${HELM[@]}" upgrade --install bt-traefik traefik --repo https://traefik.github.io/charts --version "$TRAEFIK_CHART_VERSION" \
      --namespace "$ns" --values "$work/traefik-values.yaml" --wait --timeout 5m >/dev/null
    stacks_ingresses "$ns" bt-traefik
    ;;
  envoy-gateway)
    stacks_gateway_api
    helm template eg-crds oci://docker.io/envoyproxy/gateway-crds-helm --version "$ENVOY_GATEWAY_VERSION" \
      --set crds.gatewayAPI.enabled=false --set crds.envoyGateway.enabled=true >"$work/eg-crds.yaml" 2>/dev/null
    if ! "${KUBECTL[@]}" get crd envoyproxies.gateway.envoyproxy.io >/dev/null 2>&1; then stacks_eg_crds_installed=true; fi
    "${KUBECTL[@]}" apply --server-side --force-conflicts -f "$work/eg-crds.yaml" >/dev/null
    # The Backend API is off by default; the engine's socket is a Backend.
    "${HELM[@]}" upgrade --install eg oci://docker.io/envoyproxy/gateway-helm --version "$ENVOY_GATEWAY_VERSION" --skip-crds \
      --set crds.enabled=false --namespace "$ns" --set config.envoyGateway.extensionApis.enableBackend=true \
      --wait --timeout 5m >/dev/null
    stacks_app_deployment "$ns"
    "${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: bt-envoy-gateway}
spec:
  controllerName: gateway.envoyproxy.io/gatewayclass-controller
YAML
    stacks_gateway "$ns" bt-envoy-gateway ""
    ;;
  istio)
    stacks_gateway_api
    if ! "${KUBECTL[@]}" -n istio-system get deployment/istiod >/dev/null 2>&1; then
      stacks_istio_installed=true
      "${HELM[@]}" upgrade --install istio-base base --repo "$STACK_ISTIO_REPO" --version "$ISTIO_VERSION" \
        --namespace istio-system --create-namespace --wait --timeout 5m >/dev/null
      "${HELM[@]}" upgrade --install istiod istiod --repo "$STACK_ISTIO_REPO" --version "$ISTIO_VERSION" \
        --namespace istio-system --set pilot.resources.requests.cpu=100m --set pilot.resources.requests.memory=256Mi \
        --wait --timeout 5m >/dev/null
    fi
    stacks_app_deployment "$ns"
    # No load balancer on kind: a NodePort Service.
    stacks_gateway "$ns" istio "annotations: {networking.istio.io/service-type: NodePort}"
    ;;
  haproxy)
    stacks_app_deployment "$ns"
    "${HELM[@]}" upgrade --install haproxy kubernetes-ingress --repo https://haproxytech.github.io/helm-charts \
      --version "$HAPROXY_CHART_VERSION" --namespace "$ns" --set controller.image.tag="$STACK_HAPROXY_IMAGE_TAG" \
      --set controller.replicaCount=1 --set controller.ingressClass=bt-haproxy \
      --set controller.ingressClassResource.name=bt-haproxy --set controller.service.type=NodePort \
      --wait --timeout 5m >/dev/null
    stacks_ingresses "$ns" bt-haproxy
    ;;
  raw-envoy) stacks_raw_envoy ;;
  standalone) stacks_standalone ;;
  esac
  # The sourcing script's hook, e.g. for the objects the policy names.
  if declare -F stack_pre_policy >/dev/null; then stack_pre_policy "$p"; fi
  if stack_has_operator "$p"; then stack_policy "$p"; fi
}

# stacks_ingresses NAMESPACE CLASS: the protected Ingress and the open one.
stacks_ingresses() {
  local ns=$1 class=$2 p=${1#bt-}
  "${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: app, namespace: $ns}
spec:
  ingressClassName: $class
  rules:
    - host: $(stack_host "$p")
      http: {paths: [{path: /, pathType: Prefix, backend: {service: {name: app, port: {number: 80}}}}]}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: open, namespace: $ns}
spec:
  ingressClassName: $class
  rules:
    - host: $(stack_open_host "$p")
      http: {paths: [{path: /, pathType: Prefix, backend: {service: {name: app, port: {number: 80}}}}]}
YAML
}

# stacks_gateway NAMESPACE CLASS METADATA: Gateway "bt", the protected
# HTTPRoute and the open one.
stacks_gateway() {
  local ns=$1 class=$2 meta=$3 p=${1#bt-}
  "${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: bt, namespace: $ns${meta:+, $meta}}
spec:
  gatewayClassName: $class
  listeners: [{name: http, protocol: HTTP, port: 80}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: app, namespace: $ns}
spec:
  parentRefs: [{name: bt}]
  hostnames: [$(stack_host "$p")]
  rules: [{backendRefs: [{name: app, port: 80}]}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: open, namespace: $ns}
spec:
  parentRefs: [{name: bt}]
  hostnames: [$(stack_open_host "$p")]
  rules: [{backendRefs: [{name: app, port: 80}]}]
YAML
}

# stacks_envoy_yaml [responses]: examples/raw-envoy's envoy.yaml with a
# virtual host for the open host, the filter off there; with responses,
# Envoy sends the responses too (docs/raw-envoy.md, Responses).
stacks_envoy_yaml() {
  local open
  open=$(stack_open_host raw-envoy)
  awk -v open="$open" -v responses="${1:-}" '
    /^                  virtual_hosts:$/ {
      print
      print "                    - name: open"
      print "                      domains: [\"" open "\"]"
      print "                      routes:"
      print "                        - match: {prefix: /}"
      print "                          route: {cluster: app}"
      print "                          typed_per_filter_config:"
      print "                            envoy.filters.http.ext_proc:"
      print "                              \"@type\": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExtProcPerRoute"
      print "                              disabled: true"
      next
    }
    responses != "" && /response_header_mode: SKIP/ { sub(/SKIP/, "SEND") }
    responses != "" && /response_body_mode: NONE/ {
      sub(/NONE/, "BUFFERED_PARTIAL"); print
      match($0, /^ */); ind = substr($0, 1, RLENGTH - 2)
      next_ind = ind
      pending = 1
      next
    }
    pending && /^ *response_trailer_mode:/ {
      print
      print next_ind "allow_mode_override: true"
      pending = 0
      next
    }
    { print }
  ' examples/raw-envoy/envoy.yaml
}

# stacks_raw_envoy: examples/raw-envoy as hack/kind/raw-envoy-e2e.sh applies
# it, with one Envoy, the app, the open virtual host and a NodePort Service.
stacks_raw_envoy() {
  local ns=raw-envoy dir=$work/raw-envoy
  mkdir -p "$dir"
  stacks_envoy_yaml "${1:-}" >"$dir/envoy.yaml"
  cat >"$dir/app.yaml" <<YAML
- op: replace
  path: /spec/template/spec/containers
  value:
    - name: app
      image: nginx:1.27-alpine
      ports: [{name: http, containerPort: 8080}]
      readinessProbe: {httpGet: {path: /small.html, port: 8080}}
      volumeMounts:
        - {name: app-pages, mountPath: /pages}
        - {name: app-conf, mountPath: /etc/nginx/conf.d}
- op: add
  path: /spec/template/spec/volumes
  value:
    - {name: app-pages, configMap: {name: app-pages}}
    - {name: app-conf, configMap: {name: app-conf}}
YAML
  cat >"$dir/nodeport.yaml" <<YAML
apiVersion: v1
kind: Service
metadata: {name: envoy-nodeport, namespace: $ns}
spec:
  type: NodePort
  selector: {app.kubernetes.io/name: raw-envoy}
  ports: [{name: http, port: 80, targetPort: http}]
YAML
  cat >"$dir/kustomization.yaml" <<YAML
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: [$(realpath --relative-to="$dir" examples/raw-envoy), nodeport.yaml]
images: [{name: ghcr.io/inkwall-dev/inkwall-engine, newName: ${IMAGE%:*}, newTag: ${IMAGE##*:}}]
replicas: [{name: envoy, count: 1}]
configMapGenerator:
  - {name: envoy-config, namespace: $ns, behavior: replace, files: [envoy.yaml]}
patches:
  - {path: app.yaml, target: {kind: Deployment, name: app}}
YAML
  # The trust ConfigMap, as the guide creates it.
  key() { "${KUBECTL[@]}" -n inkwall-system get secret inkwall-bundle-signing-key -o jsonpath="{.data.$1}" | base64 -d; }
  "${KUBECTL[@]}" -n inkwall-system get secret inkwall-operator-webhook-tls -o jsonpath='{.data.ca\.crt}' | base64 -d >"$dir/ca.crt"
  key 'trusted-keys\.pub' >"$dir/trusted-keys.pub"
  if [[ ! -s $dir/trusted-keys.pub ]]; then key 'ed25519\.pub' >"$dir/trusted-keys.pub"; fi
  "${KUBECTL[@]}" -n "$ns" create configmap inkwall-trust --from-file="$dir/ca.crt" --from-file="$dir/trusted-keys.pub" \
    --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
  "${KUBECTL[@]}" apply -k "$dir" >/dev/null
  "${KUBECTL[@]}" -n "$ns" rollout status deployment/envoy --timeout=180s >/dev/null
  "${KUBECTL[@]}" -n "$ns" rollout status deployment/app --timeout=120s >/dev/null
}

# stacks_standalone: the engine's reverse proxy and the app in one pod,
# Services for both.
stacks_standalone() {
  local ns=bt-standalone args="" a
  for a in $STACK_STANDALONE_ARGS; do args+="            - $a"$'\n'; done
  "${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: standalone, namespace: $ns}
spec:
  selector: {matchLabels: {app: bt-standalone}}
  template:
    metadata: {labels: {app: bt-standalone}}
    spec:
      containers:
$(stacks_app_container)
        - name: inkwall-engine
          image: $IMAGE
          imagePullPolicy: Never
          args:
            - proxy
            - --upstream=http://127.0.0.1:8080
${args}          ports: [{name: proxy, containerPort: 8480}, {name: inkwall-admin, containerPort: 9480}]
          readinessProbe: {httpGet: {path: /readyz, port: inkwall-admin}}
          volumeMounts: [{name: tmp, mountPath: /tmp}]
          securityContext:
            runAsNonRoot: true
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: {drop: [ALL]}
            seccompProfile: {type: RuntimeDefault}
      volumes:
$(stacks_app_volumes)
        - {name: tmp, emptyDir: {sizeLimit: 16Mi}}
---
apiVersion: v1
kind: Service
metadata: {name: proxy, namespace: $ns}
spec:
  type: NodePort
  selector: {app: bt-standalone}
  ports: [{name: http, port: 80, targetPort: proxy}]
---
apiVersion: v1
kind: Service
metadata: {name: app, namespace: $ns}
spec:
  type: NodePort
  selector: {app: bt-standalone}
  ports: [{name: http, port: 80, targetPort: http}]
YAML
  "${KUBECTL[@]}" -n "$ns" rollout status deployment/standalone --timeout=180s >/dev/null
}

# stack_injected PROXY: every running pod of the proxy has the engine.
stack_injected() {
  local p
  p=$("${KUBECTL[@]}" -n "$(stack_ns "$1")" get pods -l "$(stack_pods "$1")" \
    -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}|{.status.phase}|{.spec.initContainers[*].name} {.spec.containers[*].name}{"\n"}{end}' |
    grep '^|Running|') && ! grep -qv inkwall-engine <<<"$p"
}

# stack_wait PROXY: the proxy's pods have the engine, the policy claims its
# protection, the app answers through it and an attack is blocked.
stack_wait() {
  local p=$1
  EVENTUALLY_TRIES=${STACK_WAIT_TRIES:-360} eventually "$p: the proxy's pods have the engine" stack_injected "$p"
  if stack_has_operator "$p"; then
    EVENTUALLY_TRIES=${STACK_WAIT_TRIES:-360} eventually "$p: the policy is $(stack_claims "$p")" stack_claimed "$p"
  fi
  EVENTUALLY_TRIES=${STACK_WAIT_TRIES:-360} eventually "$p: the app answers through the proxy" stack_serves "$p"
  EVENTUALLY_TRIES=${STACK_WAIT_TRIES:-360} eventually "$p: an attack is blocked" stack_blocks "$p"
}

# stacks_up PROXY...: every stack, then waits for each.
stacks_up() {
  local p
  if ! "${KUBECTL[@]}" get clusterwafruleset owasp-crs-v4 >/dev/null 2>&1; then
    stacks_crs_created=true
    "${KUBECTL[@]}" apply --server-side -f operator/config/samples/clusterwafruleset.yaml >/dev/null
  fi
  for p in "$@"; do stack_up "$p"; done
  for p in "$@"; do stack_wait "$p"; done
}

# stack_running_pods PROXY: the running pods of the proxy, one per line.
stack_running_pods() {
  "${KUBECTL[@]}" -n "$(stack_ns "$1")" get pods -l "$(stack_pods "$1")" \
    -o jsonpath='{range .items[*]}{.metadata.name}|{.metadata.deletionTimestamp}|{.status.phase}{"\n"}{end}' |
    awk -F'|' '$2 == "" && $3 == "Running" { print $1 }'
}

# stack_restart PROXY: restarts the proxy's pods (and waits), as a change of
# their configuration needs.
stack_restart() {
  local ns kind name
  ns=$(stack_ns "$1")
  case $1 in
  traefik) kind=deployment name=bt-traefik ;;
  envoy-gateway) kind=deployment name=$("${KUBECTL[@]}" -n "$ns" get deployment -l "$(stack_pods envoy-gateway)" -o jsonpath='{.items[0].metadata.name}') ;;
  istio) kind=deployment name=bt-istio ;;
  haproxy) kind=deployment name=haproxy-kubernetes-ingress ;;
  raw-envoy) kind=deployment name=envoy ;;
  standalone) kind=deployment name=standalone ;;
  esac
  "${KUBECTL[@]}" -n "$ns" rollout restart "$kind/$name" >/dev/null
  "${KUBECTL[@]}" -n "$ns" rollout status "$kind/$name" --timeout=300s >/dev/null
}

# stack_down PROXY: removes the proxy's stack (its namespace, its proxy's
# release), unless KEEP=1.
stack_down() {
  local p=$1 ns rest=()
  [[ ${KEEP:-} != 1 ]] || return 0
  ns=$(stack_ns "$p")
  case $p in
  traefik) "${HELM[@]}" -n "$ns" uninstall bt-traefik --wait >/dev/null 2>&1 || true ;;
  envoy-gateway)
    "${KUBECTL[@]}" -n "$ns" delete gateway bt --ignore-not-found --timeout=120s >/dev/null 2>&1 || true
    "${HELM[@]}" -n "$ns" uninstall eg --wait >/dev/null 2>&1 || true
    "${KUBECTL[@]}" delete gatewayclass bt-envoy-gateway --ignore-not-found >/dev/null 2>&1 || true
    ;;
  haproxy) "${HELM[@]}" -n "$ns" uninstall haproxy --wait >/dev/null 2>&1 || true ;;
  esac
  "${KUBECTL[@]}" delete namespace "$ns" --ignore-not-found --timeout=180s >/dev/null 2>&1 || true
  case $p in
  traefik | haproxy) "${KUBECTL[@]}" delete ingressclass "bt-$p" --ignore-not-found >/dev/null 2>&1 || true ;;
  esac
  for q in ${stacks_created[@]+"${stacks_created[@]}"}; do [[ $q == "$p" ]] || rest+=("$q"); done
  stacks_created=(${rest[@]+"${rest[@]}"})
}

# stacks_cleanup: removes every stack still up, and what they shared
# (Istio, the CRDs, the CRS rule set) if stacks_up installed it, unless
# KEEP=1.
stacks_cleanup() {
  [[ ${KEEP:-} != 1 ]] || return 0
  local p
  for p in ${stacks_created[@]+"${stacks_created[@]}"}; do stack_down "$p"; done
  if $stacks_istio_installed; then
    "${HELM[@]}" -n istio-system uninstall istiod --wait >/dev/null 2>&1 || true
    "${HELM[@]}" -n istio-system uninstall istio-base --wait >/dev/null 2>&1 || true
    "${KUBECTL[@]}" delete namespace istio-system --ignore-not-found --timeout=120s >/dev/null 2>&1 || true
  fi
  if $stacks_eg_crds_installed; then "${KUBECTL[@]}" delete -f "$work/eg-crds.yaml" --ignore-not-found >/dev/null 2>&1 || true; fi
  if $stacks_gateway_api_installed; then "${KUBECTL[@]}" delete -f "$work/gateway-api.yaml" --ignore-not-found >/dev/null 2>&1 || true; fi
  if $stacks_crs_created; then "${KUBECTL[@]}" delete clusterwafruleset owasp-crs-v4 --ignore-not-found >/dev/null 2>&1 || true; fi
}
