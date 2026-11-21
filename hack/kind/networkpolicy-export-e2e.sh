# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# shellcheck disable=SC2154 # work: the sourcing script's

# Export to SIEMs under the chart's egress NetworkPolicy (design 0010 §7,
# §9), sourced by hack/kind/networkpolicy-e2e.sh once its proxy pod's engine
# is connected: an export sink in a namespace of its own gets nothing while
# the egress policy doesn't list it, and the events once it is listed in
# networkPolicy.egress.extra (the buffer kept them). The events come from
# an attack sent to the proxy pod's engine as Traefik's ForwardAuth would
# send it. Uses networkpolicy-e2e.sh's CLUSTER, NAMESPACE, PROXY_NS,
# KUBECTL, HELM, CHART, ok and fail.

echo "== export: a sink only once listed in networkPolicy.egress.extra"
SINK_NS=inkwall-np-sink
docker build -q -f hack/kind/eventsink.Dockerfile -t inkwall-eventsink:dev . >/dev/null
kind load docker-image inkwall-eventsink:dev --name "$CLUSTER" >/dev/null
"${KUBECTL[@]}" create namespace "$SINK_NS" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
"${KUBECTL[@]}" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: eventsink, namespace: $SINK_NS}
spec:
  selector: {matchLabels: {app: eventsink}}
  template:
    metadata: {labels: {app: eventsink}}
    spec:
      containers:
        - name: sink
          image: inkwall-eventsink:dev
          imagePullPolicy: Never
          args: ["--dns-name=eventsink.$SINK_NS.svc"]
          ports: [{containerPort: 8080}, {containerPort: 8081}]
---
apiVersion: v1
kind: Service
metadata: {name: eventsink, namespace: $SINK_NS}
spec:
  selector: {app: eventsink}
  ports: [{name: http, port: 8080}, {name: admin, port: 8081}]
---
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata: {name: inkwall-np-traefik}
spec: {controller: traefik.io/ingress-controller}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: np-app, namespace: $PROXY_NS}
spec:
  ingressClassName: inkwall-np-traefik
  rules:
    - host: np.e2e.example.com
      http:
        paths: [{path: /, pathType: Prefix, backend: {service: {name: np-app, port: {number: 80}}}}]
---
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: np-app, namespace: $PROXY_NS}
spec:
  targetRefs: [{kind: Ingress, name: np-app}]
  mode: Block
YAML
"${KUBECTL[@]}" -n "$SINK_NS" rollout status deployment/eventsink --timeout=120s >/dev/null
np_sink_requests() {
  "${KUBECTL[@]}" get --raw "/api/v1/namespaces/$SINK_NS/services/eventsink:admin/proxy/stats" 2>/dev/null |
    jq '[.requests[]? | select(.path == "/np")] | length' || echo 0
}
if ! "${KUBECTL[@]}" get inkwallconfig default >/dev/null 2>&1; then
  printf 'apiVersion: waf.inkwall.dev/v1alpha1\nkind: InkwallConfig\nmetadata: {name: default}\nspec: {}\n' | "${KUBECTL[@]}" apply -f - >/dev/null
fi
"${KUBECTL[@]}" patch inkwallconfig default --type=merge -p "{\"spec\":{\"events\":{\"export\":{\"sinks\":[
  {\"name\":\"np\",\"json\":{\"url\":\"http://eventsink.$SINK_NS.svc:8080/np\"},\"insecure\":true,\"batch\":{\"maxDelay\":\"1s\"}}]}}}}" >/dev/null

# np_attack: a ForwardAuth subrequest for an attack on the policy's host,
# to the proxy pod's engine (127.0.0.1:9001 in its pod); its status.
np_port=19001
"${KUBECTL[@]}" -n "$PROXY_NS" port-forward pod/proxy "$np_port:9001" >/dev/null 2>&1 &
np_pf=$!
np_attack() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$np_port/v1/forward-auth" \
    -H 'X-Forwarded-Method: GET' -H 'X-Forwarded-Proto: http' -H 'X-Forwarded-Host: np.e2e.example.com' \
    -H "X-Forwarded-Uri: /export?id=1%27%20OR%20%271%27%3D%271" -H 'X-Forwarded-For: 203.0.113.9' || true
}
np_denied() { [[ $(np_attack) == 403 ]]; }
denied=false
for _ in $(seq 60); do
  if np_denied; then
    denied=true
    break
  fi
  sleep 2
done
if $denied; then
  ok "the proxy pod's engine denies an attack (an event)"
else
  fail "the proxy pod's engine doesn't deny the attack: $(np_attack)"
fi
# Blocked: the egress policy lists DNS and the API server, not the sink.
sleep 20
np_attack >/dev/null
sleep 10
if [[ $(np_sink_requests) == 0 ]]; then
  ok "the sink gets nothing in 30 s (30 times the batch delay) while the egress policy doesn't list it"
else
  fail "the sink got $(np_sink_requests) requests through the egress policy"
fi
cat >"$work/np-sink.yaml" <<YAML
networkPolicy:
  egress:
    extra:
      - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: $SINK_NS}}}]
        ports: [{port: 8080}]
YAML
"${HELM[@]}" upgrade inkwall "$CHART" --namespace "$NAMESPACE" --reuse-values -f "$work/np-sink.yaml" >/dev/null
got=0
for _ in $(seq 60); do
  got=$(np_sink_requests)
  [[ ${got:-0} -ge 1 ]] && break
  sleep 3
done
if [[ ${got:-0} -ge 1 ]]; then
  ok "listed in networkPolicy.egress.extra, the sink gets the buffered events"
else
  fail "the sink gets nothing once listed in networkPolicy.egress.extra"
  "${KUBECTL[@]}" get inkwallconfig default -o jsonpath='{.status.conditions[?(@.type=="EventsExported")]}' || true
fi
kill "$np_pf" 2>/dev/null || true
"${KUBECTL[@]}" patch inkwallconfig default --type=json -p '[{"op":"remove","path":"/spec/events/export"}]' >/dev/null || true
"${KUBECTL[@]}" -n "$PROXY_NS" delete wafpolicy np-app --ignore-not-found >/dev/null || true
"${KUBECTL[@]}" -n "$PROXY_NS" delete ingress np-app --ignore-not-found >/dev/null || true
"${KUBECTL[@]}" delete ingressclass inkwall-np-traefik --ignore-not-found >/dev/null || true
"${KUBECTL[@]}" delete namespace "$SINK_NS" --wait=false >/dev/null || true
