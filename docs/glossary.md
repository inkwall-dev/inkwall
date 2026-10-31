# Glossary

Inkwall's own terms, and the outside concepts the docs use, each with a one-line definition. Each
outside concept links to an authoritative source. The other docs link a concept to its source the
first time they mention it.

## Contents

- [Inkwall terms](#inkwall-terms)
- [Outside concepts](#outside-concepts)

## Inkwall terms

- <a id="adapter"></a>**Adapter**: An engine listener that speaks one proxy protocol (forward-auth,
  `/v1/check`, reverse proxy, ...), plus the proxy-side configuration or plugin that calls it. See
  [0006](design/0006-adapter-protocols.md).
- <a id="bundle"></a>**Bundle**: A policy bundle: the immutable, versioned, signed snapshot of all
  of a cluster's policies, built by the operator and enforced by every engine. See [0002
  §4.3](design/0002-system-architecture.md#43-bundle-format).
- <a id="bundle-mode"></a>**Bundle mode**: An engine run by an operator, which gets its policies
  from the operator's bundles rather than from flags.
- <a id="cluster-mode"></a>**Cluster mode**: `InkwallConfig.spec.mode`. **Standalone** (the
  default): no control plane. **GitOps**: policies are [CRDs](#crd) (from [Git](#gitops)), mirrored
  to the control plane. **Managed**: the control plane owns the policies, and the operator writes
  them as CRDs. See [connecting to a control plane](control-plane.md#modes).
- <a id="control-plane"></a>**Control plane**: The optional hosted service: API, UI, policy store,
  analytics. A separate product, not in this repository.
- <a id="enforcement-mode"></a>**Enforcement mode**: Per policy. **Detect mode** logs what it would
  block. **Block mode** rejects it.
- <a id="engine"></a>**Engine**: `inkwall-engine`: the process that inspects requests and returns
  verdicts.
- <a id="failure-mode"></a>**Failure mode**: What happens to a request that can't be inspected: the
  engine **fails open** (lets it through) or **fails closed** (rejects it with 503). By default it
  fails closed in block mode and open in detect mode. It applies only while the engine answers:
  Traefik answers 500 when it can't reach the engine, in both modes.
- <a id="injection"></a>**Injection**: Adding the engine to proxy [pods](#pod) as a
  [sidecar](#sidecar) (a container in the same pod).
- <a id="inkwallconfig"></a>**InkwallConfig**: The cluster-wide singleton, named `default`, that
  sets the cluster mode, the engine image, the integrations, the control plane and signing key
  rotation.
- <a id="inkwallctl"></a>**inkwallctl**: Inkwall's command-line tool: `inkwallctl test` checks
  rules, policies and bundles offline ([testing policies](testing-policies.md)); `inkwallctl bench`
  benchmarks the engine.
- <a id="integration"></a>**Integration**: The operator's support for one proxy: finding its pods,
  injection and wiring. Discovery reports each proxy controller in the cluster as `Full`,
  `Partial` or `Unsupported` in `InkwallConfig.status.proxies`.
- <a id="leader"></a>**Leader**: The operator replica that holds the [leader-election
  lease](#leader-election). It builds bundles, wires routes and talks to the control plane.
- <a id="operator"></a>**Operator**: `inkwall-operator`: reconciles the CRDs, injects engines, wires
  proxies and distributes bundles. See [0004](design/0004-operator.md).
- <a id="policy"></a>**Policy**: A `WAFPolicy` object: mode, rule sets, limits and exclusions for a
  set of routes.
- <a id="policy-snapshot"></a>**Policy snapshot**: A `PolicySnapshot`: the policy objects the
  control plane sends in Managed mode. Not a bundle.
- <a id="proxy"></a>**Proxy**: The [ingress controller](#ingress-controller)'s data-plane process
  ([Traefik](#traefik), [Envoy](#envoy), ...) that asks the engine for a verdict. "Ingress
  controller" means the Kubernetes product as a whole.
- <a id="rule-set"></a>**Rule set**: A `WAFRuleSet` (namespaced) or `ClusterWAFRuleSet` object:
  rules a policy uses, from the built-in [CRS](#crs), inline [SecLang](#seclang) or a
  [ConfigMap](#configmap).
- <a id="standalone"></a>**Standalone**: On its own, "Standalone" always means the cluster mode with
  no control plane. The engine without an operator is the **standalone [reverse
  proxy](#reverse-proxy)** (`inkwall-engine proxy`, see [running the engine without
  Kubernetes](standalone-proxy.md)), a **standalone Deployment** behind a Service, or an engine
  **configured by flags**.
- <a id="tier"></a>**Tier**: One stage of the engine's request pipeline, cheapest first: T0 route
  and skip list, T1 IP lists and rate limits, T2 header and URI rules, T3 body rules, T4 response
  inspection. See [0001
  §4](design/0001-performance-first-architecture.md#4-request-pipeline-tiered-cheapest-first).
- <a id="verdict"></a>**Verdict**: The engine's answer: allow, deny (or log, in detect mode), plus
  metadata.
- <a id="wiring"></a>**Wiring**: Configuring the proxy to call the engine on protected routes. For
  Traefik: the `inkwall-waf` [Middleware](#middleware) and the references to it.

## Outside concepts

[A](#a) · [B](#b) · [C](#c) · [D](#d) · [E](#e) · [F](#f) · [G](#g) · [H](#h) · [I](#i) · [J](#j) · [K](#k) · [L](#l) · [M](#m) · [N](#n) · [O](#o) · [P](#p) · [R](#r) · [S](#s) · [T](#t) · [U](#u) · [W](#w) · [X](#x) · [Y](#y)

### A

- <a id="abstract-syntax-tree"></a>**Abstract syntax tree (AST)**: A tree that represents the
  structure of parsed source code; Inkwall's planned rule engine parses SecLang into one.
  ([Wikipedia](https://en.wikipedia.org/wiki/Abstract_syntax_tree))
- <a id="admission-webhook"></a>**Admission webhook**: An HTTP callback the Kubernetes API server
  calls before it stores an object: a validating webhook can refuse the object, a mutating one can
  change it. Its `failurePolicy` says what happens when the webhook doesn't answer. ([Kubernetes
  docs](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/))
- <a id="affinity"></a>**Affinity and anti-affinity**: Pod scheduling rules that attract pods to, or
  spread them away from, nodes or other pods. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/))
- <a id="aho-corasick"></a>**Aho-Corasick**: An algorithm that finds many literal strings in one
  pass over the input. ([Wikipedia](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm))
- <a id="annotation"></a>**Annotation**: A key-value pair in an object's metadata for tools to read;
  unlike a label, it can't be used to select objects. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/))
- <a id="anomaly-scoring"></a>**Anomaly scoring**: The CRS mode in which each matching rule adds to
  a request's score, and the request is blocked once the score reaches a threshold. ([CRS
  docs](https://coreruleset.org/docs/concepts/anomaly_scoring/))
- <a id="apache-2-0"></a>**Apache License 2.0**: The permissive open-source license of Inkwall,
  Coraza and the CRS. ([Apache Software Foundation](https://www.apache.org/licenses/LICENSE-2.0))
- <a id="argo-cd"></a>**Argo CD**: A GitOps tool that syncs Kubernetes objects from Git. An
  Application is one set of objects it deploys; `ignoreDifferences` and sync options control what it
  reports as drift. ([Argo CD docs](https://argo-cd.readthedocs.io/en/stable/))

### B

- <a id="buf"></a>**buf**: A build tool for Protocol Buffers, which Inkwall uses to generate its API
  code. ([buf docs](https://buf.build/docs/))

### C

- <a id="caddy"></a>**Caddy**: A web server and reverse proxy, extended with Go modules compiled in
  with `xcaddy`. ([Caddy docs](https://caddyserver.com/docs/))
- <a id="cel"></a>**CEL validation rules**: Rules in the Common Expression Language that a CRD's
  schema runs to validate objects, without a webhook. ([Kubernetes
  docs](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#validation-rules))
- <a id="cert-manager"></a>**cert-manager**: A Kubernetes add-on that issues and renews TLS
  certificates, as `Certificate` objects. ([cert-manager docs](https://cert-manager.io/docs/))
- <a id="cgo"></a>**cgo**: The Go tool that lets Go code call C code; it complicates builds and
  cross-compiling. ([Go docs](https://pkg.go.dev/cmd/cgo))
- <a id="cidr"></a>**CIDR**: Notation for an IP address range, such as `10.0.0.0/16`. ([RFC
  4632](https://www.rfc-editor.org/rfc/rfc4632))
- <a id="client-go"></a>**client-go**: The official Go client library for the Kubernetes API.
  ([GitHub](https://github.com/kubernetes/client-go))
- <a id="command-injection"></a>**Command injection**: An attack that gets an application to run
  operating-system commands the attacker chose (remote command execution).
  ([OWASP](https://owasp.org/www-community/attacks/Command_Injection))
- <a id="condition"></a>**Condition**: An entry in an object's `status.conditions`: a type, `True`
  or `False`, a reason and a message. Inkwall's policies report `Accepted`, `Programmed`, `Enforced`
  and `Ready`. ([Kubernetes API
  conventions](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties))
- <a id="configmap"></a>**ConfigMap**: A Kubernetes object that holds non-secret configuration data;
  pods can mount it as files. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/configuration/configmap/))
- <a id="contour"></a>**Contour**: An ingress controller built on Envoy. ([Contour
  docs](https://projectcontour.io/docs/))
- <a id="controller"></a>**Controller**: A Kubernetes control loop that watches objects and
  reconciles the cluster toward the state they describe. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/architecture/controller/))
- <a id="controller-runtime"></a>**controller-runtime**: The Go library most Kubernetes operators,
  Inkwall's included, are built on.
  ([GitHub](https://github.com/kubernetes-sigs/controller-runtime))
- <a id="conventional-commits"></a>**Conventional Commits**: A format for commit messages
  (`type(scope): subject`) that tools can turn into a changelog and a version number.
  ([conventionalcommits.org](https://www.conventionalcommits.org/en/v1.0.0/))
- <a id="coraza"></a>**Coraza**: An OWASP WAF library in Go that runs ModSecurity's rule language
  and the CRS. Inkwall's engine evaluates rules with it. ([Coraza docs](https://coraza.io/))
- <a id="cosign"></a>**cosign**: Sigstore's tool to sign and verify container images and other
  artifacts. Keyless signing ties the signature to the CI workflow's identity instead of a
  long-lived key. ([Sigstore docs](https://docs.sigstore.dev/cosign/signing/overview/))
- <a id="crd"></a>**CRD (CustomResourceDefinition)**: An object that adds a new kind, a custom
  resource, to the Kubernetes API, such as `WAFPolicy`. Conversion webhooks convert between its
  versions. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/))
- <a id="crs"></a>**CRS (OWASP Core Rule Set)**: The open-source set of generic attack detection
  rules, written in SecLang, that Inkwall's engine runs. ([CRS docs](https://coreruleset.org/))
- <a id="cve"></a>**CVE**: A public identifier for a disclosed vulnerability. ([CVE
  program](https://www.cve.org/))

### D

- <a id="daemonset"></a>**DaemonSet**: A Kubernetes workload that runs one pod on each node.
  ([Kubernetes docs](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/))
- <a id="deployment"></a>**Deployment**: A Kubernetes workload that keeps a number of identical pods
  running and rolls out changes to them. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/))
- <a id="distroless"></a>**Distroless image**: A container image with only the application and its
  runtime dependencies: no shell or package manager.
  ([GitHub](https://github.com/GoogleContainerTools/distroless))
- <a id="dry-run"></a>**Dry run (server-side)**: A request the API server runs through validation
  and admission webhooks without storing the result. With strict field validation, an unknown field
  is an error. ([Kubernetes
  docs](https://kubernetes.io/docs/reference/using-api/api-concepts/#dry-run))

### E

- <a id="e2e-framework"></a>**e2e-framework**: A Go framework for end-to-end tests against a
  Kubernetes cluster. ([GitHub](https://github.com/kubernetes-sigs/e2e-framework))
- <a id="ecdsa-p-256"></a>**ECDSA P-256**: A digital signature algorithm on the NIST P-256 elliptic
  curve; the operator's control plane identity uses it. ([NIST FIPS
  186-5](https://csrc.nist.gov/pubs/fips/186-5/final))
- <a id="ed25519"></a>**Ed25519**: A fast, compact public-key signature algorithm. The operator
  signs bundles with it. ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032))
- <a id="emptydir"></a>**emptyDir**: A pod volume that starts empty and lives as long as the pod.
  ([Kubernetes docs](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir))
- <a id="entry-point"></a>**Entry point (Traefik)**: A port Traefik listens on, such as `web` or
  `websecure`, with its own settings, such as the PROXY protocol. ([Traefik
  docs](https://doc.traefik.io/traefik/routing/entrypoints/))
- <a id="envoy"></a>**Envoy**: A high-performance proxy, used by Envoy Gateway, Istio and Contour.
  Its Go filter runs Go code in-process. ([Envoy
  docs](https://www.envoyproxy.io/docs/envoy/latest/))
- <a id="envoy-gateway"></a>**Envoy Gateway**: An implementation of the Gateway API on Envoy,
  extended with objects such as `EnvoyExtensionPolicy`. ([Envoy Gateway
  docs](https://gateway.envoyproxy.io/))
- <a id="envtest"></a>**envtest**: A test helper that runs a real Kubernetes API server and etcd,
  without nodes, for controller tests. ([kubebuilder
  book](https://book.kubebuilder.io/reference/envtest))
- <a id="etcd"></a>**etcd**: The key-value store that holds a Kubernetes cluster's state. ([etcd
  docs](https://etcd.io/docs/))
- <a id="ext-authz"></a>**ext_authz**: Envoy's external authorization filter: one call per request
  to a service that allows or denies it. ([Envoy
  docs](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter))
- <a id="ext-proc"></a>**ext_proc**: Envoy's external processing filter: a gRPC stream per request
  that can inspect and change headers and bodies, in both directions. ([Envoy
  docs](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter))
- <a id="extensionref"></a>**ExtensionRef filter**: A Gateway API `HTTPRoute` filter that calls an
  implementation's own object. Traefik's Gateway API provider runs a Traefik `Middleware` through
  one; Inkwall adds one to each rule it protects. ([Gateway API
  docs](https://gateway-api.sigs.k8s.io/reference/spec/#localobjectreference))
- <a id="externaltrafficpolicy"></a>**externalTrafficPolicy**: A Service setting. `Local` delivers
  external traffic only to pods on the node that received it, which keeps the client's source
  address. ([Kubernetes
  docs](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/#preserving-the-client-source-ip))

### F

- <a id="false-positive"></a>**False positive**: A legitimate request that a rule flags as an
  attack. Rule exclusions tune them out. ([CRS
  docs](https://coreruleset.org/docs/concepts/false_positives_tuning/))
- <a id="finalizer"></a>**Finalizer**: A key on an object that makes Kubernetes wait, before
  deleting the object, until a controller removes the key. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/))
- <a id="flame-graph"></a>**Flame graph**: A visualization of profiled stack traces that shows where
  the time goes. ([Brendan Gregg](https://www.brendangregg.com/flamegraphs.html))
- <a id="flux"></a>**Flux**: A GitOps tool for Kubernetes. Its kustomize-controller applies
  `Kustomization`s, and its helm-controller installs `HelmRelease`s. ([Flux
  docs](https://fluxcd.io/flux/))
- <a id="forwardauth"></a>**ForwardAuth**: A Traefik Middleware that asks an outside HTTP service
  whether to let each request through. Inkwall's engine is that service. ([Traefik
  docs](https://doc.traefik.io/traefik/middlewares/http/forwardauth/))
- <a id="fuzzing"></a>**Fuzzing**: Testing with generated, random inputs to find crashes and broken
  properties. Go has it built in (`go test -fuzz`). ([Go docs](https://go.dev/doc/security/fuzz/))

### G

- <a id="garbage-collection"></a>**Garbage collection (Go)**: How Go frees unused memory. `GOGC` and
  `GOMEMLIMIT` tune it. ([Go docs](https://go.dev/doc/gc-guide))
- <a id="gateway-api"></a>**Gateway API**: The Kubernetes API for routing traffic into a cluster,
  successor to `Ingress`: `GatewayClass`, `Gateway`, `HTTPRoute` and policy attachment. ([Gateway
  API docs](https://gateway-api.sigs.k8s.io/))
- <a id="ghcr"></a>**GHCR**: GitHub Container Registry, where Inkwall publishes its images and
  chart. ([GitHub
  docs](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry))
- <a id="github-actions"></a>**GitHub Actions**: GitHub's CI/CD service, which runs Inkwall's tests
  and releases. ([GitHub docs](https://docs.github.com/en/actions))
- <a id="gitops"></a>**GitOps**: Managing a system by declaring its desired state in Git and having
  an agent, such as Argo CD or Flux, apply it continuously. ([OpenGitOps](https://opengitops.dev/))
- <a id="go"></a>**Go**: The programming language Inkwall is written in. A module, defined by
  `go.mod`, is a versioned unit of Go code. ([go.dev](https://go.dev/))
- <a id="go-ftw"></a>**go-ftw**: The framework that runs the CRS regression tests against a WAF.
  ([GitHub](https://github.com/coreruleset/go-ftw))
- <a id="goreleaser"></a>**GoReleaser**: A tool that builds, packages and publishes Go releases.
  ([GoReleaser docs](https://goreleaser.com/))
- <a id="govulncheck"></a>**govulncheck**: The Go tool that reports known vulnerabilities in the
  code a program actually calls. ([Go docs](https://go.dev/doc/security/vuln/))
- <a id="grafana"></a>**Grafana**: A dashboard tool for metrics, logs and traces. Grafana Labs also
  makes k6 and Pyroscope. ([Grafana docs](https://grafana.com/docs/grafana/latest/))
- <a id="grpc"></a>**gRPC**: A remote procedure call framework over HTTP/2, with messages in
  Protocol Buffers. The operator streams bundles to engines over it. ([gRPC
  docs](https://grpc.io/docs/))
- <a id="gzip"></a>**gzip**: A widely used compression format. ([RFC
  1952](https://www.rfc-editor.org/rfc/rfc1952))

### H

- <a id="haproxy"></a>**HAProxy**: A load balancer and proxy. It calls outside agents through SPOE.
  ([HAProxy docs](https://docs.haproxy.org/))
- <a id="har"></a>**HAR**: HTTP Archive: a JSON format, exported by browsers, that records HTTP
  requests and responses. ([W3C
  draft](https://w3c.github.io/web-performance/specs/HAR/Overview.html))
- <a id="helm"></a>**Helm**: The package manager for Kubernetes. A chart is a package of templated
  manifests; Inkwall's is published as an OCI artifact. ([Helm docs](https://helm.sh/docs/))
- <a id="helm-hook"></a>**Helm hook**: A chart object, such as a Job, that Helm runs at a point in a
  release's life, such as before an uninstall (pre-delete). ([Helm
  docs](https://helm.sh/docs/topics/charts_hooks/))
- <a id="http-wasm"></a>**http-wasm**: A specification for HTTP middleware compiled to WebAssembly,
  which Traefik can run. ([http-wasm](https://http-wasm.io/))
- <a id="http-versions"></a>**HTTP/1.1 and HTTP/2**: Versions of the HTTP protocol. HTTP/2
  multiplexes many streams over one connection, which gRPC uses. ([RFC 9112, RFC
  9113](https://www.rfc-editor.org/rfc/rfc9113))
- <a id="httproute"></a>**HTTPRoute**: The Gateway API object that routes HTTP requests from a
  Gateway to Services. ([Gateway API
  docs](https://gateway-api.sigs.k8s.io/reference/api-types/httproute/))
- <a id="hyperscan"></a>**Hyperscan**: A C library that matches many regular expressions at once.
  ([GitHub](https://github.com/intel/hyperscan))

### I

- <a id="ingress"></a>**Ingress**: The Kubernetes object that routes HTTP traffic from outside the
  cluster to Services, by host and path. Its `IngressClass` names the controller that serves it.
  ([Kubernetes docs](https://kubernetes.io/docs/concepts/services-networking/ingress/))
- <a id="ingress-controller"></a>**Ingress controller**: The product that implements `Ingress` (and
  often Gateway API) objects, such as Traefik or ingress-nginx; its proxy pods carry the traffic.
  ([Kubernetes docs](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/))
- <a id="ingress-nginx"></a>**ingress-nginx**: The Kubernetes community's ingress controller built
  on nginx, which can run ModSecurity and call an outside service per request (`auth-url`,
  `global-auth-url`). ([ingress-nginx docs](https://kubernetes.github.io/ingress-nginx/))
- <a id="ingressroute"></a>**IngressRoute**: Traefik's own route object (a CRD), with a richer
  `match` syntax than `Ingress`. ([Traefik
  docs](https://doc.traefik.io/traefik/routing/providers/kubernetes-crd/))
- <a id="init-container"></a>**Init container**: A container that runs before a pod's app
  containers. One with `restartPolicy: Always` is a native sidecar. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/))
- <a id="intermediate-representation"></a>**Intermediate representation (IR)**: The form a compiler
  turns source code into before it runs or translates it.
  ([Wikipedia](https://en.wikipedia.org/wiki/Intermediate_representation))
- <a id="istio"></a>**Istio**: A service mesh built on Envoy; an `EnvoyFilter` adds Envoy
  configuration to it. ([Istio docs](https://istio.io/latest/docs/))

### J

- <a id="job"></a>**Job**: A Kubernetes workload that runs pods until a task completes. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/workloads/controllers/job/))
- <a id="jq"></a>**jq**: A command-line JSON processor; Argo CD accepts its expressions to ignore
  fields. ([jq manual](https://jqlang.org/manual/))
- <a id="json-merge-patch"></a>**JSON merge patch**: A patch format in which a JSON document lists
  the fields to change; a list is always replaced whole. ([RFC
  7386](https://www.rfc-editor.org/rfc/rfc7386))
- <a id="json-pointer"></a>**JSON pointer**: A string such as `/spec/routes/0` that points to one
  value in a JSON document; `/` in a key is written `~1`. ([RFC
  6901](https://www.rfc-editor.org/rfc/rfc6901))

### K

- <a id="k6"></a>**k6**: A load testing tool. ([Grafana docs](https://grafana.com/docs/k6/latest/))
- <a id="kind"></a>**kind**: Kubernetes in Docker: a tool that runs a Kubernetes cluster in
  containers, for development and CI. ([kind docs](https://kind.sigs.k8s.io/))
- <a id="kstatus"></a>**kstatus**: A convention for status conditions that lets tools tell whether a
  Kubernetes object is ready.
  ([GitHub](https://github.com/kubernetes-sigs/cli-utils/blob/master/pkg/kstatus/README.md))
- <a id="kube-apiserver"></a>**kube-apiserver**: The Kubernetes API server, which validates and
  stores every object. ([Kubernetes
  docs](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/))
- <a id="kube-proxy"></a>**kube-proxy**: The node component that routes Service traffic to pods,
  rewriting the source address unless told not to. ([Kubernetes
  docs](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-proxy/))
- <a id="kubebuilder"></a>**kubebuilder**: A framework for building Kubernetes operators. Its
  markers in Go comments generate CRD schemas and RBAC rules. ([kubebuilder
  book](https://book.kubebuilder.io/))
- <a id="kubectl"></a>**kubectl**: The Kubernetes command-line tool. ([Kubernetes
  docs](https://kubernetes.io/docs/reference/kubectl/))
- <a id="kubelet"></a>**kubelet**: The node agent that runs pods, and updates the ConfigMaps and
  Secrets they mount. ([Kubernetes
  docs](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/))
- <a id="kubernetes"></a>**Kubernetes**: The container orchestration platform Inkwall runs on.
  ([Kubernetes docs](https://kubernetes.io/docs/concepts/overview/))
- <a id="kubernetes-operator"></a>**Kubernetes operator**: A controller that manages an application
  through custom resources. Inkwall's is `inkwall-operator`. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/))
- <a id="kustomize"></a>**kustomize**: A tool that assembles Kubernetes manifests from bases and
  patches, built into `kubectl`. ([kustomize
  docs](https://kubectl.docs.kubernetes.io/references/kustomize/))

### L

- <a id="label"></a>**Label and selector**: A key-value pair on an object; a selector picks the
  objects whose labels match. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/))
- <a id="leader-election"></a>**Lease and leader election**: A `Lease` object that one replica holds
  at a time, so only that replica, the leader, does the work only one may do. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/architecture/leases/#leader-election))
- <a id="libinjection"></a>**libinjection**: A library that detects SQL injection and XSS by
  tokenizing input; the CRS uses it through `@detectSQLi` and `@detectXSS`.
  ([GitHub](https://github.com/libinjection/libinjection))
- <a id="lua"></a>**Lua (OpenResty)**: A scripting language that nginx, and so ingress-nginx, runs
  through the OpenResty Lua module. ([GitHub](https://github.com/openresty/lua-nginx-module))

### M

- <a id="middleware"></a>**Middleware (Traefik)**: A Traefik object that changes or checks requests
  on the routes that reference it, such as ForwardAuth. ([Traefik
  docs](https://doc.traefik.io/traefik/middlewares/overview/))
- <a id="modsecurity"></a>**ModSecurity**: The original open-source WAF engine, now an OWASP
  project; its library is libmodsecurity. Its rule language is SecLang.
  ([GitHub](https://github.com/owasp-modsecurity/ModSecurity))
- <a id="mtls"></a>**mTLS (mutual TLS)**: TLS in which the client also proves its identity with a
  certificate. The operator authenticates to the control plane this way. ([RFC 8446
  §4.3.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.3.2))

### N

- <a id="nginx"></a>**nginx**: A web server and reverse proxy; ingress-nginx is built on it. ([nginx
  docs](https://nginx.org/en/docs/))
- <a id="node-drain"></a>**Node drain**: Evicting a node's pods safely, for example before
  maintenance. ([Kubernetes
  docs](https://kubernetes.io/docs/tasks/administer-cluster/safely-drain-node/))

### O

- <a id="olm"></a>**OLM (Operator Lifecycle Manager)**: A system that installs and upgrades
  operators, published on OperatorHub and built with operator-sdk. ([OLM
  docs](https://olm.operatorframework.io/))
- <a id="opentelemetry"></a>**OpenTelemetry**: An open standard for traces, metrics and logs; OTLP
  is its wire protocol. ([OpenTelemetry docs](https://opentelemetry.io/docs/))
- <a id="owner-reference"></a>**Owner reference and garbage collection**: A link from an object to
  its owner; Kubernetes deletes owned objects when the owner goes. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/))

### P

- <a id="paranoia-level"></a>**Paranoia level**: The CRS setting, from 1 to 4, that trades more
  detection for more false positives. Level 1 is the default. ([CRS
  docs](https://coreruleset.org/docs/concepts/paranoia_levels/))
- <a id="pod"></a>**Pod**: The smallest Kubernetes workload: one or more containers that share a
  network and storage. ([Kubernetes docs](https://kubernetes.io/docs/concepts/workloads/pods/))
- <a id="poddisruptionbudget"></a>**PodDisruptionBudget**: A limit on how many of an application's
  pods voluntary disruptions, such as node drains, may take down at once. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/workloads/pods/disruptions/#pod-disruption-budgets))
- <a id="pprof"></a>**pprof**: Go's profiler, served over HTTP by `net/http/pprof`. ([Go
  docs](https://pkg.go.dev/net/http/pprof))
- <a id="probe"></a>**Probe**: A check the kubelet runs on a container: startup, readiness or
  liveness. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/))
- <a id="projected-token"></a>**Projected service account token**: A short-lived token for a
  ServiceAccount, with an audience, mounted into a pod as a file. Engines authenticate to the
  operator with one. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/storage/projected-volumes/#serviceaccounttoken))
- <a id="prometheus"></a>**Prometheus**: A monitoring system that scrapes metrics from a `/metrics`
  endpoint. ([Prometheus docs](https://prometheus.io/docs/introduction/overview/))
- <a id="protobuf"></a>**Protocol Buffers (protobuf)**: Google's language-neutral format for
  serializing structured data; Inkwall's APIs and bundles use it.
  ([protobuf.dev](https://protobuf.dev/))
- <a id="proxy-protocol"></a>**PROXY protocol**: A header a load balancer sends at the start of a
  TCP connection, carrying the client's original address. ([HAProxy
  spec](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt))
- <a id="pyroscope"></a>**Pyroscope**: A continuous profiling tool. ([Grafana
  docs](https://grafana.com/docs/pyroscope/latest/))

### R

- <a id="rbac"></a>**RBAC**: Kubernetes role-based access control: `Role` and `ClusterRole` grant
  permissions, and bindings give them to users and ServiceAccounts. ([Kubernetes
  docs](https://kubernetes.io/docs/reference/access-authn-authz/rbac/))
- <a id="re2"></a>**RE2**: A regular expression syntax and engine that matches in linear time; Go's
  `regexp` package implements it. ([GitHub](https://github.com/google/re2/wiki/Syntax))
- <a id="redis"></a>**Redis**: An in-memory data store. ([Redis
  docs](https://redis.io/docs/latest/))
- <a id="redos"></a>**ReDoS**: Regular expression denial of service: input crafted to make a regex
  take a very long time.
  ([OWASP](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS))
- <a id="resource-version"></a>**resourceVersion**: An object's version in the API server; an update
  that carries it fails if the object changed since. ([Kubernetes
  docs](https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-versions))
- <a id="reverse-proxy"></a>**Reverse proxy**: A server that receives requests on behalf of other
  servers and forwards them.
  ([MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Proxy_servers_and_tunneling#forward_and_reverse_proxies))
- <a id="ring-buffer"></a>**Ring buffer**: A fixed-size buffer that overwrites, or drops, the oldest
  entries when full. ([Wikipedia](https://en.wikipedia.org/wiki/Circular_buffer))

### S

- <a id="sbom"></a>**SBOM**: Software bill of materials: a list of the components in a piece of
  software. Inkwall's are generated with syft. ([CISA](https://www.cisa.gov/sbom))
- <a id="seccomp"></a>**seccomp and capabilities**: Linux features that limit what a process may do:
  seccomp filters system calls, and capabilities split root's privileges. ([Kubernetes
  docs](https://kubernetes.io/docs/tutorials/security/seccomp/))
- <a id="seclang"></a>**SecLang**: ModSecurity's rule language (`SecRule`, `SecAction`, ...), which
  the CRS and Coraza use. ([Coraza docs](https://coraza.io/docs/seclang/))
- <a id="secret"></a>**Secret**: A Kubernetes object for sensitive data, such as keys and tokens; at
  most 1 MiB. ([Kubernetes docs](https://kubernetes.io/docs/concepts/configuration/secret/))
- <a id="semver"></a>**Semantic Versioning**: A version scheme, MAJOR.MINOR.PATCH, in which the
  number that changes says what kind of change it is. ([semver.org](https://semver.org/))
- <a id="server-side-apply"></a>**Server-side apply**: A way to update Kubernetes objects in which
  the API server tracks which field manager owns each field. ([Kubernetes
  docs](https://kubernetes.io/docs/reference/using-api/server-side-apply/))
- <a id="service"></a>**Service**: A stable address for a set of pods. `LoadBalancer` and `NodePort`
  Services expose it outside the cluster. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/services-networking/service/))
- <a id="serviceaccount"></a>**ServiceAccount**: An identity for processes that run in pods.
  ([Kubernetes docs](https://kubernetes.io/docs/concepts/security/service-accounts/))
- <a id="sha-256"></a>**SHA-256**: A cryptographic hash function. ([NIST FIPS
  180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final))
- <a id="sidecar"></a>**Sidecar**: A helper container that runs next to the main container in the
  same pod. A native sidecar, Kubernetes 1.29 and later, starts before the main containers and stops
  after them. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/))
- <a id="sigstore"></a>**Sigstore**: An open-source project for signing and verifying software, home
  of cosign. ([Sigstore docs](https://docs.sigstore.dev/))
- <a id="slog"></a>**slog**: Go's standard library package for structured logging. ([Go
  docs](https://pkg.go.dev/log/slog))
- <a id="slsa-provenance"></a>**SLSA provenance**: A signed record of how and where an artifact was
  built. ([SLSA](https://slsa.dev/spec/v1.0/provenance))
- <a id="snat"></a>**SNAT**: Source network address translation: rewriting a packet's source
  address, which hides the client's address. ([Kubernetes
  docs](https://kubernetes.io/docs/tutorials/services/source-ip/))
- <a id="spoe"></a>**SPOE**: HAProxy's Stream Processing Offload Engine: it sends request data to an
  outside agent (an SPOA) over the SPOP protocol, and acts on the variables the agent sets.
  ([HAProxy docs](https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt))
- <a id="sql-injection"></a>**SQL injection**: An attack that smuggles SQL into a query an
  application builds from its input.
  ([OWASP](https://owasp.org/www-community/attacks/SQL_Injection))

### T

- <a id="testcontainers-go"></a>**testcontainers-go**: A Go library that runs throwaway containers
  in tests. ([Testcontainers docs](https://golang.testcontainers.org/))
- <a id="tls"></a>**TLS**: Transport Layer Security, the protocol that encrypts HTTPS and gRPC
  connections. ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446))
- <a id="token-bucket"></a>**Token bucket**: A rate-limiting algorithm: requests spend tokens that
  refill at a fixed rate. ([Wikipedia](https://en.wikipedia.org/wiki/Token_bucket))
- <a id="subjectaccessreview"></a>**TokenReview and SubjectAccessReview**: Kubernetes API calls that
  check a token and whether its identity may do something. The operator authenticates engines with
  them. ([Kubernetes
  docs](https://kubernetes.io/docs/reference/access-authn-authz/authorization/#checking-api-access))
- <a id="traefik"></a>**Traefik**: A reverse proxy and Kubernetes ingress controller, the one
  Inkwall supports today. Its plugins run in Yaegi. ([Traefik
  docs](https://doc.traefik.io/traefik/))
- <a id="trie"></a>**Trie**: A tree that stores keys by their prefixes, so keys that share a prefix
  share nodes. ([Wikipedia](https://en.wikipedia.org/wiki/Trie))
- <a id="trivy"></a>**Trivy**: A security scanner for container images and dependencies. ([Trivy
  docs](https://trivy.dev/))
- <a id="trunk-based-development"></a>**Trunk-based development**: A branching model with one
  long-lived branch and short-lived work branches.
  ([trunkbaseddevelopment.com](https://trunkbaseddevelopment.com/))

### U

- <a id="uid"></a>**UID**: The unique ID Kubernetes gives every object. ([Kubernetes
  docs](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids))
- <a id="unicode-case-folding"></a>**Unicode case folding**: Mapping text so that strings differing
  only in case compare equal, for every script, not only ASCII. ([Unicode
  FAQ](https://www.unicode.org/faq/casemap_charprop.html))
- <a id="unix-socket"></a>**Unix domain socket**: A socket for communication between processes on
  the same machine, addressed by a file path. ([Linux man
  page](https://man7.org/linux/man-pages/man7/unix.7.html))

### W

- <a id="waf"></a>**Web application firewall (WAF)**: A filter in front of a web application that
  inspects HTTP requests and blocks attacks.
  ([OWASP](https://owasp.org/www-community/Web_Application_Firewall))
- <a id="websocket"></a>**WebSocket**: A protocol for two-way communication over one connection,
  started with an HTTP upgrade. ([RFC 6455](https://www.rfc-editor.org/rfc/rfc6455))

### X

- <a id="x-forwarded-for"></a>**X-Forwarded-For**: An HTTP header in which proxies append the
  address they received a request from.
  ([MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For))
- <a id="xss"></a>**XSS (cross-site scripting)**: An attack that injects script into pages other
  users load. ([OWASP](https://owasp.org/www-community/attacks/xss/))

### Y

- <a id="yaegi"></a>**Yaegi**: A Go interpreter; Traefik runs its plugins in it.
  ([GitHub](https://github.com/traefik/yaegi))
