# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

GO              ?= go
# Every recipe, and the tools it runs with `go run tool@version` (which ignores go.mod), uses the
# toolchain go.mod asks for, whatever Go the machine has: golangci-lint refuses code for a newer Go
# than it was built with, and gofmt's output (in generated code) changes between versions.
export GOTOOLCHAIN := $(shell GOTOOLCHAIN=auto $(GO) env GOVERSION)
BIN_DIR         ?= bin
# Coraza operators the binaries leave out: inspectFile runs programs, rbl queries DNS. Rule sets
# are written by namespace users (pkg/rules/coraza/operators.go also unregisters them).
GO_TAGS         := coraza.disabled_operators.inspectFile,coraza.disabled_operators.rbl
GOLANGCI_LINT   ?= $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
GORELEASER      ?= $(GO) run github.com/goreleaser/goreleaser/v2@v2.18.3
GOVULNCHECK     ?= $(GO) run golang.org/x/vuln/cmd/govulncheck@v1.8.0
BUF             ?= $(GO) run github.com/bufbuild/buf/cmd/buf@v1.50.0
CONTROLLER_GEN  ?= $(GO) run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.23.0
SETUP_ENVTEST   ?= $(GO) run sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.25.2
# The API server the operator tests run against: the oldest tested Kubernetes
# version (as KIND_NODE_IMAGE), so CRDs that pass here work on every newer one.
ENVTEST_K8S_VERSION ?= 1.34.1

# Container images and local kind cluster (hack/kind).
IMAGE           ?= inkwall-engine:dev
OPERATOR_IMAGE  ?= inkwall-operator:dev
CHART           ?= deploy/helm/inkwall
KIND_CLUSTER    ?= inkwall
# kind, installed into bin/, and the node image of its clusters: the oldest Kubernetes this kind
# release ships. The Gateway API's CRDs and Envoy Gateway's chart install on it
# as shipped. CI's e2e job runs kind's newest instead (KIND_NODE_IMAGE empty).
KIND_VERSION    ?= v0.33.0
KIND_NODE_IMAGE ?= kindest/node:v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d
KIND_DIR        := $(abspath $(BIN_DIR))/kind-$(KIND_VERSION)
# kind-upgrade: its own cluster, since it installs a release of its own.
UPGRADE_CLUSTER ?= inkwall-upgrade
# Extra inkwall-operator flags for kind-operator (operator.extraArgs). kind-e2e shortens waits
# that only spread or pace work in a real cluster: a key rotation phase lasts at least the
# kubelet's ConfigMap update delay, 10 s in hack/kind/cluster.yaml (1 min by default), and a
# selector change restarts the replicas within 2 s of each other instead of 30 s.
OPERATOR_ARGS     ?=
E2E_OPERATOR_ARGS ?= --signing-key-grace=15s --selector-restart-max-delay=2s

# Benchmarks: set BENCH to a regexp to narrow, COUNT for benchstat-friendly repeats.
BENCH           ?= .
COUNT           ?= 1
# bench-compare: the revision to compare against.
BASE            ?= origin/main

# docs-check (hack/docscheck). Strict: every doc over 80 lines needs a
# ## Contents section, and docs/README.md must exist and list every doc
# (CLAUDE.md is exempt by default). CODE_OF_CONDUCT.md needs no Contents:
# it is the Contributor Covenant 2.1, kept verbatim. The install and verify
# commands of the READMEs and CONTRIBUTING.md write <version>, never a
# release, so they don't go stale when the next one ships. docs/monitoring.md
# names every metric the code registers.
DOCS_CHECK_STRICT ?= -contents-min-lines=80 -require-index -contents-exempt=CODE_OF_CONDUCT.md \
	-unpinned=README.md,deploy/helm/inkwall/README.md,CONTRIBUTING.md -metrics-doc=docs/monitoring.md
DOCS_CHECK        ?= $(GO) run ./hack/docscheck $(DOCS_CHECK_STRICT)

# scale-test: sizes as <policies>x<engines>, one operator each; "full" is 0004 §8's matrix.
# SCALE_CHANGES single-policy edits are timed; SCALE_OUT, if set, collects the results as JSON lines.
# SCALE_RESPONSES=1: every other policy inspects responses, checked on the engines and compiled once (#344).
SCALE           ?= 100x50
SCALE_CHANGES   ?= 10
SCALE_FULL      := 100x50 100x500 1000x50 1000x500 5000x50 5000x500
SCALE_OUT       ?=
SCALE_RESPONSES ?=

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build inkwall-engine and inkwallctl into ./bin
	$(GO) build -trimpath -tags $(GO_TAGS) -o $(BIN_DIR)/inkwall-engine ./cmd/engine
	$(GO) build -trimpath -tags $(GO_TAGS) -o $(BIN_DIR)/inkwallctl ./cmd/inkwallctl
	$(GO) build -trimpath -tags $(GO_TAGS) -o $(BIN_DIR)/inkwall-operator ./cmd/operator

.PHONY: test
test: ## Run unit tests with the race detector (operator tests run against a local API server, envtest)
	@a="$$($(SETUP_ENVTEST) use -p path $(ENVTEST_K8S_VERSION))"; [ -d "$$a" ] || { echo "no envtest assets for Kubernetes $(ENVTEST_K8S_VERSION): setup-envtest failed" >&2; exit 1; }; KUBEBUILDER_ASSETS="$$a" $(GO) test -race -count=1 ./...

.PHONY: scale-test
scale-test: ## Operator scale test with fake engines, in envtest (SCALE=<policies>x<engines>, default 100x50; SCALE=full; SCALE=wiring[:<policies>] for the wiring controller)
	@a="$$($(SETUP_ENVTEST) use -p path $(ENVTEST_K8S_VERSION))"; [ -d "$$a" ] || { echo "no envtest assets for Kubernetes $(ENVTEST_K8S_VERSION): setup-envtest failed" >&2; exit 1; }; export KUBEBUILDER_ASSETS="$$a"; fail=0; \
	for s in $(if $(filter full,$(SCALE)),$(SCALE_FULL),$(SCALE)); do \
		echo "== scale $$s"; \
		INKWALL_SCALE=$$s INKWALL_SCALE_CHANGES=$(SCALE_CHANGES) INKWALL_SCALE_OUT="$(SCALE_OUT)" INKWALL_SCALE_RESPONSES="$(SCALE_RESPONSES)" $(GO) test -count=1 -timeout 60m -run '^TestScale(Wiring)?$$' -v ./operator/test/scale || fail=1; \
	done; exit $$fail

.PHONY: bench
bench: ## Run benchmarks (BENCH=regexp COUNT=n)
	$(GO) test -run='^$$' -bench='$(BENCH)' -benchmem -count=$(COUNT) ./...

.PHONY: bench-compare
bench-compare: ## Compare benchmarks of changed packages with BASE (origin/main); fail on a repeated significant regression over 5%
	BENCH='$(BENCH)' hack/bench/compare.sh $(BASE)

.PHONY: crs-test
crs-test: ## Run the OWASP CRS regression suite through the proxy (test/crs)
	cd test/crs && $(GO) test -count=1 -timeout 30m -v ./...


.PHONY: lint
lint: workflow-check lint-scripts ## Run golangci-lint, and check the workflows and the shell scripts
	$(GOLANGCI_LINT) run ./...

# The workflows' and scripts' linters (#398). shellcheck and zizmor run from
# their images when they aren't installed.
ACTIONLINT ?= $(GO) run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
SHELLCHECK ?= $(if $(shell command -v shellcheck),shellcheck,docker run --rm -v $(CURDIR):/mnt -w /mnt koalaman/shellcheck:v0.10.0)
ZIZMOR     ?= $(if $(shell command -v zizmor),zizmor,docker run --rm -v $(CURDIR):/repo -w /repo ghcr.io/zizmorcore/zizmor:1.16.3)

.PHONY: lint-scripts
lint-scripts: ## Lint the workflows (actionlint, zizmor; findings triaged in .github/zizmor.yml) and the shell scripts (shellcheck)
	$(ACTIONLINT)
	$(ZIZMOR) --offline --config .github/zizmor.yml .github/workflows
	$(SHELLCHECK) $$(git ls-files '*.sh')

# The runner every CI job runs on: a fixed Ubuntu release, never
# ubuntu-latest, which GitHub moves to the next LTS unannounced (#400). Move
# to the next one in a PR of its own, which runs the whole suite.
CI_RUNNER ?= ubuntu-24.04

.PHONY: workflow-check
workflow-check: ## Check that every workflow job runs on CI_RUNNER
	@bad=$$(grep -rn 'runs-on:' .github/workflows | grep -v 'runs-on: $(CI_RUNNER)$$'); \
	if [ -n "$$bad" ]; then echo "$$bad"; echo "workflow-check: jobs must run on $(CI_RUNNER) (CI_RUNNER in the Makefile)"; exit 1; fi

.PHONY: fmt
fmt: ## Format code
	$(GOLANGCI_LINT) fmt ./...

.PHONY: docs-check
docs-check: ## Check the Markdown docs: internal links and anchors, Contents lists, the docs index
	$(DOCS_CHECK)

.PHONY: docs-check-external
docs-check-external: ## Check the Markdown docs' external links as well (slow; CI runs it nightly)
	$(DOCS_CHECK) -external

.PHONY: vuln
vuln: ## Check dependencies for known vulnerabilities
	$(GOVULNCHECK) ./...

.PHONY: generate
generate: ## Lint the protobuf APIs (api/), regenerate their Go code, and regenerate the operator's deepcopy code, CRDs, RBAC and webhook configuration (also copied into the Helm chart)
	$(BUF) lint
	$(BUF) generate
	$(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt paths=./operator/api/...
	$(CONTROLLER_GEN) crd paths=./operator/api/... output:crd:artifacts:config=operator/config/crd/bases
	$(CONTROLLER_GEN) rbac:roleName=inkwall-operator webhook paths=./operator/... paths=./cmd/operator/... \
		output:rbac:artifacts:config=operator/config/rbac output:webhook:artifacts:config=operator/config/webhook
	@# The chart renders the generated CRDs, RBAC and webhooks from its files/.
	rm -rf $(CHART)/files && mkdir -p $(CHART)/files/crds $(CHART)/files/rbac $(CHART)/files/webhook
	cp operator/config/crd/bases/*.yaml $(CHART)/files/crds/
	cp operator/config/rbac/role.yaml $(CHART)/files/rbac/
	cp operator/config/webhook/manifests.yaml $(CHART)/files/webhook/

# promtool, for the alerts' unit tests: the Prometheus image's, unless
# PROMTOOL names one installed.
PROMTOOL ?= docker run --rm -v $(CURDIR):/work -w /work --entrypoint promtool quay.io/prometheus/prometheus:v3.5.0

.PHONY: monitoring-test
monitoring-test: ## Check the chart's alerts and run their unit tests (hack/monitoring/alerts_test.yaml) with promtool
	$(PROMTOOL) check rules deploy/helm/inkwall/monitoring/alerts.yaml
	$(PROMTOOL) test rules hack/monitoring/alerts_test.yaml

.PHONY: helm-lint
helm-lint: ## Lint the Helm chart, render it with each webhook certificate mode, and check its integration roles (hack/helm-test.sh)
	helm lint --strict $(CHART)
	helm template inkwall $(CHART) --namespace inkwall-system >/dev/null
	helm template inkwall $(CHART) --namespace inkwall-system --set webhook.certs.mode=certManager >/dev/null
	helm template inkwall $(CHART) --namespace inkwall-system --set controlPlane.caBundle=ca --set controlPlane.enrollmentToken=t >/dev/null
	@# As helm upgrade --reuse-values from 0.1.0 renders it: values without controlPlane.
	helm template inkwall $(CHART) --namespace inkwall-system --set controlPlane=null >/dev/null
	@# The monitoring kit, every object of it.
	helm lint --strict $(CHART) --set metrics.forceMonitoringObjects=true --set metrics.serviceMonitor.enabled=true \
		--set metrics.podMonitor.enabled=true --set metrics.prometheusRule.enabled=true --set metrics.dashboard.enabled=true
	CHART=$(CHART) hack/helm-test.sh
	@# What the chart looks up in a cluster, against envtest.
	@a="$$($(SETUP_ENVTEST) use -p path $(ENVTEST_K8S_VERSION))"; [ -d "$$a" ] || { echo "no envtest assets for Kubernetes $(ENVTEST_K8S_VERSION): setup-envtest failed" >&2; exit 1; }; KUBEBUILDER_ASSETS="$$a" CHART=$(abspath $(CHART)) $(GO) test -count=1 ./hack/helmcheck

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum, here and in test/crs (which builds against this module)
	$(GO) mod tidy
	cd test/crs && $(GO) mod tidy

.PHONY: check
check: lint test vuln docs-check ## Run everything CI runs

.PHONY: image
image: ## Build the engine and operator container images (IMAGE=name:tag, OPERATOR_IMAGE=name:tag)
	docker build --target engine -t $(IMAGE) .
	docker build --target operator -t $(OPERATOR_IMAGE) .

.PHONY: release-snapshot
release-snapshot: ## Build the release binaries and archives into ./dist, as a tag would, without signing or publishing
	$(GORELEASER) release --snapshot --clean --skip=sign,publish

.PHONY: release-check
release-check: ## Check the goreleaser configuration
	$(GORELEASER) check

# The kind targets, and the scripts they run, use the kind of KIND_VERSION.
KIND_TARGETS := kind-cluster kind-up kind-operator kind-e2e kind-e2e-traefik kind-e2e-raw-envoy kind-e2e-envoy-gateway kind-e2e-istio kind-e2e-haproxy kind-response-load kind-upgrade kind-down
$(KIND_TARGETS): export PATH := $(KIND_DIR):$(PATH)
$(KIND_TARGETS): $(KIND_DIR)/kind

$(KIND_DIR)/kind:
	GOBIN=$(KIND_DIR) $(GO) install sigs.k8s.io/kind@$(KIND_VERSION)

.PHONY: kind-cluster
kind-cluster: ## Create the kind cluster (KIND_NODE_IMAGE), unless it exists
	kind get clusters | grep -x $(KIND_CLUSTER) >/dev/null || kind create cluster --name $(KIND_CLUSTER) \
		--config hack/kind/cluster.yaml $(if $(KIND_NODE_IMAGE),--image $(KIND_NODE_IMAGE)) --wait 120s

.PHONY: kind-up
kind-up: kind-cluster ## Create the kind cluster and deploy the demo app behind the engine and behind Traefik (hack/kind)
	KIND_CLUSTER=$(KIND_CLUSTER) IMAGE=$(IMAGE) hack/kind/up.sh

.PHONY: kind-operator
kind-operator: ## Build the operator image, install the Helm chart on the kind cluster and check the webhook
	KIND_CLUSTER=$(KIND_CLUSTER) OPERATOR_IMAGE=$(OPERATOR_IMAGE) IMAGE_ENGINE=$(IMAGE) CHART=$(CHART) \
		OPERATOR_ARGS="$(OPERATOR_ARGS)" hack/kind/operator.sh

.PHONY: kind-e2e
kind-e2e: OPERATOR_ARGS = $(E2E_OPERATOR_ARGS)
kind-e2e: ## End-to-end test on kind: a WAFPolicy is enforced by an engine in bundle mode, through Traefik, raw Envoy, Envoy Gateway, Istio and HAProxy, one after another (CI runs them as separate jobs)
	@# Each installs the operator first and ends with an uninstall. The
	@# images are built once: SKIP_IMAGE_BUILD for the others.
	$(MAKE) kind-e2e-traefik
	SKIP_IMAGE_BUILD=1 $(MAKE) kind-e2e-raw-envoy
	SKIP_IMAGE_BUILD=1 $(MAKE) kind-e2e-envoy-gateway
	SKIP_IMAGE_BUILD=1 $(MAKE) kind-e2e-istio
	SKIP_IMAGE_BUILD=1 $(MAKE) kind-e2e-haproxy

.PHONY: kind-e2e-traefik
kind-e2e-traefik: OPERATOR_ARGS = $(E2E_OPERATOR_ARGS)
kind-e2e-traefik: kind-operator ## End-to-end test on kind through Traefik: a WAFPolicy enforced by an engine in bundle mode, the control plane, signing key rotation, suspension (installs the operator first)
	@# kind-operator built (or, with SKIP_IMAGE_BUILD, found) and loaded the engine image.
	KIND_CLUSTER=$(KIND_CLUSTER) IMAGE=$(IMAGE) SKIP_BUILD=1 hack/kind/e2e.sh

.PHONY: kind-e2e-raw-envoy
kind-e2e-raw-envoy: OPERATOR_ARGS = $(E2E_OPERATOR_ARGS)
kind-e2e-raw-envoy: kind-operator ## End-to-end test on kind of raw Envoy with the engine in bundle mode, the examples/raw-envoy sample (installs the operator first)
	KIND_CLUSTER=$(KIND_CLUSTER) IMAGE=$(IMAGE) hack/kind/raw-envoy-e2e.sh

.PHONY: kind-e2e-envoy-gateway
kind-e2e-envoy-gateway: OPERATOR_ARGS = $(E2E_OPERATOR_ARGS)
kind-e2e-envoy-gateway: kind-operator ## End-to-end test on kind through Envoy Gateway and Traefik with one WAFPolicy, ending with an uninstall (installs the operator first)
	KIND_CLUSTER=$(KIND_CLUSTER) hack/kind/envoy-gateway-e2e.sh

.PHONY: kind-response-load
kind-response-load: kind-operator ## Load test on kind through Envoy Gateway, response inspection off vs. on: p50/p99 latency and engine RSS (installs the operator first; CONCURRENCY, DURATION, OUT)
	KIND_CLUSTER=$(KIND_CLUSTER) hack/kind/response-load.sh

.PHONY: kind-e2e-istio
kind-e2e-istio: OPERATOR_ARGS = $(E2E_OPERATOR_ARGS)
kind-e2e-istio: kind-operator ## End-to-end test on kind through Istio's Gateways with one WAFPolicy, ending with an uninstall (installs the operator first)
	KIND_CLUSTER=$(KIND_CLUSTER) hack/kind/istio-e2e.sh

.PHONY: kind-e2e-haproxy
kind-e2e-haproxy: OPERATOR_ARGS = $(E2E_OPERATOR_ARGS)
kind-e2e-haproxy: kind-operator ## End-to-end test on kind through the HAProxy Kubernetes Ingress Controller with one WAFPolicy, ending with an uninstall (installs the operator first)
	KIND_CLUSTER=$(KIND_CLUSTER) hack/kind/haproxy-e2e.sh

.PHONY: kind-upgrade
kind-upgrade: ## Upgrade test on kind: helm upgrade from the last release to this checkout keeps routes protected, uninstall restores them (own cluster, UPGRADE_CLUSTER)
	UPGRADE_CLUSTER=$(UPGRADE_CLUSTER) KIND_NODE_IMAGE=$(KIND_NODE_IMAGE) OPERATOR_IMAGE=$(OPERATOR_IMAGE) IMAGE=$(IMAGE) CHART=$(CHART) hack/kind/upgrade.sh

.PHONY: kind-test
kind-test: ## Send benign and attack requests to the kind demo and check verdicts
	hack/kind/smoke.sh
	NAME=traefik PROXY=http://127.0.0.1:30080 ADMIN=http://127.0.0.1:30482 hack/kind/smoke.sh

.PHONY: haproxy-e2e
haproxy-e2e: ## End-to-end test of HAProxy with the engine's SPOE agent and the examples/haproxy samples, in Docker (no cluster; Linux)
	hack/haproxy/e2e.sh

.PHONY: raw-envoy-e2e
raw-envoy-e2e: ## End-to-end test of raw Envoy with the engine's ext_proc adapter and the examples/raw-envoy samples, in Docker (no cluster)
	IMAGE=$(IMAGE) hack/raw-envoy/e2e.sh

.PHONY: websocket-e2e
websocket-e2e: ## End-to-end test of WebSocket message inspection by the engine's proxy, with hack/wsecho, in Docker (no cluster)
	IMAGE=$(IMAGE) hack/websocket/e2e.sh

.PHONY: kind-down
kind-down: ## Delete the kind cluster
	kind delete cluster --name $(KIND_CLUSTER)

.PHONY: clean
clean: ## Remove build output
	rm -rf $(BIN_DIR) dist
