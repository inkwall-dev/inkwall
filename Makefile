# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

GO              ?= go
BIN_DIR         ?= bin
GOLANGCI_LINT   ?= $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
GOVULNCHECK     ?= $(GO) run golang.org/x/vuln/cmd/govulncheck@v1.8.0
BUF             ?= $(GO) run github.com/bufbuild/buf/cmd/buf@v1.50.0
CONTROLLER_GEN  ?= $(GO) run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.23.0
SETUP_ENVTEST   ?= $(GO) run sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.25.2
# The API server the operator tests run against: the oldest supported
# Kubernetes version, so CRDs that pass here work on every newer one.
ENVTEST_K8S_VERSION ?= 1.29.5

# Container images and local kind cluster (hack/kind).
IMAGE           ?= inkwall-engine:dev
OPERATOR_IMAGE  ?= inkwall-operator:dev
CHART           ?= deploy/helm/inkwall
KIND_CLUSTER    ?= inkwall

# Benchmarks: set BENCH to a regexp to narrow, COUNT for benchstat-friendly repeats.
BENCH           ?= .
COUNT           ?= 1
# bench-compare: the revision to compare against.
BASE            ?= origin/main

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build inkwall-engine and inkwallctl into ./bin
	$(GO) build -trimpath -o $(BIN_DIR)/inkwall-engine ./cmd/engine
	$(GO) build -trimpath -o $(BIN_DIR)/inkwallctl ./cmd/inkwallctl
	$(GO) build -trimpath -o $(BIN_DIR)/inkwall-operator ./cmd/operator

.PHONY: test
test: ## Run unit tests with the race detector (operator tests run against a local API server, envtest)
	KUBEBUILDER_ASSETS="$$($(SETUP_ENVTEST) use -p path $(ENVTEST_K8S_VERSION))" $(GO) test -race -count=1 ./...

.PHONY: bench
bench: ## Run benchmarks (BENCH=regexp COUNT=n)
	$(GO) test -run='^$$' -bench='$(BENCH)' -benchmem -count=$(COUNT) ./...

.PHONY: bench-compare
bench-compare: ## Compare benchmarks with BASE (origin/main) and fail on a significant regression over 5%
	BENCH='$(BENCH)' hack/bench/compare.sh $(BASE)

.PHONY: crs-test
crs-test: ## Run the OWASP CRS regression suite through the proxy (test/crs)
	cd test/crs && $(GO) test -count=1 -timeout 30m -v ./...

.PHONY: lint
lint: ## Run golangci-lint
	$(GOLANGCI_LINT) run ./...

.PHONY: fmt
fmt: ## Format code
	$(GOLANGCI_LINT) fmt ./...

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

.PHONY: helm-lint
helm-lint: ## Lint the Helm chart and render it with each webhook certificate mode
	helm lint --strict $(CHART)
	helm template inkwall $(CHART) --namespace inkwall-system >/dev/null
	helm template inkwall $(CHART) --namespace inkwall-system --set webhook.certs.mode=certManager >/dev/null

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum, here and in test/crs (which builds against this module)
	$(GO) mod tidy
	cd test/crs && $(GO) mod tidy

.PHONY: check
check: lint test vuln ## Run everything CI runs

.PHONY: image
image: ## Build the engine and operator container images (IMAGE=name:tag, OPERATOR_IMAGE=name:tag)
	docker build --target engine -t $(IMAGE) .
	docker build --target operator -t $(OPERATOR_IMAGE) .

.PHONY: kind-up
kind-up: ## Create the kind cluster and deploy the demo app behind the engine and behind Traefik (hack/kind)
	KIND_CLUSTER=$(KIND_CLUSTER) IMAGE=$(IMAGE) hack/kind/up.sh

.PHONY: kind-operator
kind-operator: ## Build the operator image, install the Helm chart on the kind cluster and check the webhook
	KIND_CLUSTER=$(KIND_CLUSTER) OPERATOR_IMAGE=$(OPERATOR_IMAGE) CHART=$(CHART) hack/kind/operator.sh

.PHONY: kind-test
kind-test: ## Send benign and attack requests to the kind demo and check verdicts
	hack/kind/smoke.sh
	NAME=traefik PROXY=http://127.0.0.1:30080 ADMIN=http://127.0.0.1:30482 hack/kind/smoke.sh

.PHONY: kind-down
kind-down: ## Delete the kind cluster
	kind delete cluster --name $(KIND_CLUSTER)

.PHONY: clean
clean: ## Remove build output
	rm -rf $(BIN_DIR)
