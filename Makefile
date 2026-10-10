# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

GO              ?= go
BIN_DIR         ?= bin
GOLANGCI_LINT   ?= $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
GOVULNCHECK     ?= $(GO) run golang.org/x/vuln/cmd/govulncheck@v1.8.0
BUF             ?= $(GO) run github.com/bufbuild/buf/cmd/buf@v1.50.0

# Container image and local kind cluster (hack/kind).
IMAGE           ?= inkwall-engine:dev
KIND_CLUSTER    ?= inkwall

# Benchmarks: set BENCH to a regexp to narrow, COUNT for benchstat-friendly repeats.
BENCH           ?= .
COUNT           ?= 1

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build inkwall-engine into ./bin
	$(GO) build -trimpath -o $(BIN_DIR)/inkwall-engine ./cmd/engine

.PHONY: test
test: ## Run unit tests with the race detector
	$(GO) test -race -count=1 ./...

.PHONY: bench
bench: ## Run benchmarks (BENCH=regexp COUNT=n)
	$(GO) test -run='^$$' -bench='$(BENCH)' -benchmem -count=$(COUNT) ./...

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
generate: ## Lint the protobuf APIs (api/) and regenerate their Go code
	$(BUF) lint
	$(BUF) generate

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum
	$(GO) mod tidy

.PHONY: check
check: lint test vuln ## Run everything CI runs

.PHONY: image
image: ## Build the inkwall-engine container image (IMAGE=name:tag)
	docker build -t $(IMAGE) .

.PHONY: kind-up
kind-up: ## Create the kind cluster and deploy the demo app behind the engine and behind Traefik (hack/kind)
	KIND_CLUSTER=$(KIND_CLUSTER) IMAGE=$(IMAGE) hack/kind/up.sh

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
