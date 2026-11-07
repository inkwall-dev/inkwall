# syntax=docker/dockerfile:1
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# One Dockerfile, one image per target:
#   docker build --target engine   -t inkwall-engine .    (the default)
#   docker build --target operator -t inkwall-operator .

# Base images are pinned by digest (tag@sha256:…), bumped by Dependabot.
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS build
ARG TARGETOS TARGETARCH
# The release version (without "v") and commit, stamped into the binaries:
# the build context has no .git for Go to read the commit from.
ARG VERSION=
ARG COMMIT=
# Coraza operators left out of the binaries: inspectFile runs programs, rbl
# queries DNS, and rule sets are written by namespace users.
ARG GO_TAGS=coraza.disabled_operators.inspectFile,coraza.disabled_operators.rbl
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .

FROM build AS build-engine
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -tags "${GO_TAGS}" -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" -o /out/inkwall-engine ./cmd/engine

FROM build AS build-operator
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -tags "${GO_TAGS}" -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" -o /out/inkwall-operator ./cmd/operator

# Distroless, non-root, no shell (docs/design/0002). The operator writes its
# webhook certificate under /tmp: with a read-only root filesystem, mount a
# writable /tmp.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS operator
COPY --from=build-operator /out/inkwall-operator /inkwall-operator
USER 65532:65532
# Metrics, health probes, webhook.
EXPOSE 8080 8081 9443
ENTRYPOINT ["/inkwall-operator"]

# The CRS is embedded in the binary; with a read-only root filesystem, mount
# a writable /tmp (Coraza checks at startup that it can create files there).
# Last, so a plain `docker build` still builds the engine.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS engine
COPY --from=build-engine /out/inkwall-engine /inkwall-engine
USER 65532:65532
EXPOSE 8480 9480
ENTRYPOINT ["/inkwall-engine"]
