# syntax=docker/dockerfile:1
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# The stub control plane for the end-to-end test (hack/kind/e2e.sh); test
# only, never released.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -o /out/stubcontrolplane ./operator/test/stubcontrolplane

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/stubcontrolplane /stubcontrolplane
USER 65532:65532
EXPOSE 8443 8080
ENTRYPOINT ["/stubcontrolplane"]
