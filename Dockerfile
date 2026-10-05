# syntax=docker/dockerfile:1
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/inkwall-engine ./cmd/engine

# Distroless, non-root, no shell (docs/design/0002). The CRS is embedded in
# the binary; with a read-only root filesystem, mount a writable /tmp
# (Coraza checks at startup that it can create files there).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/inkwall-engine /inkwall-engine
USER 65532:65532
EXPOSE 8480 9480
ENTRYPOINT ["/inkwall-engine"]
