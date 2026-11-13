# syntax=docker/dockerfile:1
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# The stub control plane for the end-to-end test (hack/kind/e2e.sh); test
# only, never released.
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:ec47ea3725fea0cc88f6de94919aef19f40f12fc1ec0e2d1b3426dbf15ecca04 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -o /out/stubcontrolplane ./operator/test/stubcontrolplane

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/stubcontrolplane /stubcontrolplane
USER 65532:65532
EXPOSE 8443 8080
ENTRYPOINT ["/stubcontrolplane"]
