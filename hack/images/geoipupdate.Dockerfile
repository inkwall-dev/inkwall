# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Never built: the Helm chart's geoipupdate image (geo.geoipupdate.image in
# deploy/helm/inkwall/values.yaml), here so Dependabot bumps its tag and
# digest. make helm-lint (hack/helm-test.sh) checks that the two are equal.
FROM ghcr.io/maxmind/geoipupdate:v8.0.0@sha256:51e70dd6f16cd3e4d845ac02d09940b10772a75b9d741427d235a78570923c1d
