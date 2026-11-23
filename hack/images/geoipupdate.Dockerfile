# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Never built: the Helm chart's geoipupdate image (geo.geoipupdate.image in
# deploy/helm/inkwall/values.yaml), here so Dependabot bumps its tag and
# digest. make helm-lint (hack/helm-test.sh) checks that the two are equal.
FROM ghcr.io/maxmind/geoipupdate:v7.1.1@sha256:faecdca22579730ab0b7dea5aa9af350bb3c93cb9d39845c173639ead30346d2
