// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

//go:build race

package controller

// raceDetector: the race detector runs the bundle size tests at full size
// several times slower (sizeTest).
const raceDetector = true
