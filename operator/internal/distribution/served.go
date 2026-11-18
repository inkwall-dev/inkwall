// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import "sync"

// ServedPods are the proxy pods that serve each policy's routes, from the
// wiring's results, so that only their engines count for its Enforced
// condition (#371). The wiring controller sets them at each reconcile; the
// Reporter reads them. Both run on the leader.
//
// It fails safe: a policy whose pods aren't known counts every engine, and
// an engine counts for every policy when it reports no pod, or when its pod
// isn't one any policy is mapped to (a pod the wiring hasn't seen yet). A
// running pod with the engine container whose engine isn't connected holds
// its policies back (#652): until it reconnects, it may serve an older
// bundle.
type ServedPods struct {
	mu sync.RWMutex
	// byPolicy: "namespace/name" of the policy → its pods' "namespace/name".
	byPolicy map[string]map[string]bool
	// integration of each mapped pod.
	integration map[string]string
	// engine: the mapped pods that run with the engine container.
	engine map[string]bool
}

// ServedPod is a pod that serves a policy's routes.
type ServedPod struct {
	// Integration runs the pod's proxy.
	Integration string
	// Engine: the pod is running, with the engine container, so an engine
	// of it is expected to be connected.
	Engine bool
}

// Set replaces the mapping: for each policy whose pods are known, its pods
// ("namespace/name"). Nil: none known.
func (s *ServedPods) Set(m map[string]map[string]ServedPod) {
	if s == nil {
		return
	}
	byPolicy := make(map[string]map[string]bool, len(m))
	integration := map[string]string{}
	engine := map[string]bool{}
	for policy, pods := range m {
		set := make(map[string]bool, len(pods))
		for pod, sp := range pods {
			set[pod] = true
			integration[pod] = sp.Integration
			if sp.Engine {
				engine[pod] = true
			}
		}
		byPolicy[policy] = set
	}
	s.mu.Lock()
	s.byPolicy, s.integration, s.engine = byPolicy, integration, engine
	s.mu.Unlock()
}

// view is a consistent read of the mapping for one report.
type servedView struct {
	byPolicy    map[string]map[string]bool
	integration map[string]string
	engine      map[string]bool
}

func (s *ServedPods) view() servedView {
	if s == nil {
		return servedView{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return servedView{byPolicy: s.byPolicy, integration: s.integration, engine: s.engine}
}

// enginesFor returns the engines that count for a policy, and how many of
// its pods with the engine container have no engine connected (#652). Those
// aren't counted when some engine reports no pod: it may be theirs.
func (v servedView) enginesFor(policy string, engines []Engine) ([]Engine, int) {
	pods, known := v.byPolicy[policy]
	if !known {
		return engines, 0
	}
	var out []Engine
	connected := map[string]bool{}
	anonymous := false
	for _, e := range engines {
		pod := enginePod(e)
		if pod == "" {
			anonymous = true
		} else {
			connected[pod] = true
		}
		if pod == "" || v.integration[pod] == "" || pods[pod] {
			out = append(out, e)
		}
	}
	missing := 0
	if !anonymous {
		for pod := range pods {
			if v.engine[pod] && !connected[pod] {
				missing++
			}
		}
	}
	return out, missing
}

// goneFor returns the engines that disconnected recently that count for a
// policy: all of them when its pods aren't known (raw Envoy, the standalone
// proxy), as nothing else tells that one is missing (#675); none when they
// are, since enginesFor counts the known pods whose engine isn't connected,
// and a pod deleted since must not hold the policy back.
func (v servedView) goneFor(policy string, gone []Engine) []Engine {
	if _, known := v.byPolicy[policy]; known {
		return nil
	}
	return gone
}

// integrationOf names the integration whose pod runs the engine, or
// "unknown".
func (v servedView) integrationOf(e Engine) string {
	if in := v.integration[enginePod(e)]; in != "" {
		return in
	}
	return "unknown"
}

func enginePod(e Engine) string {
	if e.PodName == "" {
		return ""
	}
	return e.PodNamespace + "/" + e.PodName
}
