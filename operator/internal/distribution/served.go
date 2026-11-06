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
// isn't one any policy is mapped to (a pod the wiring hasn't seen yet).
type ServedPods struct {
	mu sync.RWMutex
	// byPolicy: "namespace/name" of the policy → its pods' "namespace/name".
	byPolicy map[string]map[string]bool
	// integration of each mapped pod.
	integration map[string]string
}

// Set replaces the mapping: for each policy whose pods are known, its pods
// ("namespace/name") and the integration that runs each. Nil: none known.
func (s *ServedPods) Set(m map[string]map[string]string) {
	if s == nil {
		return
	}
	byPolicy := make(map[string]map[string]bool, len(m))
	integration := map[string]string{}
	for policy, pods := range m {
		set := make(map[string]bool, len(pods))
		for pod, in := range pods {
			set[pod] = true
			integration[pod] = in
		}
		byPolicy[policy] = set
	}
	s.mu.Lock()
	s.byPolicy, s.integration = byPolicy, integration
	s.mu.Unlock()
}

// view is a consistent read of the mapping for one report.
type servedView struct {
	byPolicy    map[string]map[string]bool
	integration map[string]string
}

func (s *ServedPods) view() servedView {
	if s == nil {
		return servedView{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return servedView{byPolicy: s.byPolicy, integration: s.integration}
}

// enginesFor returns the engines that count for a policy.
func (v servedView) enginesFor(policy string, engines []Engine) []Engine {
	pods, known := v.byPolicy[policy]
	if !known {
		return engines
	}
	var out []Engine
	for _, e := range engines {
		pod := enginePod(e)
		if pod == "" || v.integration[pod] == "" || pods[pod] {
			out = append(out, e)
		}
	}
	return out
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
