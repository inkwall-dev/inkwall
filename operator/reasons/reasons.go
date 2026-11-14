// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package reasons says, for every condition reason the operator sets and
// every reason a security event gives, what it means and what to do. It is
// the one source of docs/troubleshooting.md's reason tables (rendered
// between its "<!-- reasons: KIND CONDITION -->" markers; go test
// ./operator/reasons -update rewrites them) and of inkwallctl explain.
// Its tests fail when the operator sets a reason without an entry here, or
// when the guide's tables aren't the ones these entries render.
package reasons

import (
	"path"
	"regexp"
	"strings"
)

// Kinds of entries: the objects whose conditions they explain, and the
// security event's reason field.
const (
	KindWAFPolicy     = "WAFPolicy"
	KindInkwallConfig = "InkwallConfig"
	// KindSecurityEvent entries explain a security event's reason
	// (condition "reason"), as the engine's log writes it.
	KindSecurityEvent = "SecurityEvent"
)

// Entry explains one reason of one condition of one kind. Meaning and Fix
// are Markdown, with links relative to docs/; Text turns them into plain
// text. Fix is empty for a reason that needs nothing done.
type Entry struct {
	Kind, Condition, Reason string
	Meaning, Fix            string
}

// All returns every entry, in the guide's order.
func All() []Entry { return append([]Entry(nil), entries...) }

// Lookup returns the entry for a kind's condition and reason.
func Lookup(kind, condition, reason string) (Entry, bool) {
	for _, e := range entries {
		if e.Kind == kind && e.Condition == condition && e.Reason == reason {
			return e, true
		}
	}
	return Entry{}, false
}

// Table renders the entries of a kind's condition as the guide's Markdown
// table; for the InkwallConfig, condition "" renders every condition in
// one table with a Condition column.
func Table(kind, condition string) string {
	var b strings.Builder
	withCondition := condition == ""
	if withCondition {
		b.WriteString("| Condition | Reason | Meaning | Fix |\n|---|---|---|---|\n")
	} else {
		b.WriteString("| Reason | Meaning | Fix |\n|---|---|---|\n")
	}
	for _, e := range entries {
		if e.Kind != kind || (!withCondition && e.Condition != condition) {
			continue
		}
		var cells []string
		if withCondition {
			cells = append(cells, "`"+e.Condition+"`")
		}
		cells = append(cells, "`"+e.Reason+"`", e.Meaning, e.Fix)
		for _, c := range cells {
			if c == "" {
				b.WriteString("| ")
			} else {
				b.WriteString("| " + c + " ")
			}
		}
		b.WriteString("|\n")
	}
	return b.String()
}

// linkRE is a Markdown link.
var linkRE = regexp.MustCompile(`\[([^\]]+)\]\(([^)\s]+)\)`)

// Text turns an entry's Markdown into plain text for a terminal: a link
// becomes its text and, in parentheses, the file it points to, from the
// repository's root (docs/monitoring.md#anchor).
func Text(markdown string) string {
	return linkRE.ReplaceAllStringFunc(markdown, func(link string) string {
		m := linkRE.FindStringSubmatch(link)
		return m[1] + " (" + DocPath(m[2]) + ")"
	})
}

// DocPath resolves a link of the guide from the repository's root.
func DocPath(target string) string {
	if strings.Contains(target, "://") {
		return target
	}
	if strings.HasPrefix(target, "#") {
		return "docs/troubleshooting.md" + target
	}
	file, anchor, _ := strings.Cut(target, "#")
	p := path.Join("docs", file)
	if anchor != "" {
		p += "#" + anchor
	}
	return p
}

// entries are the guide's tables, in order.
var entries = []Entry{
	{Kind: "WAFPolicy", Condition: "Accepted", Reason: "Accepted",
		Meaning: "Valid, and in the bundle the engines get.",
		Fix:     ""},
	{Kind: "WAFPolicy", Condition: "Accepted", Reason: "InvalidRef",
		Meaning: "A rule set, ConfigMap or key the policy (or its rule set) names doesn't exist, or isn't labeled `waf.inkwall.dev/rules=true`. Or a rule set bound with `placement: BeforeCRS` can't load there: the built-in CRS, or SecLang with `SecRuleRemoveBy*` or `SecRuleUpdate*`.",
		Fix:     "Create it, or fix the name. The message names it. Move those directives to a rule set placed `AfterCRS` (the default)."},
	{Kind: "WAFPolicy", Condition: "Accepted", Reason: "RuleCompileError",
		Meaning: "Rules in the policy's rule set don't compile, or use a directive Inkwall doesn't allow.",
		Fix:     "Fix the rules; `inkwallctl test --rule-set` shows the error before you apply."},
	{Kind: "WAFPolicy", Condition: "Accepted", Reason: "Conflict",
		Meaning: "An older policy targets the same route and applies to it: a route has one policy.",
		Fix:     "Merge the policies, or target other routes."},
	{Kind: "WAFPolicy", Condition: "Accepted", Reason: "TargetUnsupported",
		Meaning: "A target's match rules (an IngressRoute's, HTTPRoute's or VirtualService's) aren't ones the router can match, so its requests can't be told apart.",
		Fix:     "Use the forms the message lists (`Host`, `Path`, `PathPrefix`; exact and prefix paths)."},
	{Kind: "WAFPolicy", Condition: "Accepted", Reason: "BundleTooLarge",
		Meaning: "The bundle with this version of the policy is over 7,200 KiB compressed, so it isn't published; engines keep the previous one.",
		Fix:     "Move shared inline rules into one rule set that the policies reference; see [InkwallBundleNearSizeLimit](monitoring.md#inkwallbundlenearsizelimit)."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "Programmed",
		Meaning: "Every target is wired, in a proxy whose pods run the engine.",
		Fix:     ""},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "NoTargets",
		Meaning: "None of the policy's targets exists.",
		Fix:     "Fix `targetRefs`, or create the route."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "ControllerUnsupported",
		Meaning: "A target is served by a proxy Inkwall has no integration for, or is of a kind not wired yet.",
		Fix:     "Target routes of a supported proxy; `inkwallctl status` lists the proxies."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "IntegrationDisabled",
		Meaning: "The operator may not wire the proxy that serves a target: its ClusterRole isn't granted (`rbac.integrations`).",
		Fix:     "Set the chart value to `true` (or `auto` once the proxy is installed), and `helm upgrade`."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "InjectionDisabled",
		Meaning: "The chart's `injection.enabled` is `false`: no proxy pod gets the engine, so nothing is wired.",
		Fix:     "Turn injection on."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "SidecarMissing",
		Meaning: "The proxy's pods don't run the engine: none is in the proxy namespaces, the InkwallConfig's selector doesn't match them, they were created while the operator was down, or they opted out. Their traffic isn't inspected.",
		Fix:     "Add the namespace to `injection.proxyNamespaces`, fix the selector, or restart the pods the message names."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "PendingRestart",
		Meaning: "Proxy pods started before Inkwall run without the engine (or Envoy Gateway is replacing its pods with ones that have it).",
		Fix:     "Restart them: `kubectl rollout restart`."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "Pending",
		Meaning: "Wired, but not in force yet: the proxy hasn't loaded the configuration.",
		Fix:     "Wait; if it lasts, check the proxy's logs."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "Unverified",
		Meaning: "Wired, but the operator's probe hasn't proven the filter on every pod (HAProxy, Istio), or got another answer than the engine's: the filter isn't on the route. For an Istio route in `Detect` mode: no engine reported the probe's receipt (in 30 s).",
		Fix:     "HAProxy: check the controller has the operator's snippets ([HAProxy](haproxy.md)). Istio: see [the operator's probe](istio.md#the-operators-probe); another `EnvoyFilter` may remove or bypass Inkwall's. In `Detect` mode, the pods need a 0.6.0 engine."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "NotProbeable",
		Meaning: "The operator's probe can't target an Istio route (a rule whose every match is a regular expression, a server with mutual TLS or passthrough, or header or query match values over TLS, which the probe doesn't send to a certificate it doesn't verify; in `Detect` mode, also a match only for another method than `GET` or `HEAD`), so its filter can't be proven; the message says which.",
		Fix:     "Add an exact or prefix match to the rule, or accept it unproven: [Istio](istio.md#the-operators-probe)."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "WiringFailed",
		Meaning: "The operator couldn't change the proxy's objects (a conflict, a webhook, permissions).",
		Fix:     "The message names the object and the error; `kubectl -n inkwall-system logs deploy/inkwall-operator` has more."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "ResponsesNotInspected",
		Meaning: "The policy inspects responses, but a target's proxy doesn't send them to the engine: Traefik can't (Envoy Gateway, Istio and HAProxy can); HAProxy doesn't until every controller pod's engine was injected with `--response-messages` (0.6.0 or later), and never sends streamed responses' bodies, which `responses.streams: Inspect` asks for. Its requests are inspected; the policy isn't `Programmed`, so it doesn't claim the responses are.",
		Fix:     "Traefik: remove `responses`, or target routes another proxy serves. HAProxy: restart the controller's pods the message names (with a pinned `spec.engine.image`, pin 0.6.0 or later first); for streams, set `responses.streams: Skip` or target routes Envoy Gateway or Istio serves."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "Unwired",
		Meaning: "`helm uninstall` (the unwire hook) unwired the routes and stopped the operator.",
		Fix:     "Reinstall to protect the routes again."},
	{Kind: "WAFPolicy", Condition: "Enforced", Reason: "Enforced",
		Meaning: "Every engine runs the bundle, or a later one.",
		Fix:     ""},
	{Kind: "WAFPolicy", Condition: "Enforced", Reason: "NotInBundle",
		Meaning: "The policy's current spec isn't in a published bundle yet.",
		Fix:     "Wait; if it lasts, see `Accepted`."},
	{Kind: "WAFPolicy", Condition: "Enforced", Reason: "NoEngines",
		Meaning: "No engine is connected to the operator.",
		Fix:     "Check the proxy pods run the engine (`Programmed`), and that engines reach the operator ([InkwallEngineDisconnected](monitoring.md#inkwallenginedisconnected))."},
	{Kind: "WAFPolicy", Condition: "Enforced", Reason: "EnginesBehind",
		Meaning: "Some engines don't run the bundle yet.",
		Fix:     "Usually seconds; if it lasts, `inkwallctl status` names them."},
	{Kind: "WAFPolicy", Condition: "Enforced", Reason: "EngineNack",
		Meaning: "An engine rejected the bundle; the message names it and why (often an engine older than the operator, or a key it doesn't trust).",
		Fix:     "Restart the engine's pod so it runs the operator's version; see [InkwallBundleRejected](monitoring.md#inkwallbundlerejected)."},
	{Kind: "WAFPolicy", Condition: "Enforced", Reason: "EnginesOutdated",
		Meaning: "An engine runs the bundle, but is too old to enforce a field the policy sets, which it ignores.",
		Fix:     "Restart the pod the message names."},
	{Kind: "WAFPolicy", Condition: "Enforced", Reason: "EnginesUnreported",
		Meaning: "An operator replica's engine report is full, so not every engine is known.",
		Fix:     "Run more operator replicas, or fewer proxy pods per replica."},
	{Kind: "WAFPolicy", Condition: "Enforced", Reason: "Suspended",
		Meaning: "The InkwallConfig suspends inspection: every engine allows every request.",
		Fix:     "`kubectl patch inkwallconfig default --type merge -p '{\"spec\":{\"suspend\":false}}'`."},
	{Kind: "WAFPolicy", Condition: "Ready", Reason: "Ready",
		Meaning: "`Accepted`, `Programmed` and `Enforced`: the policy is in force on every target.",
		Fix:     ""},
	{Kind: "WAFPolicy", Condition: "Ready", Reason: "NotAccepted",
		Meaning: "The operator hasn't reported `Accepted` on this generation yet. It lasts seconds.",
		Fix:     "If it lasts, check that the operator runs: `inkwallctl status`."},
	{Kind: "WAFPolicy", Condition: "Ready", Reason: "NotProgrammed",
		Meaning: "The operator hasn't reported `Programmed` on this generation yet. It lasts seconds.",
		Fix:     "If it lasts, check that the operator runs: `inkwallctl status`."},
	{Kind: "WAFPolicy", Condition: "Ready", Reason: "NotEnforced",
		Meaning: "The operator hasn't reported `Enforced` on this generation yet. It lasts seconds.",
		Fix:     "If it lasts, check that the operator runs: `inkwallctl status`."},
	{Kind: "InkwallConfig", Condition: "Suspended", Reason: "Suspended",
		Meaning: "The bundle the engines get suspends inspection (`spec.suspend`).",
		Fix:     "Resume when ready."},
	{Kind: "InkwallConfig", Condition: "Suspended", Reason: "NotSuspended",
		Meaning: "Inspection runs.",
		Fix:     ""},
	{Kind: "InkwallConfig", Condition: "SigningKeyRotation", Reason: "Idle",
		Meaning: "No signing key rotation is in progress.",
		Fix:     ""},
	{Kind: "InkwallConfig", Condition: "SigningKeyRotation", Reason: "Publishing",
		Meaning: "A rotation published the next key; the active one signs until every engine trusts it. The message, and `status.signingKey.waitingFor`, say what it waits for.",
		Fix:     "If it lasts, restart the engines the message names ([key rotation](key-rotation.md#when-a-rotation-waits))."},
	{Kind: "InkwallConfig", Condition: "SigningKeyRotation", Reason: "Retiring",
		Meaning: "The new key signs; the previous one stays trusted until every engine runs a bundle the new one signed.",
		Fix:     "As for `Publishing`."},
	{Kind: "InkwallConfig", Condition: "IntegrationsConfigured", Reason: "Configured",
		Meaning: "The integrations' proxy pod selectors apply.",
		Fix:     ""},
	{Kind: "InkwallConfig", Condition: "IntegrationsConfigured", Reason: "InvalidSelector",
		Meaning: "A `spec.integrations` selector can't be applied (an unknown operator); the operator keeps the selectors it runs with.",
		Fix:     "Fix the selector the message names."},
	{Kind: "InkwallConfig", Condition: "EngineConfigured", Reason: "Configured",
		Meaning: "The engine is injected with every `spec.engine` setting.",
		Fix:     ""},
	{Kind: "InkwallConfig", Condition: "EngineConfigured", Reason: "EngineTooOld",
		Meaning: "`spec.engine.image` pins an engine release too old for some settings (`logLevel`, `policyMetrics`, `jsonDenials`, `clientIP.trustedHops` need 0.5.0): it is injected without them, since it would exit on a flag it doesn't know. The message names them.",
		Fix:     "Pin a newer engine, or remove the settings."},
	{Kind: "InkwallConfig", Condition: "EngineConfigured", Reason: "EngineVersionUnknown",
		Meaning: "`spec.engine.image`'s tag isn't a release (`latest`, a digest alone, a custom build), so the engine is injected without the settings some release doesn't know.",
		Fix:     "Tag the image with its version, such as `:0.6.0` or `:0.6.0@sha256:...`."},
	{Kind: "InkwallConfig", Condition: "EngineRollout", Reason: "RollingOut",
		Meaning: "`spec.engine.rollout: Automatic`: the operator evicted a proxy pod for a new engine and waits for its replacement.",
		Fix:     ""},
	{Kind: "InkwallConfig", Condition: "EngineRollout", Reason: "Done",
		Meaning: "No proxy pod the operator injects needs a new engine.",
		Fix:     ""},
	{Kind: "InkwallConfig", Condition: "EngineRollout", Reason: "Paused",
		Meaning: "An eviction was refused (a PodDisruptionBudget) or a replacement isn't ready in time; nothing else is evicted. The message says which.",
		Fix:     "Relax the budget, or fix the replacement pod the message names (is the Pod webhook answering?)."},
	{Kind: "InkwallConfig", Condition: "ControlPlaneConnected", Reason: "Connected",
		Meaning: "Connected to the control plane.",
		Fix:     ""},
	{Kind: "InkwallConfig", Condition: "ControlPlaneConnected", Reason: "InvalidEndpoint",
		Meaning: "`spec.controlPlane.endpoint` isn't a valid address.",
		Fix:     "Fix it."},
	{Kind: "InkwallConfig", Condition: "ControlPlaneConnected", Reason: "EnrollmentTokenMissing",
		Meaning: "The enrollment token Secret, or its `token` key, is missing.",
		Fix:     "Create it ([control plane](control-plane.md))."},
	{Kind: "InkwallConfig", Condition: "ControlPlaneConnected", Reason: "EnrollmentTokenNotInOperatorNamespace",
		Meaning: "The token Secret isn't in the operator's namespace.",
		Fix:     "Move it there."},
	{Kind: "InkwallConfig", Condition: "ControlPlaneConnected", Reason: "EnrollmentTokenRejected",
		Meaning: "The control plane refused the token: unknown, expired or used.",
		Fix:     "Store a new token."},
	{Kind: "InkwallConfig", Condition: "ControlPlaneConnected", Reason: "EnrollFailed",
		Meaning: "Enrolling failed for another reason; the message says which.",
		Fix:     "Retry is automatic; fix what the message names."},
	{Kind: "InkwallConfig", Condition: "ControlPlaneConnected", Reason: "CertificateRejected",
		Meaning: "The control plane rejected the cluster's certificate.",
		Fix:     "Store a new enrollment token."},
	{Kind: "InkwallConfig", Condition: "ControlPlaneConnected", Reason: "CertificateExpired",
		Meaning: "The cluster's certificate expired before it was renewed.",
		Fix:     "Store a new enrollment token."},
	{Kind: "InkwallConfig", Condition: "ControlPlaneConnected", Reason: "ClusterDisabled",
		Meaning: "The control plane removed or disabled the cluster.",
		Fix:     "Change the configuration to try again."},
	{Kind: "InkwallConfig", Condition: "ControlPlaneConnected", Reason: "Unreachable",
		Meaning: "The control plane can't be reached; the operator retries. Engines enforce as before.",
		Fix:     "Check network access to the endpoint."},
	{Kind: "SecurityEvent", Condition: "reason", Reason: "rule",
		Meaning: "The rules found an attack: the anomaly score reached the policy's threshold, or a rule denies on its own.",
		Fix:     "If the request is legitimate, exclude the rules that matched, narrowly: `inkwallctl explain request` suggests the exclusion ([From a log line to an exclusion](testing-policies.md#from-a-log-line-to-an-exclusion))."},
	{Kind: "SecurityEvent", Condition: "reason", Reason: "timeout",
		Meaning: "Inspection took longer than the policy's `timeout`, so the request wasn't inspected; the policy's `failureMode` decided.",
		Fix:     "Raise `timeout`, or give the engine more CPU."},
	{Kind: "SecurityEvent", Condition: "reason", Reason: "error",
		Meaning: "The rules engine failed on the request; the policy's `failureMode` decided.",
		Fix:     "The engine's log around the event says why; report it if it repeats."},
	{Kind: "SecurityEvent", Condition: "reason", Reason: "overload",
		Meaning: "Every inspection slot of the engine was busy, so the request wasn't inspected; the policy's `failureMode` decided.",
		Fix:     "Run more proxy replicas, or give the engine more CPU; see [InkwallEvaluationSlotsSaturated](monitoring.md#inkwallevaluationslotssaturated)."},
	{Kind: "SecurityEvent", Condition: "reason", Reason: "oversize",
		Meaning: "The body is over what the policy inspects (`body.maxBytes`), and `body.onOversize` is `Deny` (the default in `Block` mode).",
		Fix:     "Raise `body.maxBytes`, or set `body.onOversize: Allow` to forward such bodies uninspected."},
	{Kind: "SecurityEvent", Condition: "reason", Reason: "websocket",
		Meaning: "A WebSocket handshake didn't meet the policy's `webSocket` settings: its origin, or a required header.",
		Fix:     "Add the origin to `webSocket.allowedOrigins`, or fix the client."},
	{Kind: "SecurityEvent", Condition: "reason", Reason: "ip-deny",
		Meaning: "The client IP is in a WAFIPList of the policy's `ipLists.deny`.",
		Fix:     "If the client is legitimate, remove its address from the list; check the client IP the engine resolved (`client_ip`)."},
	{Kind: "SecurityEvent", Condition: "reason", Reason: "grpc",
		Meaning: "A gRPC call, on a policy that refuses them (`body.grpc: Deny`).",
		Fix:     "Set `body.grpc: Allow` if the route serves gRPC ([gRPC](grpc.md))."},
}
