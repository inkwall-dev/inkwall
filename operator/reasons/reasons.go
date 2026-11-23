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
	KindWAFIPList     = "WAFIPList"
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
		Meaning: "Rules in the policy's rule set don't compile, use a directive Inkwall doesn't allow, or end in an open chain (the last `SecRule` has the `chain` action, with no rule after it to complete the chain).",
		Fix:     "Fix the rules; `inkwallctl test --rule-set` shows the error before you apply."},
	{Kind: "WAFPolicy", Condition: "Accepted", Reason: "Conflict",
		Meaning: "An older policy targets the same route and applies to it: a route has one policy.",
		Fix:     "Merge the policies, or target other routes."},
	{Kind: "WAFPolicy", Condition: "Accepted", Reason: "TargetUnsupported",
		Meaning: "A target's match rules (an IngressRoute's, HTTPRoute's or VirtualService's) aren't ones the router can match, so its requests can't be told apart.",
		Fix:     "Use the forms the message lists (`Host`, `Path`, `PathPrefix`; exact and prefix paths)."},
	{Kind: "WAFPolicy", Condition: "Accepted", Reason: "RuleSetsIncompatible",
		Meaning: "The policy's rule sets compile alone but not together, as the engine loads them (the same rule ID in two of them, or a rule that changes a rule the policy doesn't load). The policy is left out of the bundle (or keeps its previous version, if that compiles), so the other policies' bundle still applies.",
		Fix:     "Give the rules distinct IDs, or bind rule sets that load together; the message has the compiler's error."},
	{Kind: "WAFPolicy", Condition: "Accepted", Reason: "InvalidSpec",
		Meaning: "The engine can't compile the policy as it resolves: a value admission didn't refuse (saved while the webhook wasn't checking it, for example), or IP lists with more entries together than the engine takes. In the bundle it would make every engine refuse the bundle, so the policy is left out (or keeps its previous version, if that compiles) and the other policies' bundle still applies.",
		Fix:     "Fix the value the message names, or split the IP lists between policies."},
	{Kind: "WAFPolicy", Condition: "Accepted", Reason: "TargetNotAttached",
		Meaning: "A target HTTPRoute isn't accepted by a Gateway of a proxy Inkwall integrates with: no parent in its `status.parents` has `Accepted` `True`. No proxy routes its requests, so the policy doesn't apply to it.",
		Fix:     "Fix the route's `parentRefs`, or the Gateway's `allowedRoutes`; `kubectl get httproute -o yaml` shows why the Gateway didn't accept it."},
	{Kind: "WAFPolicy", Condition: "Accepted", Reason: "RouteOverlap",
		Meaning: "A route of the policy overlaps a route of a policy in another namespace, and the engine can't tell from the request which one the proxy used: a host served by two proxies or Gateways, or the same route. The overlap goes to the stricter policy (when they differ only in `mode` and `skip`), otherwise to the older one. `True`: this policy applies to the overlap; `False`: the other one does.",
		Fix:     "Serve a host from one proxy or Gateway, or don't share it between namespaces; the message names the routes and the other policy."},
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
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "ProxyVersionUnsupported",
		Meaning: "A target's proxy runs a release the operator can't tell from its pods, or doesn't wire: the HAProxy Kubernetes Ingress Controller is wired through backend config snippets on 3.1 to 3.2 and through its Backend custom resources on 3.4 and later, decided from the controller's own pods (in a proxy namespace, owned by its ReplicaSet or DaemonSet); a release before 3.1 isn't, nor is one whose image tag isn't a release (`latest`, a digest alone) when the controller's Backend CRD isn't installed (with it, such a release is wired with the Backend). The operator leaves the target's Ingress as it is: its traffic may not be inspected.",
		Fix:     "Run a supported release (the HAProxy chart's `controller.image.tag`), or, for an image whose tag isn't its release, say it in the controller pods' `waf.inkwall.dev/haproxy-controller-version` annotation (`controller.podAnnotations`, e.g. `3.4.1`); the message names the pods ([HAProxy](haproxy.md#controller-releases))."},
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
		Meaning: "Wired, but not in force yet: the proxy hasn't loaded the configuration. Or, for an HTTPRoute of Envoy Gateway or Istio, a Gateway hasn't accepted the route (or refuses it): the operator changes a Gateway only once the route's status says it accepts the route.",
		Fix:     "Wait; if it lasts, check the proxy's logs."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "Unverified",
		Meaning: "Wired, but the operator's probe hasn't proven the filter on every pod (HAProxy, Envoy Gateway, Istio), or got another answer than the engine's: the filter isn't on the route. For an Envoy Gateway or Istio route in `Detect` mode: no engine reported the probe's receipt (in 30 s). For a policy with `responses.inspect`: the probe's response leg hasn't proven yet that the route's responses reach the engine on every pod.",
		Fix:     "HAProxy: check the controller has the operator's snippets, or, on 3.4, that HAProxy didn't reject its `Backend` custom resource, which the controller then sets aside, serving the route without the filter: the message names the `Backend` to look for in the controller's log ([HAProxy](haproxy.md#controller-releases)). Istio: see [the operator's probe](istio.md#the-operators-probe); another `EnvoyFilter` may remove or bypass Inkwall's. Envoy Gateway: an `EnvoyPatchPolicy` may remove Inkwall's ext_proc filter. In `Detect` mode, the pods need a 0.6.0 engine."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "NotProbeable",
		Meaning: "The operator's probe can't target an Envoy Gateway or Istio route (a rule whose every match is a regular expression, a listener or server with mutual TLS or passthrough, or header or query match values over TLS, which the probe doesn't send to a certificate it doesn't verify; in `Detect` mode, also a match only for another method than `GET` or `HEAD`, and for a policy with `responses.inspect` in either mode, as the probe's response leg reaches the app), so its filter can't be proven; the message says which.",
		Fix:     "Add an exact or prefix match to the rule, take the client certificate requirement off the listener, or accept it unproven: [Istio](istio.md#the-operators-probe)."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "WiringFailed",
		Meaning: "The operator couldn't change the proxy's objects (a conflict, a webhook, permissions).",
		Fix:     "The message names the object and the error; `kubectl -n inkwall-system logs deploy/inkwall-operator` has more."},
	{Kind: "WAFPolicy", Condition: "Programmed", Reason: "ResponsesNotInspected",
		Meaning: "The policy inspects responses, but a target's proxy doesn't send them to the engine: Traefik can't (Envoy Gateway, Istio and HAProxy can); HAProxy doesn't until every controller pod's engine was injected with `--response-messages` (0.6.0 or later), and never sends streamed responses' bodies, which `responses.streams: Inspect` asks for; or the operator's probe shows that a pod's engine doesn't see the route's responses (HAProxy, Envoy Gateway, Istio: the probe's response leg came back without the engine's answer, or no receipt of it). Its requests are inspected; the policy isn't `Programmed`, so it doesn't claim the responses are.",
		Fix:     "Traefik: remove `responses`, or target routes another proxy serves. HAProxy: restart the controller's pods the message names (with a pinned `spec.engine.image`, pin 0.6.0 or later first); for streams, set `responses.streams: Skip` or target routes Envoy Gateway or Istio serves. A failed response probe: the message names the pod and what came back; check that the route's response rules ([HAProxy](haproxy.md#the-probe-and-programmed)) or response stage ([Istio](istio.md#the-operators-probe)) aren't overridden, and that the pod's engine has the policy's bundle."},
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
		Meaning: "Some engines don't run the bundle yet, or a proxy pod that serves the policy has an engine that isn't connected (starting or reconnecting), or, for a policy whose proxy pods the operator doesn't know (raw Envoy, the standalone proxy), an engine outside the integrations' pods that disconnected, while its pod exists (or, for an engine that reports no pod, for 2 minutes), hadn't run its current version (it keeps its older bundle until it reconnects).",
		Fix:     "Usually seconds; if it lasts, `inkwallctl status` names them; check that the pod's engine reaches the operator ([InkwallEngineDisconnected](monitoring.md#inkwallenginedisconnected))."},
	{Kind: "WAFPolicy", Condition: "Enforced", Reason: "EngineNack",
		Meaning: "An engine rejected the bundle; the message names it and why (often an engine older than the operator, or a key it doesn't trust).",
		Fix:     "Restart the engine's pod so it runs the operator's version; see [InkwallBundleRejected](monitoring.md#inkwallbundlerejected)."},
	{Kind: "WAFPolicy", Condition: "Enforced", Reason: "EnginesOutdated",
		Meaning: "An engine runs the bundle, but is too old to enforce a field the policy sets, which it ignores.",
		Fix:     "Restart the pod the message names."},
	{Kind: "WAFPolicy", Condition: "Enforced", Reason: "GeoDatabaseUnavailable",
		Meaning: "The policy has `spec.geo`, but the cluster has no country table (no `spec.geo.database` on the InkwallConfig, or none compiled yet), so geo is skipped; or some engines that run the bundle hold no table yet, where geo follows the policy's `failureMode`. `Accepted` stays `True`: the policy is valid.",
		Fix:     "Set the InkwallConfig's `spec.geo.database` and check its `GeoDatabaseReady` ([geo blocking](geo-blocking.md)); for engines without a table, check that they reach the operator."},
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
	{Kind: "WAFIPList", Condition: "Accepted", Reason: "Accepted",
		Meaning: "Every entry parses as the engines parse it.",
		Fix:     ""},
	{Kind: "WAFIPList", Condition: "Accepted", Reason: "InvalidEntries",
		Meaning: "An entry isn't an address or CIDR prefix the engines can parse (999.1.1.1, a prefix length over 32 or 128). The webhook refuses such entries, so the list was written while it was down. The policies that use the list aren't `Accepted` either (`InvalidRef`).",
		Fix:     "Fix or remove the entry the message names."},
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
		Meaning: "`spec.engine.image` pins an engine release too old for some settings (`logLevel`, `policyMetrics`, `denialFormat: JSON`, `clientIP.trustedHops` need 0.5.0): it is injected without them, since it would exit on a flag it doesn't know. The message names them.",
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
	{Kind: "InkwallConfig", Condition: "GeoDatabaseReady", Reason: "Loaded",
		Meaning: "The country database (`spec.geo.database`) is compiled into a country table and published to the engines. The message gives its type, build date, ranges and size, and says when the source is older than the stored table, or missing, and the stored table is in use.",
		Fix:     ""},
	{Kind: "InkwallConfig", Condition: "GeoDatabaseReady", Reason: "Stale",
		Meaning: "The country table is published, but its database was built more than 30 days ago: countries' ranges move every week, and vendors' terms may ask for updates.",
		Fix:     "Check the database's updater (`geoipupdate`, or whatever fills the volume or the Secret)."},
	{Kind: "InkwallConfig", Condition: "GeoDatabaseReady", Reason: "NotFound",
		Meaning: "The database file, or the Secret or its key, doesn't exist. Engines keep the last good table, if there was one.",
		Fix:     "Check `spec.geo.database`, the volume mounted at `/var/lib/inkwall/geo/`, or the Secret in the operator's namespace."},
	{Kind: "InkwallConfig", Condition: "GeoDatabaseReady", Reason: "Invalid",
		Meaning: "The source isn't a valid MaxMind DB, or reading it failed or took more than a minute. Engines keep the last good table, if there was one.",
		Fix:     "Download the database again; the message says what failed."},
	{Kind: "InkwallConfig", Condition: "GeoDatabaseReady", Reason: "NoCountryData",
		Meaning: "No record of the database has `country.iso_code`: it isn't a country database (an ASN database, or another schema).",
		Fix:     "Use a country or city database: GeoLite2 or GeoIP2 Country or City, DB-IP's Country Lite."},
	{Kind: "InkwallConfig", Condition: "GeoDatabaseReady", Reason: "TooLarge",
		Meaning: "The database is over a bound: 256 MiB of file, 16 MiB from a Secret (decompressed), 32 Mi networks (more than its tree can have), or a country table of 32 MiB (14,400 KiB compressed).",
		Fix:     "Use a country database; for a Secret, a small custom one, or a file instead."},
	{Kind: "InkwallConfig", Condition: "EventsExported", Reason: "Exporting",
		Meaning: "Every sink of `spec.events.export` succeeded on every operator replica within the status window (`--export-status-window`, 5 minutes by default), or had nothing to send. The message names the plaintext sinks (`insecure: true`).",
		Fix:     ""},
	{Kind: "InkwallConfig", Condition: "EventsExported", Reason: "ExportConfigInvalid",
		Meaning: "A sink can't start: a missing Secret or key, a CA that doesn't parse, a client certificate without its key, a refused header name, or a URL from `urlSecretRef` that isn't a valid one. The other sinks go on.",
		Fix:     "Fix what the message names, in the operator's namespace ([InkwallEventExportFailing](monitoring.md#inkwalleventexportfailing))."},
	{Kind: "InkwallConfig", Condition: "EventsExported", Reason: "ExportAddressRefused",
		Meaning: "A sink's host resolves only to addresses the operator never connects to: loopback, link-local or a cloud metadata service. The message names the class, not the address.",
		Fix:     "Point the sink at its real address ([InkwallEventExportFailing](monitoring.md#inkwalleventexportfailing))."},
	{Kind: "InkwallConfig", Condition: "EventsExported", Reason: "ExportFailing",
		Meaning: "A sink has failed for the status window (`--export-status-window`, 5 minutes by default) without a success on some replica; its events wait in that replica's buffer, which drops the oldest when full. The message names the sink, the replica and the last error class.",
		Fix:     "Check the sink's address, its NetworkPolicy egress (`networkPolicy.egress.extra`), its TLS and its credentials; auth failures go on being retried, at most a minute apart, so fixing the Secret resumes the flow ([InkwallEventExportFailing](monitoring.md#inkwalleventexportfailing))."},
	{Kind: "InkwallConfig", Condition: "EventsExported", Reason: "ExportNotReported",
		Meaning: "A live operator replica hasn't reported a sink for a minute, or no replica reports it at all: a replica still starting, an operator older than the export during a rollout, or replicas whose engine reports stopped. The message names the sink and the replica.",
		Fix:     "Usually seconds after a change or a rollout; if it lasts, check the operator's replicas (`inkwallctl status`) and their logs."},
	{Kind: "InkwallConfig", Condition: "EventsExported", Reason: "ExportDropping",
		Meaning: "A sink succeeds but dropped events for a full buffer within the status window (`--export-status-window`, 5 minutes by default): it can't keep up.",
		Fix:     "Raise the sink's `batch.maxEvents` or `batch.maxInFlight`, the buffer (`events.export.bufferMiB`, `diskMiB`), or the sink's capacity ([InkwallEventExportFailing](monitoring.md#inkwalleventexportfailing))."},
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
	{Kind: "SecurityEvent", Condition: "reason", Reason: "rate-limit",
		Meaning: "The client was over one of the policy's `rateLimits` (the event's `rate_limit`): 429 with `Retry-After` in `Block` mode. Each engine counts on its own, and limited requests are sampled: one event per client a minute, with the count in `sampled_count`.",
		Fix:     "Check the client IP the engine resolved (`client_ip`): behind a load balancer that hides it, every client shares one limit ([client IP](client-ip.md)). Otherwise raise the limit's `requests` or `burst`, or narrow its `match`."},
	{Kind: "SecurityEvent", Condition: "reason", Reason: "geo-deny",
		Meaning: "The client's country (the event's `country`, `unknown` for a public address the database has none for) is denied by the policy's `geo`: 403 in `Block` mode, logged in `Detect` or with `geo.mode: Detect`. Events are sampled: one per policy and country a minute, with the count in `sampled_count`.",
		Fix:     "Check the client IP the engine resolved (`client_ip`): it is only as right as that address ([client IP](client-ip.md)). If the country is wrong for the address, the database is out of date. Otherwise change the policy's `geo.deny` or `geo.allow`, or let a partner in through `ipLists.allow`."},
	{Kind: "SecurityEvent", Condition: "reason", Reason: "geo-unavailable",
		Meaning: "The bundle names a country table this engine doesn't hold yet (it just started without a cache, or every send of the table failed), and the policy fails closed: 503. In `Detect`, or with `failureMode: Open`, geo is skipped instead.",
		Fix:     "Check that the engine can reach the operator, and the InkwallConfig's `GeoDatabaseReady`; set the policy's `failureMode: Open` to let requests through meanwhile."},
}
