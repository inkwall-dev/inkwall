// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/flowcontrol"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// The audit log of policy changes (#726, docs/audit-log.md): the validating
// webhooks see who creates, changes or deletes each WAF object, and the
// object before and after. Once a request is admitted, the Auditor logs one
// "policy change" line for it, records an Event on the object and counts
// it. It never records a dry run, a refused request, or an update that
// leaves the spec as it was (labels, finalizers, the operator's
// annotations; the status is a subresource, which the webhooks don't see).

// AuditMessage is the audit log line's message.
const AuditMessage = "policy change"

// The audit record's bounds: a value longer than maxValue is cut, and a
// list item longer than maxItem; a list shows at most maxItems of its
// added and removed items, and the changes take at most maxChanges bytes
// of JSON: the rest are counted in changesOmitted. At most maxGroups of
// the user's groups are listed, the rest counted in groupsOmitted.
const (
	maxValue   = 128
	maxItem    = 256
	maxItems   = 5
	maxChanges = 4096
	maxGroups  = 16
	// maxNotePaths is how many changed paths an Event names.
	maxNotePaths = 8
)

// Redacted replaces a value the audit record never shows.
const Redacted = "<redacted>"

// The audit Events' reporting controller, and their timeout.
const (
	auditController   = "inkwall-operator"
	auditEventTimeout = 10 * time.Second
)

// policyChanges counts the changes the webhooks admitted.
var policyChanges = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "inkwall_operator_policy_changes_total",
	Help: "Changes to the WAF objects (WAFPolicy, WAFRuleSet, ClusterWAFRuleSet, WAFIPList, InkwallConfig) this replica's webhook admitted, by kind and operation (create, update, delete); dry runs and metadata-only updates aside.",
}, []string{"kind", "operation"})

func init() {
	metrics.Registry.MustRegister(policyChanges)
	for _, kind := range []string{"WAFPolicy", "WAFRuleSet", "ClusterWAFRuleSet", "WAFIPList", "InkwallConfig"} {
		for _, op := range []admissionv1.Operation{admissionv1.Create, admissionv1.Update, admissionv1.Delete} {
			policyChanges.WithLabelValues(kind, operation(op))
		}
	}
}

// EventWriter creates the audit Events: a client.Client.
type EventWriter interface {
	Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error
}

// Auditor records the changes the validating webhooks admit.
type Auditor struct {
	// Log gets one AuditMessage line per change, at Info.
	Log logr.Logger
	// Events creates one Event (events.k8s.io/v1) on the object for each
	// change, of its own: never a series, which an event recorder would
	// make of two users' changes, under the first one's note. Nil: none.
	Events EventWriter
	// Instance names this replica in the Events (reportingInstance).
	Instance string
	// EventLimit, if set, limits the Events (TryAccept): a burst of
	// changes, e.g. a GitOps sync of many objects, records Events up to it,
	// and is logged and counted in full.
	EventLimit flowcontrol.RateLimiter
	// Operator is the user the operator writes as (OperatorUser): its
	// changes are marked operator: true.
	Operator string

	// pending are the Events being created.
	pending sync.WaitGroup
}

// Change is one changed field of the spec, or one changed list.
type Change struct {
	// Path is the field's, e.g. spec.mode or spec.skip.paths.
	Path string `json:"path"`
	// Old and New are a scalar's values, cut to maxValue bytes, or {} for
	// an empty object; absent: unset.
	Old string `json:"old,omitempty"`
	New string `json:"new,omitempty"`
	// Added and Removed count a list's items added and removed;
	// AddedItems and RemovedItems show the first maxItems, as JSON, each
	// cut to maxItem bytes.
	Added        int      `json:"added,omitempty"`
	Removed      int      `json:"removed,omitempty"`
	AddedItems   []string `json:"addedItems,omitempty"`
	RemovedItems []string `json:"removedItems,omitempty"`
	// Reordered: the list holds the same items in another order.
	Reordered bool `json:"reordered,omitempty"`
}

// Record is one audit record: who changed what, how.
type Record struct {
	Operation       string
	Kind            string
	Namespace       string
	Name            string
	UID             string
	Generation      int64
	ResourceVersion string
	User            string
	Groups          []string
	GroupsOmitted   int
	ServiceAccount  string
	Operator        bool
	Changes         []Change
	ChangesOmitted  int
	// Paths are the first maxNotePaths changed paths, the omitted ones
	// too.
	Paths []string
}

// keysAndValues are the log line's fields, in a fixed order.
func (r Record) keysAndValues() []any {
	return []any{
		"operation", r.Operation,
		"kind", r.Kind,
		"namespace", r.Namespace,
		"name", r.Name,
		"uid", r.UID,
		"generation", r.Generation,
		"resourceVersion", r.ResourceVersion,
		"user", r.User,
		"groups", cmpNil(r.Groups),
		"groupsOmitted", r.GroupsOmitted,
		"serviceAccount", r.ServiceAccount,
		"operator", r.Operator,
		"changes", cmpNil(r.Changes),
		"changesOmitted", r.ChangesOmitted,
	}
}

// cmpNil makes a nil slice empty, so the line holds [] rather than null.
func cmpNil[S ~[]E, E any](s S) S {
	if s == nil {
		return S{}
	}
	return s
}

// audited records each change its Validator admits.
type audited[T client.Object] struct {
	admission.Validator[T]
	audit *Auditor
}

func (a audited[T]) ValidateCreate(ctx context.Context, obj T) (admission.Warnings, error) {
	warnings, err := a.Validator.ValidateCreate(ctx, obj)
	if err == nil {
		a.audit.record(ctx, admissionv1.Create, nil, obj)
	}
	return warnings, err
}

func (a audited[T]) ValidateUpdate(ctx context.Context, oldObj, newObj T) (admission.Warnings, error) {
	warnings, err := a.Validator.ValidateUpdate(ctx, oldObj, newObj)
	if err == nil {
		a.audit.record(ctx, admissionv1.Update, oldObj, newObj)
	}
	return warnings, err
}

func (a audited[T]) ValidateDelete(ctx context.Context, obj T) (admission.Warnings, error) {
	warnings, err := a.Validator.ValidateDelete(ctx, obj)
	if err == nil {
		a.audit.record(ctx, admissionv1.Delete, obj, nil)
	}
	return warnings, err
}

// record logs, records and counts an admitted change: oldObj is nil on
// create, newObj on delete.
func (a *Auditor) record(ctx context.Context, op admissionv1.Operation, oldObj, newObj client.Object) {
	if a == nil {
		return
	}
	req, err := admission.RequestFromContext(ctx)
	if err != nil || (req.DryRun != nil && *req.DryRun) {
		return
	}
	var oldSpec, newSpec any
	if oldObj != nil {
		oldSpec = spec(oldObj)
	}
	if newObj != nil {
		newSpec = spec(newObj)
	}
	if op == admissionv1.Update && apiequality.Semantic.DeepEqual(oldSpec, newSpec) {
		return
	}
	obj := newObj
	if obj == nil {
		obj = oldObj
	}
	// userInfo.extra is never read: it may carry credentials.
	groups := req.UserInfo.Groups
	r := Record{
		Operation:      operation(op),
		Kind:           req.Kind.Kind,
		Namespace:      obj.GetNamespace(),
		Name:           obj.GetName(),
		UID:            string(obj.GetUID()),
		Generation:     obj.GetGeneration(),
		User:           req.UserInfo.Username,
		Groups:         slices.Clone(groups[:min(len(groups), maxGroups)]),
		GroupsOmitted:  max(len(groups)-maxGroups, 0),
		ServiceAccount: serviceAccount(req.UserInfo.Username),
		Operator:       a.Operator != "" && req.UserInfo.Username == a.Operator,
	}
	if oldObj != nil {
		r.ResourceVersion = oldObj.GetResourceVersion()
	}
	r.Changes, r.ChangesOmitted, r.Paths = Summarize(toJSON(oldSpec), toJSON(newSpec))
	a.Log.Info(AuditMessage, r.keysAndValues()...)
	policyChanges.WithLabelValues(r.Kind, r.Operation).Inc()
	if a.Events != nil && (a.EventLimit == nil || a.EventLimit.TryAccept()) {
		a.createEvent(a.event(obj, schema.GroupVersion{Group: req.Kind.Group, Version: req.Kind.Version}, op, r))
	}
}

// event is the Event on obj for the change r.
func (a *Auditor) event(obj client.Object, gv schema.GroupVersion, op admissionv1.Operation, r Record) *eventsv1.Event {
	reason, action := eventReason(op)
	ns := obj.GetNamespace()
	if ns == "" {
		ns = metav1.NamespaceDefault // a cluster-scoped object's
	}
	instance := auditController
	if a.Instance != "" {
		instance += "-" + a.Instance
	}
	return &eventsv1.Event{
		ObjectMeta:          metav1.ObjectMeta{Namespace: ns, GenerateName: eventPrefix(obj.GetName())},
		EventTime:           metav1.NewMicroTime(time.Now()),
		ReportingController: auditController,
		ReportingInstance:   cut(instance, 128),
		Action:              action,
		Reason:              reason,
		Type:                corev1.EventTypeNormal,
		Note:                r.note(),
		Regarding: corev1.ObjectReference{
			APIVersion:      gv.String(),
			Kind:            r.Kind,
			Namespace:       obj.GetNamespace(),
			Name:            obj.GetName(),
			UID:             obj.GetUID(),
			ResourceVersion: obj.GetResourceVersion(),
		},
	}
}

// eventPrefix is the generateName of an Event on the object name: name
// (a DNS subdomain) cut so the prefix fits the 253 characters, ending in
// ".audit-", which only a trailing dash may (the API server adds five
// characters, and shortens a long prefix to fit).
func eventPrefix(name string) string {
	const suffix = ".audit-"
	if len(name) > 253-len(suffix)-5 {
		name = strings.TrimRight(name[:253-len(suffix)-5], ".-")
	}
	return name + suffix
}

// createEvent creates e in the background: the API server waits for the
// webhook's answer.
func (a *Auditor) createEvent(e *eventsv1.Event) {
	a.pending.Add(1)
	go func() {
		defer a.pending.Done()
		ctx, cancel := context.WithTimeout(context.Background(), auditEventTimeout)
		defer cancel()
		if err := a.Events.Create(ctx, e); err != nil {
			a.Log.Error(err, "policy change Event not recorded", "namespace", e.Regarding.Namespace, "name", e.Regarding.Name, "reason", e.Reason)
		}
	}()
}

// operation is op as the record and the metric name it.
func operation(op admissionv1.Operation) string { return strings.ToLower(string(op)) }

// eventReason is the Event's reason and action for op.
func eventReason(op admissionv1.Operation) (reason, action string) {
	switch op {
	case admissionv1.Create:
		return "Created", "Create"
	case admissionv1.Delete:
		return "Deleted", "Delete"
	}
	return "Changed", "Update"
}

// note is the Event's message: who, and the changed paths.
func (r Record) note() string {
	who := r.User
	if r.Operator {
		who = "the operator"
	}
	verb := map[string]string{"create": "Created", "update": "Changed", "delete": "Deleted"}[r.Operation]
	note := verb + " by " + who
	if r.Operation == "delete" || len(r.Paths) == 0 {
		return note
	}
	paths := r.Paths[:min(len(r.Paths), maxNotePaths)]
	more := ""
	if n := len(r.Changes) + r.ChangesOmitted - len(paths); n > 0 {
		more = fmt.Sprintf(" and %d more", n)
	}
	return cut(note+": "+strings.Join(paths, ", ")+more, 1000)
}

// serviceAccount is "namespace/name" for a ServiceAccount's user name.
func serviceAccount(user string) string {
	rest, ok := strings.CutPrefix(user, "system:serviceaccount:")
	if !ok {
		return ""
	}
	ns, name, ok := strings.Cut(rest, ":")
	if !ok {
		return ""
	}
	return ns + "/" + name
}

// toJSON is v as generic JSON (maps, lists, json.Number, strings, bools),
// or nil.
func toJSON(v any) any {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var out any
	if d.Decode(&out) != nil {
		return nil
	}
	return out
}

// summary collects the changes up to the bounds, and counts the rest.
type summary struct {
	changes []Change
	size    int
	omitted int
	paths   []string
}

// full: no more change is shown, only counted.
func (s *summary) full() bool { return s.omitted > 0 }

func (s *summary) add(c Change) {
	if len(s.paths) < maxNotePaths {
		s.paths = append(s.paths, c.Path)
	}
	if !s.full() {
		raw, _ := json.Marshal(c)
		if s.size+len(raw)+1 <= maxChanges {
			s.size += len(raw) + 1
			s.changes = append(s.changes, c)
			return
		}
	}
	s.omitted++
}

// Summarize compares two specs as generic JSON (nil: none, on create or
// delete), and returns the changes that fit in maxChanges bytes, how many
// more there were, and the first maxNotePaths changed paths. Values are
// redacted (fieldMode).
func Summarize(oldSpec, newSpec any) (changes []Change, omitted int, paths []string) {
	var s summary
	diff("spec", oldSpec, newSpec, modePlain, &s)
	return s.changes, s.omitted, s.paths
}

// mode is how a field's values are shown.
type mode int

const (
	modePlain mode = iota
	// modeURL shows a URL's scheme and host only: its path or query may
	// hold a token.
	modeURL
	// modeSecret shows nothing.
	modeSecret
)

// The field names whose values are never shown, and those shown as a URL's
// scheme and host: the names themselves (token, apiKey), and camel-case
// names ending in them (bearerToken, clientSecret). None of the five kinds
// holds a credential today, only Secrets' names (caSecretRef, ...), which
// are shown; these keep a field added later from slipping through, and
// TestAuditFieldNames lists every field of the kinds' specs. A field named
// key (a rate limit's, a ConfigMap's or Secret's key) is not one.
var (
	secretName = regexp.MustCompile(`^(?i:token|password|passphrase|secret|apiKey|privateKey|credentials?)$|` +
		`[a-z0-9](Token|Password|Passphrase|Secret|APIKey|ApiKey|PrivateKey|Credentials?)$`)
	urlName = regexp.MustCompile(`^(?i:url|uri|endpoint)$|[a-z0-9](URL|Url|URI|Uri|Endpoint)$`)
	// Under spec.events.export, header fields are never shown: a sink's
	// headers carry its credentials.
	exportHeader = regexp.MustCompile(`(?i)header`)
)

// exportPath is the export sinks' configuration.
const exportPath = "spec.events.export"

// fieldMode is the mode of path's field name, under parent's: a mode only
// gets stricter down the tree.
func fieldMode(parent mode, path, name string) mode {
	m := parent
	switch {
	case secretName.MatchString(name),
		(path == exportPath || strings.HasPrefix(path, exportPath+".")) && exportHeader.MatchString(name):
		m = max(m, modeSecret)
	case urlName.MatchString(name):
		m = max(m, modeURL)
	}
	return m
}

// identifier matches the map keys a path names with a dot.
var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func child(path, key string) string {
	if identifier.MatchString(key) {
		return path + "." + key
	}
	return path + "[" + quote(key) + "]"
}

func quote(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

// diff adds the changes from old to new under path to s.
func diff(path string, old, new any, m mode, s *summary) {
	oldMap, oldIsMap := old.(map[string]any)
	newMap, newIsMap := new.(map[string]any)
	_, oldIsList := old.([]any)
	_, newIsList := new.([]any)
	switch {
	case (oldIsMap || old == nil) && (newIsMap || new == nil) && (oldIsMap || newIsMap):
		if (old == nil && len(newMap) == 0) || (new == nil && len(oldMap) == 0) {
			// An empty object set or unset, e.g. a switch such as a rate
			// limit's key: {clientIP: {}}.
			s.add(Change{Path: path, Old: show(path, old, m), New: show(path, new, m)})
			return
		}
		// The larger side's keys fit, without a sum that could overflow;
		// append grows it for the keys only one side has.
		keys := make([]string, 0, max(len(oldMap), len(newMap)))
		for k := range oldMap {
			keys = append(keys, k)
		}
		for k := range newMap {
			if _, ok := oldMap[k]; !ok {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		for _, k := range keys {
			diff(child(path, k), oldMap[k], newMap[k], fieldMode(m, path, k), s)
		}
	case (oldIsList || old == nil) && (newIsList || new == nil) && (oldIsList || newIsList):
		if c, ok := diffList(path, old, new, m, !s.full()); ok {
			s.add(c)
		}
	case !apiequality.Semantic.DeepEqual(old, new):
		s.add(Change{Path: path, Old: show(path, old, m), New: show(path, new, m)})
	}
}

// diffList compares two lists as multisets of their items; it renders the
// items it shows only if shown.
func diffList(path string, old, new any, m mode, shown bool) (Change, bool) {
	oldList, _ := old.([]any)
	newList, _ := new.([]any)
	render := func(v any) string {
		raw, _ := json.Marshal(redactTree(path, v, m))
		return cut(string(raw), maxItem)
	}
	// Compare the raw items, so a change hidden by redaction still counts.
	key := func(v any) string {
		raw, _ := json.Marshal(v)
		return string(raw)
	}
	left := map[string]int{}
	for _, v := range oldList {
		left[key(v)]++
	}
	c := Change{Path: path}
	for _, v := range newList {
		if k := key(v); left[k] > 0 {
			left[k]--
			continue
		}
		c.Added++
		if shown && len(c.AddedItems) < maxItems {
			c.AddedItems = append(c.AddedItems, render(v))
		}
	}
	right := map[string]int{}
	for _, v := range newList {
		right[key(v)]++
	}
	for _, v := range oldList {
		if k := key(v); right[k] > 0 {
			right[k]--
			continue
		}
		c.Removed++
		if shown && len(c.RemovedItems) < maxItems {
			c.RemovedItems = append(c.RemovedItems, render(v))
		}
	}
	if c.Added == 0 && c.Removed == 0 {
		// The same items: unchanged (an empty list is as good as none), or
		// in another order.
		if len(oldList) == 0 || key(oldList) == key(newList) {
			return c, false
		}
		c.Reordered = true
	}
	return c, true
}

// redactTree is v with every value shown as its field's mode allows.
func redactTree(path string, v any, m mode) any {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, e := range v {
			out[k] = redactTree(child(path, k), e, fieldMode(m, path, k))
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = redactTree(path, e, m)
		}
		return out
	case nil:
		return nil
	}
	switch m {
	case modeSecret:
		return Redacted
	case modeURL:
		return scalar(v, m)
	}
	return v
}

// show is v as its mode allows: a scalar, or a map or list (an empty
// object, or where the schema changed its type) as redacted JSON.
func show(path string, v any, m mode) string {
	switch v.(type) {
	case map[string]any, []any:
		raw, _ := json.Marshal(redactTree(path, v, m))
		return cut(string(raw), maxValue)
	}
	return scalar(v, m)
}

// scalar shows v as its mode allows, cut to maxValue bytes; "" for nil.
func scalar(v any, m mode) string {
	if v == nil {
		return ""
	}
	var s string
	switch v := v.(type) {
	case string:
		s = v
	default:
		raw, _ := json.Marshal(v)
		s = string(raw)
	}
	switch m {
	case modeSecret:
		return Redacted
	case modeURL:
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return Redacted
		}
		// Host keeps no user information; the path and query may hold a
		// token.
		return u.Scheme + "://" + u.Host
	}
	return cut(s, maxValue)
}

// cut shortens s to at most n bytes, ending in "…", on a rune boundary.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const ellipsis = "…"
	i := n - len(ellipsis)
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i] + ellipsis
}
