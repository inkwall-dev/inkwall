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
	"unicode/utf8"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/client-go/tools/events"
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
// of JSON: the rest are counted in changesOmitted.
const (
	maxValue   = 128
	maxItem    = 256
	maxItems   = 5
	maxChanges = 4096
	// maxNotePaths is how many changed paths an Event names.
	maxNotePaths = 8
)

// Redacted replaces a value the audit record never shows.
const Redacted = "<redacted>"

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

// Auditor records the changes the validating webhooks admit.
type Auditor struct {
	// Log gets one AuditMessage line per change, at Info.
	Log logr.Logger
	// Recorder records an Event on the changed object; nil: none.
	Recorder events.EventRecorder
	// EventLimit, if set, limits the Events (TryAccept): a burst of
	// changes, e.g. a GitOps sync of many objects, records Events up to it,
	// and is logged and counted in full.
	EventLimit flowcontrol.RateLimiter
	// Operator is the user the operator writes as (OperatorUser): its
	// changes are marked operator: true.
	Operator string
}

// Change is one changed field of the spec, or one changed list.
type Change struct {
	// Path is the field's, e.g. spec.mode or spec.skip.paths.
	Path string `json:"path"`
	// Old and New are a scalar's values, cut to maxValue bytes; absent:
	// unset.
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
	ServiceAccount  string
	Operator        bool
	Changes         []Change
	ChangesOmitted  int
	// Paths are every changed path, the omitted ones too.
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
	r := Record{
		Operation:  operation(op),
		Kind:       req.Kind.Kind,
		Namespace:  obj.GetNamespace(),
		Name:       obj.GetName(),
		UID:        string(obj.GetUID()),
		Generation: obj.GetGeneration(),
		User:       req.UserInfo.Username,
		// userInfo.extra is never read: it may carry credentials.
		Groups:         slices.Clone(req.UserInfo.Groups),
		ServiceAccount: serviceAccount(req.UserInfo.Username),
		Operator:       a.Operator != "" && req.UserInfo.Username == a.Operator,
	}
	if oldObj != nil {
		r.ResourceVersion = oldObj.GetResourceVersion()
	}
	r.Changes, r.ChangesOmitted, r.Paths = Summarize(toJSON(oldSpec), toJSON(newSpec))
	a.Log.Info(AuditMessage, r.keysAndValues()...)
	policyChanges.WithLabelValues(r.Kind, r.Operation).Inc()
	if a.Recorder != nil && (a.EventLimit == nil || a.EventLimit.TryAccept()) {
		reason, action := eventReason(op)
		a.Recorder.Eventf(obj, nil, corev1.EventTypeNormal, reason, action, "%s", r.note())
	}
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
	paths := r.Paths
	more := ""
	if len(paths) > maxNotePaths {
		more = fmt.Sprintf(" and %d more", len(paths)-maxNotePaths)
		paths = paths[:maxNotePaths]
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

// Summarize compares two specs as generic JSON (nil: none, on create or
// delete), and returns the changes that fit in maxChanges bytes, how many
// more there were, and every changed path. Values are redacted (redact).
func Summarize(oldSpec, newSpec any) (changes []Change, omitted int, paths []string) {
	var all []Change
	diff("spec", oldSpec, newSpec, modePlain, &all)
	size := 0
	for i, c := range all {
		paths = append(paths, c.Path)
		raw, _ := json.Marshal(c)
		if size+len(raw)+1 > maxChanges {
			omitted = len(all) - i
			for _, c := range all[i+1:] {
				paths = append(paths, c.Path)
			}
			break
		}
		size += len(raw) + 1
		changes = append(changes, c)
	}
	return changes, omitted, paths
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

// sensitiveName matches field names whose values may be credentials, and
// urlName those that hold endpoints.
var (
	sensitiveName = regexp.MustCompile(`(?i)token|password|secret|key`)
	urlName       = regexp.MustCompile(`(?i)url|endpoint`)
	exportHeader  = regexp.MustCompile(`(?i)header`)
)

// fieldMode is the mode of path's field name, under parent's: a mode only
// gets stricter down the tree. An export sink's headers are never shown.
func fieldMode(parent mode, path, name string) mode {
	m := parent
	switch {
	case sensitiveName.MatchString(name),
		strings.HasPrefix(path, "spec.events.export") && exportHeader.MatchString(name):
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

// diff appends the changes from old to new under path.
func diff(path string, old, new any, m mode, out *[]Change) {
	oldMap, oldIsMap := old.(map[string]any)
	newMap, newIsMap := new.(map[string]any)
	_, oldIsList := old.([]any)
	_, newIsList := new.([]any)
	switch {
	case (oldIsMap || old == nil) && (newIsMap || new == nil) && (oldIsMap || newIsMap):
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
			diff(child(path, k), oldMap[k], newMap[k], fieldMode(m, path, k), out)
		}
	case (oldIsList || old == nil) && (newIsList || new == nil) && (oldIsList || newIsList):
		if c, ok := diffList(path, old, new, m); ok {
			*out = append(*out, c)
		}
	case !apiequality.Semantic.DeepEqual(old, new):
		*out = append(*out, Change{Path: path, Old: show(path, old, m), New: show(path, new, m)})
	}
}

// diffList compares two lists as multisets of their items.
func diffList(path string, old, new any, m mode) (Change, bool) {
	oldList, _ := old.([]any)
	newList, _ := new.([]any)
	render := func(l []any) []string {
		out := make([]string, len(l))
		for i, v := range l {
			raw, _ := json.Marshal(redactTree(path, v, m))
			out[i] = string(raw)
		}
		return out
	}
	// Compare the raw items, so a change hidden by redaction still counts.
	key := func(v any) string {
		raw, _ := json.Marshal(v)
		return string(raw)
	}
	oldShown, newShown := render(oldList), render(newList)
	left := map[string]int{}
	for _, v := range oldList {
		left[key(v)]++
	}
	c := Change{Path: path}
	for i, v := range newList {
		if k := key(v); left[k] > 0 {
			left[k]--
			continue
		}
		c.Added++
		if len(c.AddedItems) < maxItems {
			c.AddedItems = append(c.AddedItems, cut(newShown[i], maxItem))
		}
	}
	right := map[string]int{}
	for _, v := range newList {
		right[key(v)]++
	}
	for i, v := range oldList {
		if k := key(v); right[k] > 0 {
			right[k]--
			continue
		}
		c.Removed++
		if len(c.RemovedItems) < maxItems {
			c.RemovedItems = append(c.RemovedItems, cut(oldShown[i], maxItem))
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
			// An empty object (an unset struct) says nothing.
			if e, ok := e.(map[string]any); ok && len(e) == 0 {
				continue
			}
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

// show is v as its mode allows: a scalar, or (where the schema changed
// its type) a map or list as redacted JSON.
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
