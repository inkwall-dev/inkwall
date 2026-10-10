// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package httpcheck implements POST /v1/check, the engine's own check API
// (api/engine/v1). It serves proxies without a native protocol (the
// ingress-nginx Lua plugin, the Traefik plugin), inkwallctl and tests.
//
// The caller describes one client request in a CheckRequest, protobuf
// (Content-Type: application/x-protobuf) or JSON (application/json), and
// gets the verdict back in a CheckResponse in the same encoding. Any
// well-formed check is answered with 200; the verdict is in the body.
//
// The caller is trusted: the engine inspects the request it describes and
// takes its client_ip as given. Listen only where the proxy alone can reach
// it (a Unix socket or localhost).
package httpcheck

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	"github.com/inkwall-dev/inkwall/pkg/adapters/internal/httpadapter"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// Path is where check requests are sent.
const Path = "/v1/check"

// Content types of the two encodings.
const (
	ContentTypeProtobuf = "application/x-protobuf"
	ContentTypeJSON     = "application/json"
)

// envelope bounds the encoded CheckRequest beyond the body it carries:
// method, URI and headers.
const envelope = 1 << 20

// Config configures a Handler.
type Config struct {
	// MaxBodyBytes is how much of a request body is inspected; longer bodies
	// are treated as truncated. Zero disables body inspection.
	MaxBodyBytes int64
	// Logger receives one security event per denied or logged request.
	// Nil uses slog.Default().
	Logger *slog.Logger
}

// Handler answers check requests.
type Handler struct {
	pipeline *pipeline.Pipeline
	maxBody  int64
	logger   *slog.Logger
}

// New returns a Handler that inspects requests with p.
func New(p *pipeline.Pipeline, cfg Config) (*Handler, error) {
	if cfg.MaxBodyBytes < 0 {
		return nil, fmt.Errorf("max body bytes %d must not be negative", cfg.MaxBodyBytes)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{pipeline: p, maxBody: cfg.MaxBodyBytes, logger: logger}, nil
}

var jsonOut = protojson.MarshalOptions{UseProtoNames: true}

// ServeHTTP decodes a CheckRequest, inspects the request it describes and
// writes the CheckResponse.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != Path {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	isJSON, err := encoding(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBody+envelope))
	if err != nil {
		if errors.As(err, new(*http.MaxBytesError)) {
			http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read check request: "+err.Error(), http.StatusBadRequest)
		return
	}
	var in enginev1.CheckRequest
	if isJSON {
		err = protojson.Unmarshal(raw, &in)
	} else {
		err = proto.Unmarshal(raw, &in)
	}
	if err != nil {
		http.Error(w, "decode check request: "+err.Error(), http.StatusBadRequest)
		return
	}
	req, path, err := h.toRequest(&in)
	if err != nil {
		http.Error(w, "invalid check request: "+err.Error(), http.StatusBadRequest)
		return
	}

	v := h.pipeline.Check(r.Context(), req)
	if httpadapter.IsEvent(v) {
		httpadapter.LogEvent(r.Context(), h.logger, req, path, v)
	}

	out := toResponse(req.ID, v)
	var body []byte
	if isJSON {
		w.Header().Set("Content-Type", ContentTypeJSON)
		body, err = jsonOut.Marshal(out)
	} else {
		w.Header().Set("Content-Type", ContentTypeProtobuf)
		body, err = proto.Marshal(out)
	}
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(body)
}

// encoding reports whether a Content-Type selects JSON (true) or protobuf.
func encoding(contentType string) (bool, error) {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false, fmt.Errorf("content type %q: want %s or %s", contentType, ContentTypeProtobuf, ContentTypeJSON)
	}
	switch mt {
	case ContentTypeJSON:
		return true, nil
	case ContentTypeProtobuf, "application/protobuf":
		return false, nil
	default:
		return false, fmt.Errorf("content type %q: want %s or %s", mt, ContentTypeProtobuf, ContentTypeJSON)
	}
}

// toRequest validates a CheckRequest and converts it. It also returns the
// decoded path for logging.
func (h *Handler) toRequest(in *enginev1.CheckRequest) (*request.Request, string, error) {
	if !httpadapter.IsToken(in.GetMethod()) {
		return nil, "", fmt.Errorf("invalid method %q", in.GetMethod())
	}
	path, err := httpadapter.URIPath(in.GetRawUri())
	if err != nil {
		return nil, "", fmt.Errorf("raw_uri: %w", err)
	}
	scheme := "http"
	switch s := strings.ToLower(in.GetScheme()); s {
	case "", "http":
	case "https":
		scheme = s
	default:
		return nil, "", fmt.Errorf("invalid scheme %q", in.GetScheme())
	}
	proto := in.GetProtocol()
	if proto == "" {
		proto = "HTTP/1.1"
	}
	peer, err := parseAddr("peer_ip", in.GetPeerIp())
	if err != nil {
		return nil, "", err
	}
	client, err := parseAddr("client_ip", in.GetClientIp())
	if err != nil {
		return nil, "", err
	}
	if !client.IsValid() {
		client = peer
	}

	headers := make(http.Header, len(in.GetHeaders()))
	for _, hf := range in.GetHeaders() {
		name := hf.GetName()
		if !httpadapter.IsToken(name) {
			return nil, "", fmt.Errorf("invalid header name %q", name)
		}
		// The authority travels in its own field, as in request.Request.
		if strings.EqualFold(name, "Host") {
			continue
		}
		value := hf.GetValue()
		if raw := hf.GetRawValue(); len(raw) > 0 {
			value = string(raw)
		}
		headers.Add(name, value)
	}

	id := httpadapter.RequestID(in.GetRequestId())
	if id == "" {
		id = httpadapter.NewRequestID()
	}
	req := &request.Request{
		ID:       id,
		Proto:    proto,
		Method:   in.GetMethod(),
		Scheme:   scheme,
		Host:     in.GetAuthority(),
		RawURI:   in.GetRawUri(),
		Headers:  headers,
		ClientIP: client,
		PeerIP:   peer,
	}
	if h.maxBody > 0 {
		body := in.GetBody()
		if int64(len(body)) > h.maxBody {
			req.Body = body[:h.maxBody]
			req.BodyTruncated = true
		} else {
			req.Body = body
			req.BodyTruncated = in.GetBodyTruncated()
		}
	}
	return req, path, nil
}

func parseAddr(field, s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%s: %w", field, err)
	}
	return a.Unmap(), nil
}

func toResponse(id string, v pipeline.Verdict) *enginev1.CheckResponse {
	ids := make([]uint32, 0, len(v.RuleIDs))
	for _, rid := range v.RuleIDs {
		ids = append(ids, uint32(rid)) // #nosec G115 -- rule IDs are positive and below 2^32
	}
	return &enginev1.CheckResponse{
		Action:             action(v.Action),
		Status:             uint32(v.Status), // #nosec G115 -- an HTTP status
		ResponseHeaders:    []*enginev1.Header{{Name: "X-Request-Id", Value: id}},
		RuleIds:            ids,
		Reason:             reason(v.Reason),
		InterruptingRuleId: uint32(v.InterruptingRuleID), // #nosec G115 -- a rule ID
		RequestId:          id,
		InspectionTime:     durationpb.New(v.Duration),
	}
}

func action(a pipeline.Action) enginev1.Action {
	switch a {
	case pipeline.ActionAllow:
		return enginev1.Action_ACTION_ALLOW
	case pipeline.ActionDeny:
		return enginev1.Action_ACTION_DENY
	case pipeline.ActionLog:
		return enginev1.Action_ACTION_LOG
	default:
		return enginev1.Action_ACTION_UNSPECIFIED
	}
}

func reason(r pipeline.Reason) enginev1.Reason {
	switch r {
	case pipeline.ReasonNone:
		return enginev1.Reason_REASON_NONE
	case pipeline.ReasonRule:
		return enginev1.Reason_REASON_RULE
	case pipeline.ReasonTimeout:
		return enginev1.Reason_REASON_TIMEOUT
	case pipeline.ReasonError:
		return enginev1.Reason_REASON_ERROR
	case pipeline.ReasonCanceled:
		return enginev1.Reason_REASON_CANCELED
	case pipeline.ReasonOverload:
		return enginev1.Reason_REASON_OVERLOAD
	case pipeline.ReasonOversize:
		return enginev1.Reason_REASON_OVERSIZE
	case pipeline.ReasonSkipped:
		return enginev1.Reason_REASON_SKIPPED
	default:
		return enginev1.Reason_REASON_UNSPECIFIED
	}
}
