// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package httpadapter holds request handling shared by the adapters that
// receive requests over net/http: the reverse proxy and forward-auth.
package httpadapter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// SnapshotHeaders returns a private copy of r's headers for inspection, with
// Transfer-Encoding and Content-Length restored.
//
// The copy matters because an evaluation that times out keeps running after
// the handler has returned, and must not read the live request. Copying costs
// about 0.3µs, well under 0.1% of an evaluation.
//
// net/http moves Transfer-Encoding out of the header map, and Content-Length
// can be absent (HTTP/2) even when the length is known. Without them, rules see
// a POST with neither header and raise a false positive.
func SnapshotHeaders(r *http.Request) http.Header {
	h := r.Header.Clone()
	if h == nil {
		h = http.Header{}
	}
	if len(r.TransferEncoding) > 0 && h.Get("Transfer-Encoding") == "" {
		h["Transfer-Encoding"] = r.TransferEncoding
	}
	if r.ContentLength > 0 && h.Get("Content-Length") == "" {
		h.Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	return h
}

// NewRequestID returns a random 16-hex-digit request ID.
func NewRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails on supported platforms
	return hex.EncodeToString(b[:])
}

// maxRequestIDLen bounds client-supplied request IDs.
const maxRequestIDLen = 128

// RequestID returns id if it is a safe correlation ID (at most 128 of
// [A-Za-z0-9._:-]), and "" otherwise so that one is generated. The value is
// client-controlled and ends up in logs and events.
func RequestID(id string) string {
	if id == "" || len(id) > maxRequestIDLen {
		return ""
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == ':', c == '-':
		default:
			return ""
		}
	}
	return id
}

// PeerAddr parses the address of the direct TCP peer from r.RemoteAddr.
func PeerAddr(remoteAddr string) netip.Addr {
	if ap, err := netip.ParseAddrPort(remoteAddr); err == nil {
		return ap.Addr().Unmap()
	}
	if a, err := netip.ParseAddr(remoteAddr); err == nil {
		return a.Unmap()
	}
	return netip.Addr{}
}

// IsEvent reports whether a verdict is logged as a security event: blocks and
// detections, and every request that went uninspected unexpectedly (timeout,
// error, overload). Client cancellations and routes configured to skip
// inspection are not events.
func IsEvent(v pipeline.Verdict) bool {
	return v.Action != pipeline.ActionAllow ||
		(v.Reason != pipeline.ReasonNone && v.Reason != pipeline.ReasonCanceled && v.Reason != pipeline.ReasonSkipped)
}

// LogEvent writes one security event for req.
func LogEvent(ctx context.Context, logger *slog.Logger, req *request.Request, path string, v pipeline.Verdict) {
	logger.LogAttrs(ctx, slog.LevelWarn, "security event",
		slog.String("action", v.Action.String()),
		slog.String("reason", v.Reason.String()),
		slog.Int("status", v.Status),
		slog.Int("interrupting_rule_id", v.InterruptingRuleID),
		slog.Any("rule_ids", v.RuleIDs),
		slog.String("client_ip", addrString(req.ClientIP)),
		slog.String("method", req.Method),
		slog.String("host", req.Host),
		slog.String("path", path),
		slog.String("request_id", req.ID),
		slog.Duration("inspection_time", v.Duration),
	)
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
