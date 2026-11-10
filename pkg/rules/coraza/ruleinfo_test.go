// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"strings"
	"testing"
)

// The descriptions come from the embedded rules, not from a list of our own
// (#438).
func TestEmbeddedRule(t *testing.T) {
	for _, tc := range []struct {
		id       int
		message  string
		severity string
		pl       int
		file     string
	}{
		{942100, "SQL Injection Attack Detected via libinjection", "critical", 1, "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"},
		{941100, "XSS Attack Detected via libinjection", "critical", 1, "REQUEST-941-APPLICATION-ATTACK-XSS.conf"},
		{949110, "Inbound Anomaly Score Exceeded", "", 0, "REQUEST-949-BLOCKING-EVALUATION.conf"},
		{200004, "Argument limit reached; request rejected (GET/PATH args)", "", 0, ""},
	} {
		ri, ok, err := EmbeddedRule(tc.id)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("%d: not found", tc.id)
			continue
		}
		if !strings.HasPrefix(ri.Message, tc.message) || ri.Severity != tc.severity || ri.ParanoiaLevel != tc.pl || !strings.HasSuffix(ri.File, tc.file) {
			t.Errorf("%d: %+v, want message %q, severity %q, paranoia level %d, file %q", tc.id, ri, tc.message, tc.severity, tc.pl, tc.file)
		}
	}
	// A macro would be expanded with the request's data: the message
	// leaves it out.
	if ri, _, _ := EmbeddedRule(949110); ri.Message != "Inbound Anomaly Score Exceeded" {
		t.Errorf("949110: message %q, want it without the macro", ri.Message)
	}
	if _, ok, _ := EmbeddedRule(1000001); ok {
		t.Error("a custom rule's ID is described as an embedded rule")
	}
	// Every CRS detection rule has a message.
	info, err := embeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	ids, err := CRSRuleIDs()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if id >= 920000 && id < 949000 && info[id].Severity != "" && info[id].Message == "" {
			t.Errorf("CRS rule %d has a severity but no message", id)
		}
	}
}
