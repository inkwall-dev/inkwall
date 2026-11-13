// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/inkwall-dev/inkwall/operator/enginereport"
)

// The report a replica writes (Engine) is what enginereport, and with it
// inkwallctl status, reads: every field survives the trip.
func TestEngineReportFields(t *testing.T) {
	e := Engine{
		ID: "e1", ServiceAccount: "traefik/traefik", PodNamespace: "traefik", PodName: "traefik-1", NodeName: "n1",
		EngineVersion: "v0.5.0", Applied: 7, Rejected: 8, RejectError: "bad", TrustedKeys: []string{"k1"},
		ProbeReceipts: []string{"0123456789abcdef0123456789abcdef"},
		Replica:       "inkwall-operator-a", ConnectedAt: time.Unix(1700000000, 0).UTC(),
	}
	if n := reflect.TypeFor[Engine]().NumField() - 1; n != reflect.TypeFor[enginereport.Engine]().NumField() {
		t.Fatalf("Engine has %d exported fields, enginereport.Engine %d: keep them the same", n, reflect.TypeFor[enginereport.Engine]().NumField())
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var r enginereport.Engine
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(r)
	if string(again) != string(raw) {
		t.Errorf("read back:\n %s\nwritten:\n %s", again, raw)
	}
}
