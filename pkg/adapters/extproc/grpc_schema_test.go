// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"strings"
	"testing"
	"time"

	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/inkwall-dev/inkwall/pkg/grpcschema/grpcschematest"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
)

// TestGRPCSchema (#316): with the policy's gRPC schema, the messages of a
// described method are read with it, buffered and one by one, and the
// attack's event names the field (ARGS:service); an undescribed method's
// by number (ARGS:1).
func TestGRPCSchema(t *testing.T) {
	schema := grpcschematest.Schema(t, grpc_health_v1.File_grpc_health_v1_health_proto)
	for _, perMessage := range []bool{false, true} {
		for method, variable := range map[string]string{
			"/grpc.health.v1.Health/Check": "ARGS:service",
			"/grpc.health.v1.Health/Nope":  "ARGS:1",
		} {
			eval, err := coraza.New(coraza.Config{})
			if err != nil {
				t.Fatal(err)
			}
			p := pipeline.New(eval, pipeline.Config{Mode: pipeline.ModeBlock, Timeout: 10 * time.Second,
				GRPCMessages: true, GRPCPerMessage: perMessage, GRPCSchema: schema})
			var logs bytes.Buffer
			e := newEnvoy(t, p, 64, &logs)
			var resps []*extprocv3.ProcessingResponse
			if perMessage {
				resps = e.exchange(t, withMode(grpcHeaders(method), filterv3.ProcessingMode_BUFFERED_PARTIAL), body(grpcMessages("ok", sqli), false))
			} else {
				resps = e.exchange(t, withMode(grpcHeaders(method), filterv3.ProcessingMode_BUFFERED), body(grpcMessages("ok", sqli), true))
			}
			if resps[len(resps)-1].GetImmediateResponse() == nil {
				t.Errorf("per message %v, %s: the attack isn't denied", perMessage, method)
			}
			evs := securityEvents(t, &logs)
			if len(evs) != 1 || !strings.Contains(logs.String(), `"variable":"`+variable+`"`) {
				t.Errorf("per message %v, %s: events %s, want one naming %s", perMessage, method, logs.String(), variable)
			}
		}
	}
}
