// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package httpcheck

import (
	"strings"
	"testing"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
)

// The errors of a request the adapter can't read name the field, never its
// value: a URI's query or a header can carry a secret, and they're logged.
func TestParseErrorsHaveNoValues(t *testing.T) {
	for name, in := range map[string]*enginev1.CheckRequest{
		"raw_uri": {Method: "GET", RawUri: "https://shop.example.com/?token=SECRET"},
		"method":  {Method: "GET SECRET", RawUri: "/"},
		"scheme":  {Method: "GET", RawUri: "/", Scheme: "SECRET"},
		"peer_ip": {Method: "GET", RawUri: "/", PeerIp: "SECRET"},
		"header":  {Method: "GET", RawUri: "/", Headers: []*enginev1.Header{{Name: "x SECRET", Value: "v"}}},
	} {
		_, _, err := (&Handler{}).toRequest(in)
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: error %q has the value", name, err)
		}
	}
}
